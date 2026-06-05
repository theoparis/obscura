//! BoringSSL-native TLS connector for bypassing TLS fingerprinting.
//!
//! Uses `bssl-sys` directly so the ClientHello matches Chrome exactly.
//! BoringSSL IS Chrome's TLS library — same crypto stack, same handshake.
//!
//! # Platform notes
//! - **Unix**: uses raw fd via `SSL_set_fd`. The fd is shared between the
//!   `SSL` object and a `tokio::TcpStream` (for readiness polling).
//! - **Windows**: `SSL_set_fd` works with WinSock HANDLEs too, but tokio
//!   on Windows uses IOCP rather than epoll. When adding Windows support,
//!   the readiness polling (`poll_read_ready` / `poll_write_ready`) will
//!   need to be replaced with IOCP-aware equivalents (e.g. via
//!   `tokio::net::TcpStream::async_io` or a dedicated blocking thread per
//!   connection). The `spawn_blocking` handshake approach already works
//!   cross-platform.

use std::ffi::CString;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bssl_sys as ffi;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Chrome 145 supported curves
const CHROME_CURVES: &str = "X25519:P-256:P-384";

// HTTP/1.1 only — we speak raw HTTP/1.1, not HTTP/2 frames
const CHROME_ALPN: &[u8] = b"\x08http/1.1";

/// A BoringSSL TLS stream over a tokio TcpStream.
///
/// The SSL pointer does all crypto. The tokio stream is used only for
/// readiness polling so tokio's reactor knows when the fd has data.
pub struct BoringTlsStream {
    ssl: *mut ffi::SSL,
    // tokio stream for readiness polling - the fd is shared with SSL
    tcp: tokio::net::TcpStream,
}

unsafe impl Send for BoringTlsStream {}
unsafe impl Sync for BoringTlsStream {}

impl Drop for BoringTlsStream {
    fn drop(&mut self) {
        unsafe {
            ffi::SSL_shutdown(self.ssl);
            ffi::SSL_free(self.ssl);
        }
    }
}

pub struct BoringTlsConnector {
    ctx: *mut ffi::SSL_CTX,
}

unsafe impl Send for BoringTlsConnector {}
unsafe impl Sync for BoringTlsConnector {}

impl BoringTlsConnector {
    pub fn new() -> io::Result<Self> {
        unsafe {
            let method = ffi::TLS_client_method();
            let ctx = ffi::SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "SSL_CTX_new failed"));
            }

            // TLS 1.2 minimum
            ffi::SSL_CTX_set_min_proto_version(ctx, ffi::TLS1_2_VERSION as u16);

            // Set TLS 1.2 cipher preference order (TLS 1.3 suites are
            // controlled separately by BoringSSL and match Chrome by default).
            // Only include TLS 1.2 names here; TLS 1.3 names are ignored by
            // SSL_CTX_set_cipher_list but accepted by set_strict_cipher_list.
            let ciphers12 = CString::new(concat!(
                "ECDHE-ECDSA-AES128-GCM-SHA256:",
                "ECDHE-RSA-AES128-GCM-SHA256:",
                "ECDHE-ECDSA-AES256-GCM-SHA384:",
                "ECDHE-RSA-AES256-GCM-SHA384:",
                "ECDHE-ECDSA-CHACHA20-POLY1305:",
                "ECDHE-RSA-CHACHA20-POLY1305",
            ))
            .unwrap();
            ffi::SSL_CTX_set_cipher_list(ctx, ciphers12.as_ptr());

            // Chrome curves
            let curves = CString::new(CHROME_CURVES).unwrap();
            if ffi::SSL_CTX_set1_curves_list(ctx, curves.as_ptr()) != 1 {
                let err = bssl_error();
                ffi::SSL_CTX_free(ctx);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSL_CTX_set1_curves_list: {}", err),
                ));
            }

            // ALPN
            if ffi::SSL_CTX_set_alpn_protos(ctx, CHROME_ALPN.as_ptr(), CHROME_ALPN.len()) != 0 {
                let err = bssl_error();
                ffi::SSL_CTX_free(ctx);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSL_CTX_set_alpn_protos: {}", err),
                ));
            }

            // Load system root certificates for peer verification
            if ffi::SSL_CTX_set_default_verify_paths(ctx) != 1 {
                // Non-fatal: we'll proceed without cert verification
                tracing::warn!("SSL_CTX_set_default_verify_paths failed");
            }

            Ok(Self { ctx })
        }
    }

    /// Connect TLS. Does a blocking handshake, then hands back an async stream.
    pub async fn connect(
        &self,
        tcp: tokio::net::TcpStream,
        hostname: &str,
    ) -> io::Result<BoringTlsStream> {
        // Get the raw fd while we still own the TcpStream
        #[cfg(unix)]
        let fd = {
            use std::os::fd::AsRawFd;
            tcp.as_raw_fd()
        };

        let ssl = unsafe {
            let ssl = ffi::SSL_new(self.ctx);
            if ssl.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "SSL_new failed"));
            }

            let host = CString::new(hostname)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname has null"))?;
            if ffi::SSL_set_tlsext_host_name(ssl, host.as_ptr()) != 1 {
                let err = bssl_error();
                ffi::SSL_free(ssl);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSL_set_tlsext_host_name: {}", err),
                ));
            }

            #[cfg(unix)]
            ffi::SSL_set_fd(ssl, fd);

            ssl
        };

        // Run the blocking handshake on a dedicated thread so we don't
        // stall the tokio runtime.
        let std_tcp = tcp.into_std()?;
        std_tcp.set_nonblocking(false)?;

        // ssl is a raw pointer; wrap it so we can Send it to spawn_blocking.
        struct SendSsl(*mut ffi::SSL);
        unsafe impl Send for SendSsl {}

        // Set a 10-second timeout on the socket for the handshake
        std_tcp
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        std_tcp
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();

        let ssl_usize = ssl as usize;
        let handshake_result = tokio::task::spawn_blocking(move || {
            let ssl = ssl_usize as *mut ffi::SSL;
            let result = unsafe {
                loop {
                    let ret = ffi::SSL_connect(ssl);
                    if ret == 1 {
                        break Ok(());
                    }
                    let ssl_err = ffi::SSL_get_error(ssl, ret);
                    match ssl_err {
                        ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE => continue,
                        ffi::SSL_ERROR_SSL => {
                            break Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("SSL_connect: {}", bssl_error()),
                            ));
                        }
                        ffi::SSL_ERROR_SYSCALL => {
                            let e = io::Error::last_os_error();
                            break Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("SSL_connect syscall: {}", e),
                            ));
                        }
                        other => {
                            break Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("SSL_connect error {}", other),
                            ));
                        }
                    }
                }
            };
            (ssl as usize, std_tcp, result)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn_blocking: {}", e)))?;

        let (raw_ssl, std_tcp, result) = handshake_result;
        let ssl = raw_ssl as *mut ffi::SSL;

        // Clear timeouts before restoring non-blocking
        std_tcp.set_read_timeout(None).ok();
        std_tcp.set_write_timeout(None).ok();
        std_tcp.set_nonblocking(true)?;
        let tcp = tokio::net::TcpStream::from_std(std_tcp)?;

        if let Err(e) = result {
            unsafe { ffi::SSL_free(ssl) };
            return Err(e);
        }

        Ok(BoringTlsStream { ssl, tcp })
    }

    pub fn shared() -> io::Result<&'static Self> {
        use std::sync::OnceLock;
        static CONNECTOR: OnceLock<BoringTlsConnector> = OnceLock::new();
        if let Some(c) = CONNECTOR.get() {
            return Ok(c);
        }
        let c = Self::new()?;
        let _ = CONNECTOR.set(c);
        Ok(CONNECTOR.get().unwrap())
    }
}

impl Drop for BoringTlsConnector {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) };
    }
}

fn bssl_error() -> String {
    unsafe {
        let code = ffi::ERR_get_error();
        if code == 0 {
            return "unknown".to_string();
        }
        let mut buf = vec![0u8; 256];
        ffi::ERR_error_string_n(code, buf.as_mut_ptr() as *mut _, buf.len());
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).to_string()
    }
}

impl AsyncRead for BoringTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        if dst.is_empty() {
            return Poll::Ready(Ok(()));
        }

        // SSL_read / poll loop: retry after registering readiness interest.
        loop {
            let ret =
                unsafe { ffi::SSL_read(self.ssl, dst.as_mut_ptr() as *mut _, dst.len() as i32) };

            if ret > 0 {
                buf.advance(ret as usize);
                return Poll::Ready(Ok(()));
            }

            let ssl_err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
            match ssl_err {
                ffi::SSL_ERROR_ZERO_RETURN => return Poll::Ready(Ok(())),
                ffi::SSL_ERROR_WANT_READ => {
                    // Register waker with tokio reactor, wait for fd readiness
                    match Pin::new(&mut self.tcp).poll_read_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            // fd is ready: retry SSL_read immediately
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ffi::SSL_ERROR_WANT_WRITE => match Pin::new(&mut self.tcp).poll_write_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                ffi::SSL_ERROR_SYSCALL if ret == 0 => return Poll::Ready(Ok(())),
                _ => {
                    let msg = unsafe { bssl_error() };
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("SSL_read ({ssl_err}): {msg}"),
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for BoringTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let ret =
                unsafe { ffi::SSL_write(self.ssl, buf.as_ptr() as *const _, buf.len() as i32) };

            if ret > 0 {
                return Poll::Ready(Ok(ret as usize));
            }

            let ssl_err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
            match ssl_err {
                ffi::SSL_ERROR_WANT_WRITE => match Pin::new(&mut self.tcp).poll_write_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                ffi::SSL_ERROR_WANT_READ => match Pin::new(&mut self.tcp).poll_read_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                _ => {
                    let msg = unsafe { bssl_error() };
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("SSL_write ({ssl_err}): {msg}"),
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
