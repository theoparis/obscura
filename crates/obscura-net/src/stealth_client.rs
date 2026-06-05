use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use url::Url;

use crate::client::{ObscuraNetError, Response};
use crate::cookies::CookieJar;
#[cfg(feature = "stealth")]
use crate::stealth_tls::BoringTlsConnector;

pub const STEALTH_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

pub struct StealthHttpClient {
    pub cookie_jar: Arc<CookieJar>,
    pub extra_headers: RwLock<HashMap<String, String>>,
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
}

impl StealthHttpClient {
    pub fn new(cookie_jar: Arc<CookieJar>) -> Self {
        Self::with_proxy(cookie_jar, None, None)
    }

    pub fn with_proxy(
        cookie_jar: Arc<CookieJar>,
        _proxy_url: Option<&str>,
        _ja3: Option<Ja3Fingerprint>,
    ) -> Self {
        StealthHttpClient {
            cookie_jar,
            extra_headers: RwLock::new(HashMap::new()),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub async fn fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        let mut current_url = url.clone();
        let mut redirects = Vec::new();

        for _ in 0..20 {
            self.in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!("Sending stealth request to {}", current_url);

            let result = self.fetch_single(&current_url).await;

            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            let (status, response_headers, body) = match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Stealth request failed for {}: {}", current_url, e);
                    return Err(e);
                }
            };

            tracing::debug!(
                "Received response from {} with status {}",
                current_url,
                status
            );

            // Handle Set-Cookie headers
            if let Some(cookies) = response_headers.get("set-cookie") {
                for cookie_str in cookies.split('\n') {
                    let cookie_str = cookie_str.trim();
                    if !cookie_str.is_empty() {
                        self.cookie_jar.set_cookie(cookie_str, &current_url);
                    }
                }
            }

            // Handle redirects
            if status >= 300 && status < 400 {
                if let Some(location) = response_headers.get("location") {
                    let next_url = current_url.join(location).map_err(|e| {
                        ObscuraNetError::Network(format!("Invalid redirect URL: {}", e))
                    })?;
                    redirects.push(current_url.clone());
                    current_url = next_url;
                    continue;
                }
            }

            return Ok(Response {
                url: current_url,
                status,
                headers: response_headers,
                body,
                redirected_from: redirects,
            });
        }

        Err(ObscuraNetError::TooManyRedirects(url.to_string()))
    }

    /// Perform a single HTTP GET request using native BoringSSL TLS.
    #[cfg(feature = "stealth")]
    async fn fetch_single(
        &self,
        url: &Url,
    ) -> Result<(u16, HashMap<String, String>, Vec<u8>), ObscuraNetError> {
        let host = url
            .host_str()
            .ok_or_else(|| ObscuraNetError::Network("No host in URL".into()))?;
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = url.path();
        let full_path = if let Some(q) = url.query() {
            format!("{}?{}", if path.is_empty() { "/" } else { path }, q)
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };

        // Connect TCP
        let addr = format!("{}:{}", host, port);
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| ObscuraNetError::Network(format!("TCP connect to {}: {}", addr, e)))?;

        // Perform BoringSSL-native TLS handshake
        let connector = BoringTlsConnector::shared()
            .map_err(|e| ObscuraNetError::Network(format!("TLS connector init: {}", e)))?;
        tracing::debug!("TCP connected to {}, starting TLS", addr);
        let mut tls = connector
            .connect(tcp, host)
            .await
            .map_err(|e| ObscuraNetError::Network(format!("TLS connect: {}", e)))?;

        // Build HTTP/1.1 request
        let cookie_header = self.cookie_jar.get_cookie_header(url);
        let extra = self.extra_headers.read().await;

        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n",
            full_path, host, STEALTH_USER_AGENT,
        );

        if !cookie_header.is_empty() {
            request.push_str(&format!("Cookie: {}\r\n", cookie_header));
        }

        for (k, v) in extra.iter() {
            request.push_str(&format!("{}: {}\r\n", k, v));
        }
        drop(extra);

        request.push_str("Connection: close\r\n\r\n");

        // Write request
        tokio::io::AsyncWriteExt::write_all(&mut tls, request.as_bytes())
            .await
            .map_err(|e| ObscuraNetError::Network(format!("Write request: {}", e)))?;
        tokio::io::AsyncWriteExt::flush(&mut tls)
            .await
            .map_err(|e| ObscuraNetError::Network(format!("Flush request: {}", e)))?;

        // Read response
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tls, &mut tmp).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(ObscuraNetError::Network(format!("Read response: {}", e))),
            }
        }

        // Parse HTTP response
        let (status, headers, body_start) = Self::parse_http_response(&buf)?;

        let response_headers: HashMap<String, String> = headers
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();

        Ok((status, response_headers, buf[body_start..].to_vec()))
    }

    /// Fallback for non-stealth builds (shouldn't be used, but provides compilation)
    #[cfg(not(feature = "stealth"))]
    async fn fetch_single(
        &self,
        _url: &Url,
    ) -> Result<(u16, HashMap<String, String>, Vec<u8>), ObscuraNetError> {
        Err(ObscuraNetError::Network(
            "Stealth HTTP client not available without stealth feature".into(),
        ))
    }

    /// Parse a raw HTTP/1.1 response into status code, headers, and body start offset.
    fn parse_http_response(
        data: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, usize), ObscuraNetError> {
        // Find end of headers (\r\n\r\n)
        let header_end = data
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| {
                ObscuraNetError::Network("Invalid HTTP response: no header terminator".into())
            })?;

        let header_bytes = &data[..header_end];
        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.lines();

        // Parse status line
        let status_line = lines
            .next()
            .ok_or_else(|| ObscuraNetError::Network("Empty HTTP response".into()))?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(ObscuraNetError::Network(format!(
                "Invalid status line: {}",
                status_line
            )));
        }
        let status: u16 = parts[1]
            .parse()
            .map_err(|_| ObscuraNetError::Network(format!("Invalid status code: {}", parts[1])))?;

        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.to_string(), v.trim().to_string()));
            }
        }

        let body_start = header_end + 4; // Skip \r\n\r\n
        Ok((status, headers, body_start))
    }

    pub async fn set_extra_headers(&self, headers: HashMap<String, String>) {
        *self.extra_headers.write().await = headers;
    }

    pub fn active_requests(&self) -> u32 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_network_idle(&self) -> bool {
        self.active_requests() == 0
    }
}

/// JA3 Fingerprint structure for legacy support
pub struct Ja3Fingerprint {
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub elliptic_curve_formats: Vec<u8>,
}

impl Ja3Fingerprint {
    pub fn parse(ja3: &str) -> Option<Self> {
        let parts: Vec<&str> = ja3.split(',').collect();
        if parts.len() != 5 {
            return None;
        }

        let version = parts[0].parse().ok()?;
        let cipher_suites = parts[1].split('-').filter_map(|s| s.parse().ok()).collect();
        let extensions = parts[2].split('-').filter_map(|s| s.parse().ok()).collect();
        let elliptic_curves = parts[3].split('-').filter_map(|s| s.parse().ok()).collect();
        let elliptic_curve_formats = parts[4].split('-').filter_map(|s| s.parse().ok()).collect();

        Some(Ja3Fingerprint {
            version,
            cipher_suites,
            extensions,
            elliptic_curves,
            elliptic_curve_formats,
        })
    }
}

/// JA4 Fingerprint structure (A_B_C) for high-fidelity browser matching.
/// Example: t13d1516h2_8daaf6152771_498c036f01ec
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    /// Part A: Protocol, SNI, Extensions, ALPNs (e.g., "t13d1516h2")
    pub a: String,
    /// Part B: Cipher Suite Hash (e.g., "8daaf6152771")
    pub b: String,
    /// Part C: Extension Hash (e.g., "498c036f01ec")
    pub c: String,
}

impl Ja4Fingerprint {
    /// Parses a JA4 string in the format A_B_C
    pub fn parse(ja4: &str) -> Option<Self> {
        let parts: Vec<&str> = ja4.split('_').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Ja4Fingerprint {
            a: parts[0].to_string(),
            b: parts[1].to_string(),
            c: parts[2].to_string(),
        })
    }

    /// Calculates a JA4 fingerprint from raw ClientHello bytes
    pub fn from_client_hello(hello: &[u8]) -> Self {
        let mut pos = 0;

        // Skip TLS Record Layer (5 bytes) if present
        if hello.len() > 5 && hello[0] == 0x16 {
            pos += 5;
        }

        // Skip Handshake Header (4 bytes)
        if hello.len() > pos + 4 && hello[pos] == 0x01 {
            pos += 4;
        }

        // Skip Version (2) and Random (32)
        pos += 34;

        if pos >= hello.len() {
            return Self::unknown();
        }

        // Skip Session ID
        let session_id_len = hello[pos] as usize;
        pos += 1 + session_id_len;

        if pos + 2 > hello.len() {
            return Self::unknown();
        }

        // Extract Cipher Suites
        let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2;
        let mut cipher_suites = Vec::new();
        for _ in 0..(cipher_suites_len / 2) {
            if pos + 2 > hello.len() {
                break;
            }
            let suite = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            if !is_grease(suite) {
                cipher_suites.push(suite);
            }
            pos += 2;
        }

        if pos + 1 > hello.len() {
            return Self::unknown();
        }

        // Skip Compression Methods
        let comp_len = hello[pos] as usize;
        pos += 1 + comp_len;

        if pos + 2 > hello.len() {
            return Self::unknown();
        }

        // Extract Extensions
        let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        let mut extensions = Vec::new();
        let mut has_sni = false;
        let mut first_alpn = "00".to_string();
        let mut num_alpn = 0;
        let mut tls_version = "12"; // Default to 1.2

        while pos + 4 <= extensions_end && pos + 4 <= hello.len() {
            let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);

                match ext_type {
                    0x0000 => has_sni = true,
                    0x0010 => {
                        // ALPN
                        if pos + 2 <= hello.len() {
                            let alpn_list_len =
                                u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
                            let mut alpn_pos = pos + 2;
                            if alpn_pos + 1 <= hello.len() {
                                let first_len = hello[alpn_pos] as usize;
                                if alpn_pos + 1 + first_len <= hello.len() {
                                    let alpn_val = &hello[alpn_pos + 1..alpn_pos + 1 + first_len];
                                    if !alpn_val.is_empty() {
                                        first_alpn = format!(
                                            "{:02x}{:02x}",
                                            alpn_val[0],
                                            alpn_val[alpn_val.len() - 1]
                                        );
                                    }
                                }
                            }
                            let alpn_end = alpn_pos + alpn_list_len;
                            while alpn_pos < alpn_end && alpn_pos < hello.len() {
                                let len = hello[alpn_pos] as usize;
                                num_alpn += 1;
                                alpn_pos += 1 + len;
                            }
                        }
                    }
                    0x002b => {
                        // Supported Versions
                        if pos + 1 <= hello.len() {
                            let versions_len = hello[pos] as usize;
                            let mut v_pos = pos + 1;
                            while v_pos + 2 <= pos + 1 + versions_len && v_pos + 2 <= hello.len() {
                                let v = u16::from_be_bytes([hello[v_pos], hello[v_pos + 1]]);
                                if v == 0x0304 {
                                    tls_version = "13";
                                }
                                v_pos += 2;
                            }
                        }
                    }
                    _ => {}
                }
            }
            pos += ext_len;
        }

        let sni_char = if has_sni { "d" } else { "n" };
        let part_a = format!(
            "t{}{}{:02}{:02}{}",
            tls_version,
            sni_char,
            extensions.len().min(99),
            num_alpn.min(99),
            first_alpn
        );

        cipher_suites.sort_unstable();
        let b_str = cipher_suites
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");
        let part_b = hash_and_truncate(&b_str);

        extensions.retain(|&e| e != 0 && e != 16);
        extensions.sort_unstable();
        let c_str = extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let part_c = hash_and_truncate(&c_str);

        Ja4Fingerprint {
            a: part_a,
            b: part_b,
            c: part_c,
        }
    }

    fn unknown() -> Self {
        Ja4Fingerprint {
            a: "t00n00000000".into(),
            b: "000000000000".into(),
            c: "000000000000".into(),
        }
    }

    /// Returns the full JA4 string representation
    pub fn to_string(&self) -> String {
        format!("{}_{}_{}", self.a, self.b, self.c)
    }
}

#[cfg(feature = "stealth")]
fn is_grease(val: u16) -> bool {
    if (val & 0x0f0f) == 0x0a0a {
        return true;
    }
    // Specific known GREASE values from RFC 8701
    matches!(
        val,
        0x0a0a
            | 0x1a1a
            | 0x2a2a
            | 0x3a3a
            | 0x4a4a
            | 0x5a5a
            | 0x6a6a
            | 0x7a7a
            | 0x8a8a
            | 0x9a9a
            | 0xaaaa
            | 0xbaba
            | 0xcaca
            | 0xdada
            | 0xeaea
            | 0xfafa
    )
}

#[cfg(feature = "stealth")]
fn hash_and_truncate(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    use bssl_crypto::digest;
    let hash = digest::Sha256::hash(input.as_bytes());
    // Convert to hex and take first 12 chars
    let mut hex = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write;
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex[..12].to_string()
}
