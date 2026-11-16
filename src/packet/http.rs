// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/http.rs — HTTP request parsing
//
// Parses HTTP/1.x requests to extract the Host header and find
// split points for DPI bypass.

/// Result of HTTP request parsing
#[derive(Debug)]
pub struct HttpRequest<'a> {
    /// The full HTTP request data
    pub data: &'a [u8],
    /// HTTP method (GET, POST, etc.)
    pub method: &'a str,
    /// Request URI
    pub uri: &'a str,
    /// Host header value
    pub host: Option<String>,
    /// Byte offset of "Host: " header within the data
    pub host_offset: Option<usize>,
    /// Length of the Host header value
    pub host_length: Option<usize>,
    /// Byte offset of the first line end (\r\n)
    pub first_line_end: usize,
}

impl<'a> HttpRequest<'a> {
    /// Try to parse an HTTP request from TCP payload.
    /// Returns None if this is not a valid HTTP request.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        // Must be at least "GET / HTTP/1.0\r\n" (16 bytes minimum)
        if data.len() < 16 {
            return None;
        }

        // Only the request line needs to be valid UTF-8 to read the method and
        // URI. The Host header is located by the byte-level search below, and
        // the request body may be binary (e.g. a POST upload) — requiring the
        // whole payload to be UTF-8 would reject such requests and skip Host
        // fragmentation, leaving the domain readable by DPI.
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let request_line = std::str::from_utf8(data.get(..line_end)?).ok()?;

        // Check for common HTTP methods
        let (method, after_method) = request_line.split_once(' ')?;

        if !matches!(
            method,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT"
        ) {
            return None;
        }

        // Find URI end
        let (uri, _) = after_method.split_once(' ')?;

        // Byte offset just past the request line's CRLF
        let first_line_end = line_end + 2;

        // Find Host header (case-insensitive byte search — avoids full payload to_lowercase())
        let mut host: Option<String> = None;
        let mut host_offset: Option<usize> = None;
        let mut host_length: Option<usize> = None;

        // Search for "\r\nHost: " or "\r\nhost: " etc. by scanning bytes
        let host_header = data.windows(8).position(|w| {
            matches!(
                w,
                [
                    b'\r',
                    b'\n',
                    b'H' | b'h',
                    b'o' | b'O',
                    b's' | b'S',
                    b't' | b'T',
                    b':',
                    b' '
                ]
            )
        });
        if let Some(i) = host_header {
            let value_start = i + 8;
            let rest = data.get(value_start..).unwrap_or_default();
            // The value runs to the next CRLF, or to the end of the segment.
            let value_len = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(rest.len());
            if let Some(Ok(host_value)) = rest.get(..value_len).map(std::str::from_utf8) {
                host = Some(host_value.trim().to_lowercase());
                host_offset = Some(value_start);
                host_length = Some(value_len);
            }
        }

        Some(HttpRequest {
            data,
            method,
            uri,
            host,
            host_offset,
            host_length,
            first_line_end,
        })
    }

    /// Get the Host header value
    pub fn host_domain(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Check if this is an HTTP request
    pub fn is_valid(&self) -> bool {
        !self.method.is_empty()
    }
}

/// Check if TCP payload looks like an HTTP request
pub fn is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // Check for common HTTP methods
    data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"CONNECT ")
}

/// Check if a response looks like an HTTP 302 redirect
pub fn is_http_redirect(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    // "HTTP/1.x 302" or "HTTP/1.x 301"
    data.starts_with(b"HTTP/1.")
        && data
            .get(9..12)
            .is_some_and(|code| matches!(code, b"302" | b"301" | b"307"))
}

/// Find the best split point for an HTTP request to break the Host header
/// across two TCP segments.
///
/// Strategy: Split right before or in the middle of the Host header value.
pub fn find_http_split_point(data: &[u8]) -> Option<usize> {
    let req = HttpRequest::parse(data)?;

    // Strategy 1: Split in the middle of the Host header value
    if let (Some(offset), Some(length)) = (req.host_offset, req.host_length)
        && length > 1
    {
        return Some(offset + length / 2);
    }

    // Strategy 2: Split right after the first line
    if req.first_line_end > 0 && req.first_line_end < data.len() {
        return Some(req.first_line_end);
    }

    None
}
