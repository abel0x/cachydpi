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
    /// The host the request names, normalized for the domain filter: lowercase,
    /// without a port or a trailing dot. `None` when there is no Host header,
    /// or when this segment does not settle which host it is (see
    /// [`find_host_header`]).
    pub host: Option<String>,
    /// Byte offset of the Host header value within the data, also set when
    /// the value is cut off by the end of the segment
    pub host_offset: Option<usize>,
    /// Length of the Host header value as it appears, port included
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

        let found = find_host_header(data, first_line_end);
        let host = found.as_ref().and_then(|h| h.name.clone());
        let host_offset = found.as_ref().map(|h| h.offset);
        let host_length = found.as_ref().map(|h| h.length);

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

/// Where a Host header's value sits, and the host it names if that is settled.
struct HostHeader {
    offset: usize,
    length: usize,
    name: Option<String>,
}

/// Find the Host header among the header lines that follow the request line.
///
/// Only the header block is searched: the scan stops at the blank line that
/// ends it, so a body containing "Host:" is never taken for the header. The
/// name is matched case-insensitively and the value may be surrounded by
/// spaces or tabs (RFC 9110 OWS), so `Host:example.com` counts as well.
///
/// The position is returned whenever a Host header starts in this segment, so
/// a split can still land inside its value. The name is returned only when the
/// segment settles it: the line must end here, there must be exactly one Host
/// header, and it must not continue on an obsolete folded line. Otherwise the
/// host is unknown, and the domain filter treats it that way rather than
/// judging a fragment such as `exam` as if it were a whole name.
fn find_host_header(data: &[u8], headers_start: usize) -> Option<HostHeader> {
    let mut found: Option<HostHeader> = None;
    // Whether the line before was the Host header or a fold continuing it.
    let mut in_host = false;
    let mut pos = headers_start;
    loop {
        let rest = data.get(pos..).unwrap_or_default();
        let (line, complete) = match rest.windows(2).position(|w| w == b"\r\n") {
            Some(end) => (rest.split_at(end).0, true),
            None => (rest, false),
        };
        if complete && line.is_empty() {
            break; // end of the header block
        }
        let folded = matches!(line.first(), Some(b' ' | b'\t'));
        if folded {
            if in_host && let Some(h) = found.as_mut() {
                h.name = None; // obs-fold: the value goes on, the name is unclear
            }
            if !complete {
                break;
            }
            pos += line.len() + 2;
            continue;
        }
        in_host = false;
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && let (name, after_name) = line.split_at(colon)
            && name.eq_ignore_ascii_case(b"host")
        {
            in_host = true;
            if let Some(first) = found.as_mut() {
                first.name = None; // two Host headers: no single answer
            } else {
                let value = after_name.get(1..).unwrap_or_default();
                let lead = value
                    .iter()
                    .take_while(|&&b| b == b' ' || b == b'\t')
                    .count();
                let trimmed = value.get(lead..).unwrap_or_default().trim_ascii_end();
                found = Some(HostHeader {
                    offset: pos + colon + 1 + lead,
                    length: if complete {
                        trimmed.len()
                    } else {
                        value.len() - lead
                    },
                    name: complete
                        .then(|| std::str::from_utf8(trimmed).ok())
                        .flatten()
                        .and_then(normalize_authority),
                });
            }
        }
        if !complete {
            break;
        }
        pos += line.len() + 2;
    }
    found
}

/// The host part of a Host header value, as the domain filter compares it.
///
/// Lowercased, with the port and one trailing dot removed: `Example.COM.:8080`
/// names the same site as `example.com`. A bracketed IPv6 literal comes back
/// without its brackets. Anything with whitespace or an empty host is not a
/// name.
pub fn normalize_authority(value: &str) -> Option<String> {
    let host = if let Some(literal) = value.strip_prefix('[') {
        let (inside, after) = literal.split_once(']')?;
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        inside
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if is_port(port) && !host.contains(':') => host,
            Some(_) => return None,
            None => value,
        }
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// An empty port is allowed (`host:`), as RFC 3986 allows it.
fn is_port(s: &str) -> bool {
    s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())
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
