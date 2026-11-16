//! Pure HTTP/1.x request-head parser and validator for the edge filter.
//!
//! Owns the parsing policy and verdicts only: the module knows nothing about
//! I/O. Input is the accumulated head, output is a [`Verdict`], which keeps the
//! logic unit-testable without sockets.

/// Validation policy derived from the `[protocol.http]` section.
#[derive(Debug, Clone)]
pub struct Policy {
	pub max_header_bytes: usize,
	pub blocked_paths: Vec<String>,
	pub require_user_agent: bool,
}

/// Outcome of validating a request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
	Allow { method: String, path: String, host: String },
	Reject { reason: String },
}

const ALLOWED_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Looks for the end of the request head (`\r\n\r\n`) and returns its full length.
#[must_use]
pub fn scan_head(buf: &[u8]) -> Option<usize> {
	buf.windows(HEADER_TERMINATOR.len())
		.position(|window| window == HEADER_TERMINATOR)
		.map(|pos| pos + HEADER_TERMINATOR.len())
}

/// Parses and validates a request head against the policy.
#[must_use]
pub fn evaluate(head: &[u8], policy: &Policy) -> Verdict {
	let Ok(text) = std::str::from_utf8(head) else {
		return reject("request head is not valid utf-8");
	};
	let mut lines = text.split("\r\n");
	let Some(request_line) = lines.next().filter(|line| !line.is_empty()) else {
		return reject("empty request line");
	};

	let mut parts = request_line.split(' ');
	let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
		return reject("malformed request line");
	};
	if parts.next().is_some() {
		return reject("malformed request line");
	}
	if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
		return reject("unsupported http version");
	}
	if !ALLOWED_METHODS.contains(&method) {
		return reject("method not allowed");
	}

	let mut host: Option<&str> = None;
	let mut user_agent: Option<&str> = None;
	for line in lines {
		if line.is_empty() {
			continue;
		}
		let Some((name, value)) = line.split_once(':') else {
			return reject("malformed header line");
		};
		let value = value.trim();
		if name.eq_ignore_ascii_case("host") {
			host = Some(value);
		} else if name.eq_ignore_ascii_case("user-agent") {
			user_agent = Some(value);
		}
	}

	let path = match target.split_once('?') {
		Some((path, _)) => path,
		None => target,
	};
	if policy
		.blocked_paths
		.iter()
		.any(|prefix| path.starts_with(prefix.as_str()))
	{
		return reject("path is blocklisted");
	}

	let Some(host) = host.filter(|value| !value.is_empty()) else {
		return reject("missing host header");
	};
	if policy.require_user_agent && user_agent.is_none_or(str::is_empty) {
		return reject("missing user-agent header");
	}

	Verdict::Allow {
		method: method.to_string(),
		path: path.to_string(),
		host: host.to_string(),
	}
}

fn reject(reason: &str) -> Verdict {
	Verdict::Reject {
		reason: reason.to_string(),
	}
}
