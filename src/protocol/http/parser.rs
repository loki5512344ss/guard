//! Чистый парсер и валидатор HTTP/1.x request-head для edge-фильтра.
//!
//! Модуль не знает про I/O: на вход — накопленный заголовок, на выходе —
//! [`Verdict`]. Это позволяет покрывать логику юнит-тестами без сокетов.

/// Политика проверки, снятая с секции `[protocol.http]`.
#[derive(Debug, Clone)]
pub struct Policy {
    pub max_header_bytes: usize,
    pub blocked_paths: Vec<String>,
    pub require_user_agent: bool,
}

/// Результат проверки головы запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow { method: String, path: String, host: String },
    Reject { reason: String },
}

const ALLOWED_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Ищет конец головы запроса (`\r\n\r\n`) и возвращает её полную длину.
#[must_use]
pub fn scan_head(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
        .map(|pos| pos + HEADER_TERMINATOR.len())
}

/// Разбирает и валидирует голову запроса согласно политике.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            max_header_bytes: 8192,
            blocked_paths: Vec::new(),
            require_user_agent: false,
        }
    }

    #[test]
    fn scan_finds_full_head_length() {
        assert_eq!(scan_head(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(scan_head(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn valid_request_is_allowed() {
        let head = b"POST /api/items?limit=5 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let verdict = evaluate(head, &policy());
        assert_eq!(
            verdict,
            Verdict::Allow {
                method: "POST".to_string(),
                path: "/api/items".to_string(),
                host: "example.com".to_string()
            }
        );
    }

    #[test]
    fn unknown_method_is_rejected() {
        let head = b"TRACE / HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
    }

    #[test]
    fn missing_host_is_rejected() {
        let head = b"GET / HTTP/1.1\r\nUser-Agent: t\r\n\r\n";
        assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
    }

    #[test]
    fn http2_version_is_rejected() {
        let head = b"GET / HTTP/2.0\r\nHost: h\r\n\r\n";
        assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
    }

    #[test]
    fn malformed_line_is_rejected() {
        assert!(matches!(
            evaluate(b"nonsense\r\n\r\n", &policy()),
            Verdict::Reject { .. }
        ));
        assert!(matches!(
            evaluate(b"GET / HTTP/1.1\r\nbroken\r\n\r\n", &policy()),
            Verdict::Reject { .. }
        ));
    }

    #[test]
    fn non_utf8_head_is_rejected() {
        assert!(matches!(evaluate(&[0xff, 0xfe], &policy()), Verdict::Reject { .. }));
    }

    #[test]
    fn blocked_path_prefix_is_rejected() {
        let mut custom = policy();
        custom.blocked_paths = vec!["/admin".to_string()];
        assert!(matches!(
            evaluate(b"GET /admin/panel HTTP/1.1\r\nHost: h\r\n\r\n", &custom),
            Verdict::Reject { .. }
        ));
        assert!(matches!(
            evaluate(b"GET /public HTTP/1.1\r\nHost: h\r\n\r\n", &custom),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn required_user_agent_enforced() {
        let mut custom = policy();
        custom.require_user_agent = true;
        let head = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(matches!(evaluate(head, &custom), Verdict::Reject { .. }));
        let head_with_ua = b"GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n\r\n";
        assert!(matches!(evaluate(head_with_ua, &custom), Verdict::Allow { .. }));
    }
}
