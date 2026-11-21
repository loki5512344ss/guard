//! Wall-clock helpers on top of the `time` crate (unix seconds and RFC 3339).
//!
//! Every timestamp that crosses a process boundary (Redis records, manager API,
//! ClickHouse rows, JWT claims) is unix seconds or an RFC 3339 string; this module is
//! the single place that converts between them and rejects out-of-range values.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current unix time in seconds.
#[must_use]
pub fn unix_now() -> i64 {
	OffsetDateTime::now_utc().unix_timestamp()
}

/// Whether `ts` (unix seconds) is a representable calendar date. Absurd values from
/// untrusted records (Redis, API) must be rejected instead of flowing into arithmetic.
#[must_use]
pub fn is_valid_unix(ts: i64) -> bool {
	OffsetDateTime::from_unix_timestamp(ts).is_ok()
}

/// Formats unix seconds as RFC 3339 (UTC, `Z` suffix); `None` when out of range.
#[must_use]
pub fn format_rfc3339(ts: i64) -> Option<String> {
	OffsetDateTime::from_unix_timestamp(ts).ok()?.format(&Rfc3339).ok()
}

/// Current time as RFC 3339.
#[must_use]
pub fn now_rfc3339() -> String {
	OffsetDateTime::now_utc()
		.format(&Rfc3339)
		.unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

/// Parses an RFC 3339 string (any offset) into unix seconds.
#[must_use]
pub fn parse_rfc3339_unix(text: &str) -> Option<i64> {
	OffsetDateTime::parse(text, &Rfc3339)
		.ok()
		.map(OffsetDateTime::unix_timestamp)
}
