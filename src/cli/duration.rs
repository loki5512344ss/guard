//! Human-readable durations for CLI flags: `30s`, `5m`, `1h30m`, `2d`.

/// Hint appended to every rejection so a unit mistake is fixed on the first retry.
const UNITS_HINT: &str = "valid units: s (seconds), m (minutes), h (hours), d (days); e.g. 30s, 5m, 1h30m, 2d";

/// Parses a duration into seconds.
///
/// Grammar: one or more `<digits><unit>` parts with units `d`, `h`, `m`, `s` in
/// strictly descending order, each at most once, no whitespace. A bare number is
/// rejected (seconds versus minutes is a classic mistake); only a bare `0` is
/// accepted and yields zero, which callers treat as "no duration".
///
/// # Errors
/// Returns a message with the valid units on any deviation or on overflow.
pub fn parse_duration_secs(text: &str) -> Result<u64, String> {
	if text.is_empty() {
		return Err(format!("duration must not be empty ({UNITS_HINT})"));
	}
	if text == "0" {
		return Ok(0);
	}
	let mut total: u64 = 0;
	let mut rest = text;
	let mut last_rank = u8::MAX;
	while !rest.is_empty() {
		let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
		if digits == 0 {
			return Err(format!("invalid duration '{text}' ({UNITS_HINT})"));
		}
		let (number, tail) = rest.split_at(digits);
		let mut chars = tail.chars();
		let (rank, factor) = match chars.next() {
			Some('d') => (3, 86_400),
			Some('h') => (2, 3_600),
			Some('m') => (1, 60),
			Some('s') => (0, 1),
			Some(_) => return Err(format!("invalid unit in '{text}' ({UNITS_HINT})")),
			None => return Err(format!("duration '{text}' needs a unit ({UNITS_HINT})")),
		};
		if rank >= last_rank {
			return Err(format!(
				"units in '{text}' must be unique and descending ({UNITS_HINT})"
			));
		}
		last_rank = rank;
		let value: u64 = number.parse().map_err(|_| format!("duration '{text}' is too large"))?;
		total = value
			.checked_mul(factor)
			.and_then(|part| total.checked_add(part))
			.ok_or_else(|| format!("duration '{text}' is too large"))?;
		rest = chars.as_str();
	}
	Ok(total)
}

/// Formats seconds with the two largest non-zero units, e.g. `1h30m`.
#[must_use]
pub fn format_duration_secs(secs: u64) -> String {
	if secs == 0 {
		return "0s".to_string();
	}
	let parts = [
		(secs / 86_400, 'd'),
		(secs % 86_400 / 3_600, 'h'),
		(secs % 3_600 / 60, 'm'),
		(secs % 60, 's'),
	];
	parts
		.iter()
		.filter(|(value, _)| *value > 0)
		.take(2)
		.map(|(value, unit)| format!("{value}{unit}"))
		.collect()
}
