//! Minimal parser for the Prometheus text exposition format (version 0.0.4).
//!
//! Owns the parsing rules for `/metrics` bodies. Accepts comment lines
//! (`# HELP`, `# TYPE`, `#`), `metric{label="value",...} value [timestamp]` and
//! `metric value [timestamp]`. `NaN`/`+Inf`/`-Inf` are parsed through
//! `f64::from_str`.

use std::collections::BTreeMap;

/// One sample from the Prometheus exposition format.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
	pub name: String,
	pub labels: BTreeMap<String, String>,
	pub value: f64,
}

/// All samples of a single `/metrics` response.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MetricSet {
	samples: Vec<MetricSample>,
}

impl MetricSet {
	/// Sums the values of every series with this name (for counter/gauge vecs).
	///
	/// A missing metric yields `0.0`.
	#[must_use]
	pub fn sum(&self, name: &str) -> f64 {
		self.samples.iter().filter(|s| s.name == name).map(|s| s.value).sum()
	}

	/// Value of the series with this name carrying `label == value`, or `None`
	/// when no such series exists.
	#[must_use]
	pub fn labeled(&self, name: &str, label: &str, value: &str) -> Option<f64> {
		self.samples
			.iter()
			.find(|s| s.name == name && s.labels.get(label).map(String::as_str) == Some(value))
			.map(|s| s.value)
	}

	/// All samples (for tests and debugging).
	#[must_use]
	pub fn samples(&self) -> &[MetricSample] {
		&self.samples
	}
}

/// Parses a `/metrics` response body.
///
/// Lines with a malformed format are skipped: an exposition stream may be
/// partially corrupted and the TUI must not die because of it.
#[must_use]
pub fn parse(input: &str) -> MetricSet {
	let mut samples = Vec::new();
	for line in input.lines() {
		if let Some(sample) = parse_line(line) {
			samples.push(sample);
		}
	}
	MetricSet { samples }
}

fn parse_line(line: &str) -> Option<MetricSample> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') {
		return None;
	}
	// Format: metric[{labels}] value [timestamp]. Label values may contain
	// spaces, so the head has to be cut with quote awareness.
	let (head, rest) = split_head_and_rest(line);
	let value_str = rest.split_whitespace().next()?;
	// A timestamp after the value is irrelevant for the TUI and dropped.

	let (name, labels) = split_metric(head)?;
	let value = parse_value(value_str)?;
	Some(MetricSample { name, labels, value })
}

/// Splits `metric{...}` from the trailing `value [timestamp]`.
fn split_head_and_rest(line: &str) -> (&str, &str) {
	let Some(open) = line.find('{') else {
		return match line.find(char::is_whitespace) {
			Some(space) => (&line[..space], &line[space..]),
			None => (line, ""),
		};
	};
	match find_closing_brace(line, open + 1) {
		Some(close) => (&line[..=close], &line[close + 1..]),
		None => match line.find(char::is_whitespace) {
			Some(space) => (&line[..space.min(open)], &line[space.min(open)..]),
			None => (line, ""),
		},
	}
}

/// Index of the `}` outside quotes, starting at `from`.
fn find_closing_brace(line: &str, from: usize) -> Option<usize> {
	let mut in_quotes = false;
	let mut escaped = false;
	for (idx, ch) in line[from..].char_indices() {
		match ch {
			'\\' if in_quotes => escaped = !escaped,
			'"' if !escaped => in_quotes = !in_quotes,
			'}' if !in_quotes => return Some(from + idx),
			_ => {},
		}
		if ch != '\\' {
			escaped = false;
		}
	}
	None
}

fn split_metric(head: &str) -> Option<(String, BTreeMap<String, String>)> {
	match head.find('{') {
		None => Some((head.to_owned(), BTreeMap::new())),
		Some(open) => {
			if !head.ends_with('}') || open == 0 {
				return None;
			}
			let name = head[..open].trim().to_owned();
			let inner = &head[open + 1..head.len() - 1];
			Some((name, parse_labels(inner)))
		},
	}
}

fn parse_labels(inner: &str) -> BTreeMap<String, String> {
	let mut labels = BTreeMap::new();
	for pair in split_label_pairs(inner) {
		if let Some(eq) = pair.find('=') {
			let key = pair[..eq].trim();
			let raw_value = pair[eq + 1..].trim();
			if let Some(unquoted) = raw_value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
				labels.insert(key.to_owned(), unescape_label(unquoted));
			}
		}
	}
	labels
}

/// Splits `a="1", b="2"` on commas outside quotes.
fn split_label_pairs(inner: &str) -> Vec<&str> {
	let mut parts = Vec::new();
	let mut in_quotes = false;
	let mut escaped = false;
	let mut start = 0;
	for (idx, ch) in inner.char_indices() {
		match ch {
			'\\' if in_quotes => escaped = !escaped,
			'"' if !escaped => in_quotes = !in_quotes,
			',' if !in_quotes => {
				parts.push(&inner[start..idx]);
				start = idx + 1;
			},
			_ => {},
		}
		if ch != '\\' {
			escaped = false;
		}
	}
	parts.push(&inner[start..]);
	parts
}

fn unescape_label(value: &str) -> String {
	let mut out = String::with_capacity(value.len());
	let mut chars = value.chars();
	while let Some(ch) = chars.next() {
		if ch == '\\' {
			match chars.next() {
				Some('n') => out.push('\n'),
				Some(next) => out.push(next),
				None => {},
			}
		} else {
			out.push(ch);
		}
	}
	out
}

fn parse_value(value: &str) -> Option<f64> {
	match value {
		"+Inf" | "Inf" => Some(f64::INFINITY),
		"-Inf" => Some(f64::NEG_INFINITY),
		"NaN" => Some(f64::NAN),
		v => v.parse::<f64>().ok(),
	}
}
