//! Минималистичный парсер текстового формата Prometheus (version=0.0.4).
//!
//! Поддерживает: комментарии (`# HELP`, `# TYPE`, `#`), строки вида
//! `metric{label="value",...} value [timestamp]` и `metric value [timestamp]`.
//! Значения `NaN`/`+Inf`/`-Inf` парсятся штатно через `f64::from_str`.

use std::collections::BTreeMap;

/// Один сэмпл из exposition-формата Prometheus.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// Набор сэмплов одного ответа `/metrics`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MetricSet {
    samples: Vec<MetricSample>,
}

impl MetricSet {
    /// Сумма значений всех серий с данным именем (для counter/gauge vec).
    /// Отсутствующая метрика даёт `0.0`.
    #[must_use]
    pub fn sum(&self, name: &str) -> f64 {
        self.samples.iter().filter(|s| s.name == name).map(|s| s.value).sum()
    }

    /// Значение серии с именем и одной меткой; `None`, если не найдено.
    #[must_use]
    pub fn labeled(&self, name: &str, label: &str, value: &str) -> Option<f64> {
        self.samples
            .iter()
            .find(|s| s.name == name && s.labels.get(label).map(String::as_str) == Some(value))
            .map(|s| s.value)
    }

    /// Все сэмплы (для тестов и отладки).
    #[must_use]
    pub fn samples(&self) -> &[MetricSample] {
        &self.samples
    }
}

/// Парсит тело ответа `/metrics`.
///
/// Строки с ошибкой формата пропускаются (exposition-поток может быть частично
/// повреждён — TUI не должен падать на этом).
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
    // Формат: metric[{labels}] value [timestamp]; значения меток могут
    // содержать пробелы, поэтому голову отрезаем с учётом кавычек.
    let (head, rest) = split_head_and_rest(line);
    let value_str = rest.split_whitespace().next()?;
    // Timestamp после value игнорируем.

    let (name, labels) = split_metric(head)?;
    let value = parse_value(value_str)?;
    Some(MetricSample { name, labels, value })
}

/// Отделяет `metric{...}` от хвоста `value [timestamp]`.
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

/// Индекс `}` вне кавычек, начиная с позиции `from`.
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

/// Разбивает `a="1", b="2"` по запятым вне кавычек.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and_labeled_lines() {
        let set = parse("up 1\nxdp_total{iface=\"eth0\"} 42\n");
        assert_eq!(set.sum("up"), 1.0);
        assert_eq!(set.labeled("xdp_total", "iface", "eth0"), Some(42.0));
    }

    #[test]
    fn skips_comments_help_type_and_empty_lines() {
        let input = "# HELP rampart_xdp_total Total\n# TYPE rampart_xdp_total gauge\n\nrampart_xdp_total 7\n";
        let set = parse(input);
        assert_eq!(set.samples().len(), 1);
        assert_eq!(set.sum("rampart_xdp_total"), 7.0);
    }

    #[test]
    fn ignores_timestamp_and_special_values() {
        let set = parse("m1 10 1700000000000\nm2 +Inf\nm3 NaN\nbroken_line_no_value\nbad{} \nm4 -2.5e3\n");
        assert_eq!(set.sum("m1"), 10.0);
        assert_eq!(set.sum("m2"), f64::INFINITY);
        assert!(set.labeled("m3", "x", "y").is_none());
        assert_eq!(set.sum("m4"), -2500.0);
    }

    #[test]
    fn sums_series_with_same_name() {
        let input = "bans{reason=\"cps\"} 3\nbans{reason=\"syn\"} 4\nbans 5\n";
        assert_eq!(parse(input).sum("bans"), 12.0);
    }

    #[test]
    fn handles_spaces_in_label_values() {
        let set = parse("m{k=\"a b\", j=\"v w\"} 1\n");
        assert_eq!(set.labeled("m", "k", "a b"), Some(1.0));
        assert_eq!(set.labeled("m", "j", "v w"), Some(1.0));
    }

    #[test]
    fn handles_escaped_quotes_and_backslashes_in_labels() {
        let set = parse("m{q=\"a\\\"b\", s=\"c\\\\d\"} 1\n");
        assert_eq!(set.labeled("m", "q", "a\"b"), Some(1.0));
        assert_eq!(set.labeled("m", "s", "c\\d"), Some(1.0));
    }
}
