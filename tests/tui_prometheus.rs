//! Prometheus exposition parser: labeled series, comments, timestamps,
//! special float values and label values containing spaces or escapes.

use rampart::tui::prometheus::parse;

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
