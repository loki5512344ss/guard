//! TUI metrics: the Prometheus exposition parser and the endpoint fetchers.
//!
//! Owns the read-only side of the TUI: turning `/metrics` text into a
//! [`prometheus::MetricSet`] and pulling the body over HTTP (or a test mock).
pub mod fetch;
pub mod prometheus;
