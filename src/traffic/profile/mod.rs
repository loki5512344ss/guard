//! Edge-node traffic profiling and attack-detector alerts.
//!
//! Owns the sliding EWMA profiler and the deduplicating alert dispatcher;
//! both are re-exported at `traffic::{profiler, alert}`.
pub mod alert;
pub mod profiler;
