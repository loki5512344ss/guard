//! Traffic profiling, attack detection and per-IP reputation.
//!
//! Owns the state the edge node feeds from the accept path: [`hook::TrafficHook`]
//! wires reputation, auto-ban and window metrics together, while the `intel`,
//! `prefix` and `profile` submodules hold the detectors themselves.

pub mod hook;
pub mod intel;
pub mod prefix;
pub mod profile;

// Re-exported under the old paths (`traffic::{detector, ewma, ...}`) so the
// grouping into `intel/` and `profile/` stays source-compatible.
pub use intel::{detector, ewma, reputation};
pub use profile::{alert, profiler};
