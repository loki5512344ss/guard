//! Traffic intelligence: EWMA smoothing, attack detector and per-IP reputation.
//!
//! Owns the scoring primitives consumed by [`crate::traffic::hook`]; the
//! modules are also re-exported at `traffic::{ewma, detector, reputation}`.
pub mod detector;
pub mod ewma;
pub mod reputation;
