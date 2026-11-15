//! Rampart TUI: live edge-node and manager metrics in the terminal (ratatui).
//!
//! Owns the terminal front end used by the `rampart-tui` binary; the data
//! source is the Prometheus exposition endpoint (`/metrics`).
//!
//! The fetch task and the render loop communicate only through
//! [`state::AppState`], so a slow or failing endpoint never blocks the UI.

pub mod app;
pub mod metrics;
pub mod state;
pub mod ui;

pub use metrics::{fetch, prometheus};
