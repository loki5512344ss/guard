//! Rampart is a universal L3/L4/L7 network protection platform.
//!
//! The crate root owns the module tree; each module documents what it owns.
pub mod app;
pub mod cli;
pub mod config;
pub mod engine;
pub mod filter;
pub mod manager;
pub mod metrics;
pub mod protocol;
pub mod store;
pub mod traffic;
pub mod tui;
pub mod xdp;
