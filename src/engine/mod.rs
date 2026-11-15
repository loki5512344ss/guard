//! Edge engine: multi-worker listener, generic TCP tunnel and the PoW gate.
//!
//! Owns the per-connection pipeline and the subnet-level detection wiring that
//! sits between the kernel filter and the traffic intelligence layer.

pub mod challenge;
pub mod listener;
pub mod subnet;
pub mod tunnel;

// Path compatibility after the move into `subnet/`: `engine::subnet_tracker` and
// `engine::subnet_monitor` stay valid module paths.
pub use subnet::{monitor as subnet_monitor, tracker as subnet_tracker};
