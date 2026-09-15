//! Edge-движок: listener, generic TCP tunnel, PoW gate.

pub mod challenge;
pub mod listener;
pub mod subnet;
pub mod tunnel;

// Совместимость путей после переезда в subnet/: `engine::subnet_tracker` /
// `engine::subnet_monitor` остаются валидными алиасами модулей.
pub use subnet::{monitor as subnet_monitor, tracker as subnet_tracker};
