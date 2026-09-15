//! Профилирование трафика, детектор атак и репутация IP.

pub mod hook;
pub mod intel;
pub mod prefix;
pub mod profile;

// Совместимость путей после группировки: домены `intel/` и `profile/`
// остаются доступны по прежним путям `traffic::{detector, ewma, ...}`.
pub use intel::{detector, ewma, reputation};
pub use profile::{alert, profiler};
