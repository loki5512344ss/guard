//! Wiring-логика edge-демона: сборка сервисов и главный цикл запуска.

pub mod runtime;
pub mod services;
mod shutdown;

pub use runtime::run;
pub use shutdown::RunExit;
