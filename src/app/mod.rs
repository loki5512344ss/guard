//! Edge daemon wiring: service construction and the main run loop.

pub mod lockout;
pub mod runtime;
pub mod services;
mod shutdown;

pub use runtime::run;
pub use shutdown::RunExit;
