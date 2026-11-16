//! Manager HTTP API.
//!
//! Owns the route handlers (`auth`, `blacklist`, `inventory`) and the shared
//! HTTP hardening in [`guard`], including the only supported way to assemble
//! the service.
pub mod auth;
pub mod blacklist;
pub mod guard;
pub mod inventory;

pub use guard::build_router;
