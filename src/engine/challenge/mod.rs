//! Universal SHA-256 hashcash: challenge generation, solver, verifier and
//! adaptive difficulty.

mod difficulty;
mod pow;

pub use difficulty::DifficultyAdjuster;
pub use pow::{Challenge, enforce, solve};
