//! Universal SHA-256 hashcash: challenge generation, solver, verifier and
//! adaptive difficulty.

mod difficulty;
mod pow;

pub use difficulty::{DifficultyAdjuster, MAX_DIFFICULTY, MIN_DIFFICULTY};
pub use pow::{Challenge, enforce, solve};
