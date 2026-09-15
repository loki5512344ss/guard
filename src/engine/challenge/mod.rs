//! Универсальный SHA-256 hashcash: генерация challenge, решатель,
//! верификатор и адаптивная сложность.

mod difficulty;
mod pow;

pub use difficulty::DifficultyAdjuster;
pub use pow::{Challenge, enforce, solve};
