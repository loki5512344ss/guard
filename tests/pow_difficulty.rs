//! Adaptive PoW difficulty: configured floor, range clamping and the rate
//! ladder. The adjuster lives in `src/engine/challenge/difficulty.rs`; these
//! tests are the only consumer of the range constants.

use rampart::engine::challenge::{DifficultyAdjuster, MAX_DIFFICULTY, MIN_DIFFICULTY};

#[test]
fn idle_uses_the_configured_floor() {
	let adjuster = DifficultyAdjuster::new(4, 10);
	assert_eq!(adjuster.current_difficulty(), 4);
}

#[test]
fn configured_pow_difficulty_is_the_starting_point() {
	// `[pow].difficulty = 7` must not be ignored until the first connection.
	assert_eq!(DifficultyAdjuster::with_floor(7).current_difficulty(), 7);
}

#[test]
fn configured_floor_can_be_lower_than_the_old_hardcoded_minimum() {
	assert_eq!(DifficultyAdjuster::with_floor(2).current_difficulty(), 2);
}

#[test]
fn configured_floor_is_clamped_to_the_supported_range() {
	assert_eq!(DifficultyAdjuster::with_floor(0).current_difficulty(), MIN_DIFFICULTY);
	assert_eq!(DifficultyAdjuster::with_floor(250).current_difficulty(), MAX_DIFFICULTY);
}

#[test]
fn inverted_range_is_swapped_instead_of_breaking_the_clamp() {
	let mut adjuster = DifficultyAdjuster::new(9, 5);
	assert_eq!(adjuster.current_difficulty(), 5, "lower end is the starting point");
	for _ in 0..600 {
		adjuster.record_connection();
	}
	assert_eq!(
		adjuster.current_difficulty(),
		9,
		"under load the swapped upper end applies"
	);
}

#[test]
fn pinned_range_never_moves() {
	let mut adjuster = DifficultyAdjuster::new(6, 6);
	for _ in 0..600 {
		adjuster.record_connection();
	}
	assert_eq!(adjuster.current_difficulty(), 6);
}

#[test]
fn rate_ladder_is_clamped_to_the_configured_range() {
	let mut adjuster = DifficultyAdjuster::new(7, 8);
	for _ in 0..60 {
		adjuster.record_connection();
	}
	// Raw ladder step is 6, below the configured floor.
	assert_eq!(adjuster.current_difficulty(), 7);
	for _ in 60..201 {
		adjuster.record_connection();
	}
	// Raw ladder step is 8 and fits the range.
	assert_eq!(adjuster.current_difficulty(), 8);
	for _ in 201..600 {
		adjuster.record_connection();
	}
	// Raw ladder step is MAX_DIFFICULTY, above the configured ceiling.
	assert_eq!(adjuster.current_difficulty(), 8);
}

#[test]
fn default_range_rises_to_ten_under_load() {
	let mut adjuster = DifficultyAdjuster::default();
	for _ in 0..600 {
		adjuster.record_connection();
	}
	assert_eq!(adjuster.current_difficulty(), 10);
}
