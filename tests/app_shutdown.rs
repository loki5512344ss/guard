//! Edge daemon exit codes: a forced drain timeout must not look like success.

use rampart::app::RunExit;

#[test]
fn clean_shutdown_exits_zero() {
	assert_eq!(RunExit::Ok.code(), 0);
}

#[test]
fn forced_drain_timeout_exits_nonzero() {
	// Connections were cut before finishing: supervisors and scripts must see a
	// failure, not a clean exit.
	assert_eq!(RunExit::DrainTimeout.code(), 1);
}
