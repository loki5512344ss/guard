use rampart::engine::challenge::{Challenge, solve};

/// Fixed 32-byte token: sha256(hex(token) || "garbage") starts with "ebc1",
/// so "garbage" provably fails the difficulty-2 check (first two hex chars
/// must be in "0123"). A random token made this flaky with probability 1/16
/// per run, since any digest lands in the accepted prefix with p=(4/16)^2.
const FIXED_TOKEN: [u8; 32] = *b"rampart-pow-fixed-token-test-v1!";

#[test]
fn solver_output_passes_verifier() {
    let mut challenge = Challenge::generate(3);
    let nonce = solve(&challenge.challenge_string(), 3).expect("solver must find nonce for difficulty 3");
    assert!(challenge.verify(&nonce));
}

#[test]
fn verifier_rejects_garbage_and_replay() {
    let mut challenge = Challenge::with_token(FIXED_TOKEN, 2);
    assert!(!challenge.verify("garbage"));

    let nonce = solve(&challenge.challenge_string(), 2).expect("solved");
    assert!(challenge.verify(&nonce), "first use passes");
    assert!(!challenge.verify(&nonce), "replay is rejected");
}
