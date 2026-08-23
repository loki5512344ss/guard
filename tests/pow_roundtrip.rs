use rampart::engine::challenge::{Challenge, solve};

#[test]
fn solver_output_passes_verifier() {
    let mut challenge = Challenge::generate(3);
    let nonce = solve(&challenge.challenge_string(), 3).expect("solver must find nonce for difficulty 3");
    assert!(challenge.verify(&nonce));
}

#[test]
fn verifier_rejects_garbage_and_replay() {
    let mut challenge = Challenge::generate(2);
    assert!(!challenge.verify("garbage"));

    let nonce = solve(&challenge.challenge_string(), 2).expect("solved");
    assert!(challenge.verify(&nonce), "first use passes");
    assert!(!challenge.verify(&nonce), "replay is rejected");
}
