//! Manager JWT authentication: token round-trip and rejection of tokens signed
//! for a different audience or with a different secret.

use rampart::manager::auth::{create_token, verify_token};

fn valid_secret() -> String {
	"this-is-a-test-secret-32-bytes-long!".to_string()
}

#[test]
fn create_verify_roundtrip_passes() {
	let secret = valid_secret();
	let token = create_token(&secret, 3600, "rampart").expect("token creation should succeed");
	let claims = verify_token(&token, &secret, "rampart").expect("verification should succeed");
	assert_eq!(claims.sub, "rampart-admin");
	assert_eq!(claims.aud, "rampart");
	assert_eq!(claims.role, "admin");
	assert!(claims.exp > claims.iat);
}

#[test]
fn verify_rejects_wrong_audience() {
	let secret = valid_secret();
	let token = create_token(&secret, 3600, "rampart").expect("token creation should succeed");
	assert!(verify_token(&token, &secret, "other").is_err());
}

#[test]
fn verify_rejects_wrong_secret() {
	let secret = valid_secret();
	let other_secret = "another-test-secret-also-32-bytes-long!".to_string();
	let token = create_token(&secret, 3600, "rampart").expect("token creation should succeed");
	assert!(verify_token(&token, &other_secret, "rampart").is_err());
}
