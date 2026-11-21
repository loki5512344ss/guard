use rampart::filter::blacklist::Blacklist;
use std::net::IpAddr;
use std::time::Duration;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("valid test address")
}

#[test]
fn port_ban_blocks_only_that_port() {
	let blacklist = Blacklist::new();
	let attacker = ip("203.0.113.9");
	assert!(blacklist.add_port(attacker, 25565, Duration::from_secs(60)));

	assert!(blacklist.is_blocked_on(attacker, 25565));
	assert!(!blacklist.is_blocked_on(attacker, 22), "SSH port must stay reachable");
	assert!(
		!blacklist.is_blocked(attacker),
		"an address-wide lookup is not affected"
	);
	assert!(
		!blacklist.is_blocked_on(ip("203.0.113.10"), 25565),
		"other addresses are not affected"
	);
}

#[test]
fn address_ban_covers_every_port() {
	let blacklist = Blacklist::new();
	let attacker = ip("203.0.113.9");
	blacklist.add(attacker, Duration::from_secs(60), "test");
	assert!(blacklist.is_blocked_on(attacker, 22));
	assert!(blacklist.is_blocked_on(attacker, 25565));
}

#[test]
fn port_ban_expires_and_can_be_removed() {
	let blacklist = Blacklist::new();
	let client = ip("198.51.100.4");
	assert!(blacklist.add_port(client, 80, Duration::from_millis(30)));
	assert!(blacklist.is_blocked_on(client, 80));
	std::thread::sleep(Duration::from_millis(60));
	assert!(
		!blacklist.is_blocked_on(client, 80),
		"an expired port ban must stop applying"
	);

	assert!(blacklist.add_port(client, 80, Duration::from_secs(60)));
	blacklist.remove_port(client, 80);
	assert!(!blacklist.is_blocked_on(client, 80));
}

#[test]
fn port_zero_and_mapped_addresses() {
	let blacklist = Blacklist::new();
	assert!(
		!blacklist.add_port(ip("192.0.2.1"), 0, Duration::from_secs(60)),
		"port 0 means any and is rejected"
	);
	assert!(blacklist.add_port(ip("::ffff:192.0.2.7"), 443, Duration::from_secs(60)));
	assert!(
		blacklist.is_blocked_on(ip("192.0.2.7"), 443),
		"mapped and plain IPv4 share one key"
	);
}

#[test]
fn port_bans_are_counted_and_swept() {
	let blacklist = Blacklist::new();
	assert!(blacklist.is_empty());
	blacklist.add_port(ip("192.0.2.1"), 25565, Duration::from_millis(20));
	assert_eq!(blacklist.len(), 1);
	std::thread::sleep(Duration::from_millis(50));
	blacklist.clear_expired();
	assert!(blacklist.is_empty());
}
