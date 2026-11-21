use rampart::app::lockout::{established_peers, ssh_port, unprotected_clients};
use std::collections::HashSet;
use std::net::IpAddr;

const TCP4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100A8C0:0016 0A01A8C0:C350 01 00000000:00000000 02:000A1B2C 00000000     0        0 12345 2 0000000000000000 20 4 30 10 -1
   1: 0100A8C0:0016 0B01A8C0:C351 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000
   2: 0100A8C0:0050 0C01A8C0:C352 01 00000000:00000000 00:00000000 00000000     0        0 22 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:0016 0100007F:C353 01 00000000:00000000 00:00000000 00000000     0        0 23 1 0000000000000000 20 4 30 10 -1
";

const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 B80D0120000000000000000001000000:D431 01 00000000:00000000 02:000A1B2C 00000000     0        0 5 2 0000000000000000 20 4 30 10 -1
   1: 0000000000000000FFFF00000100A8C0:0016 0000000000000000FFFF00000D01A8C0:D432 01 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 20 4 30 10 -1
";

fn ip(text: &str) -> IpAddr {
	text.parse().expect("valid test address")
}

#[test]
fn reads_only_established_connections_to_the_ssh_port() {
	let peers = established_peers(TCP4, 22);
	assert_eq!(peers, vec![ip("192.168.1.10"), ip("127.0.0.1")]);
}

#[test]
fn decodes_ipv6_and_mapped_ipv4_peers() {
	let peers = established_peers(TCP6, 22);
	assert_eq!(peers, vec![ip("2001:db8::1"), ip("192.168.1.13")]);
}

#[test]
fn warns_only_about_non_loopback_clients_missing_from_the_whitelist() {
	let peers = established_peers(TCP4, 22);
	assert_eq!(unprotected_clients(&peers, &HashSet::new()), vec![ip("192.168.1.10")]);
	let whitelist: HashSet<IpAddr> = [ip("192.168.1.10")].into();
	assert!(unprotected_clients(&peers, &whitelist).is_empty());
}

#[test]
fn ssh_port_follows_the_current_session() {
	assert_eq!(ssh_port(Some("10.0.0.5 51000 10.0.0.1 2222")), 2222);
	assert_eq!(ssh_port(Some("garbage")), 22);
	assert_eq!(ssh_port(None), 22);
}

#[test]
fn garbage_lines_are_ignored() {
	assert!(established_peers("header\nnot a table row\n", 22).is_empty());
}
