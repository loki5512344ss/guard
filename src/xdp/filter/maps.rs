pub(super) fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Encodes an LPM-trie key for `blacklist_map`: prefix length in byte 0 and the
/// four IPv4 octets in bytes 4..8 (bytes 1..3 are padding the kernel ignores).
pub(super) fn blacklist_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = prefix_len;
    key[4..8].copy_from_slice(v4);
    key
}

/// Absolute ban expiry in ns-since-epoch, saturating so an absurd duration
/// clamps to `u64::MAX` rather than wrapping into the past.
pub(super) fn blacklist_expiry_ns(now_ns: u64, duration_secs: u64) -> u64 {
    now_ns.saturating_add(duration_secs.saturating_mul(1_000_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklist_key_puts_prefix_len_first_and_octets_last() {
        assert_eq!(blacklist_key(24, &[10, 0, 1, 200]), [24, 0, 0, 0, 10, 0, 1, 200]);
        assert_eq!(blacklist_key(32, &[127, 0, 0, 1]), [32, 0, 0, 0, 127, 0, 0, 1]);
    }

    #[test]
    fn blacklist_expiry_converts_secs_to_ns() {
        assert_eq!(blacklist_expiry_ns(1_000, 2), 1_000 + 2_000_000_000);
    }

    #[test]
    fn blacklist_expiry_saturates_instead_of_wrapping() {
        assert_eq!(blacklist_expiry_ns(u64::MAX, 1), u64::MAX);
        assert_eq!(blacklist_expiry_ns(0, u64::MAX), u64::MAX);
    }
}
