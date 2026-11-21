//! Per-CPU counter aggregation: libbpf returns one buffer per possible CPU.

use rampart::xdp::sum_percpu_u64;

fn slot(v: u64) -> Vec<u8> {
	v.to_le_bytes().to_vec()
}

#[test]
fn sums_every_slot_regardless_of_cpu_count() {
	for cpus in [1u64, 2, 7, 64, 512] {
		let slots: Vec<Vec<u8>> = (1..=cpus).map(slot).collect();
		assert_eq!(sum_percpu_u64(&slots), cpus * (cpus + 1) / 2, "{cpus} CPUs");
	}
}

#[test]
fn offline_but_possible_cpus_contribute_zero() {
	let slots = vec![slot(5), slot(0), slot(0), slot(7)];
	assert_eq!(sum_percpu_u64(&slots), 12);
}

#[test]
fn empty_and_short_buffers_are_harmless() {
	assert_eq!(sum_percpu_u64(&[]), 0);
	assert_eq!(sum_percpu_u64(&[vec![1, 2, 3]]), 0);
}

#[test]
fn large_counters_wrap_instead_of_panicking() {
	assert_eq!(sum_percpu_u64(&[slot(u64::MAX), slot(2)]), 1);
}
