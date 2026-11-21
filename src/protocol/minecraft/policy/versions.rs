//! Known Minecraft Java protocol ids.
//!
//! Only ids verified against the public protocol version list are included.
//! Newer or snapshot ids are valid but unnamed: they are labelled `other` in
//! metrics so label cardinality stays bounded.

/// `(protocol id, release name)` sorted by id.
pub const VERSIONS: &[(i32, &str)] = &[
	(47, "1.8.x"),
	(107, "1.9"),
	(108, "1.9.1"),
	(109, "1.9.2"),
	(110, "1.9.3-4"),
	(210, "1.10.x"),
	(315, "1.11"),
	(316, "1.11.1-2"),
	(335, "1.12"),
	(338, "1.12.1"),
	(340, "1.12.2"),
	(393, "1.13"),
	(401, "1.13.1"),
	(404, "1.13.2"),
	(477, "1.14"),
	(480, "1.14.1"),
	(485, "1.14.2"),
	(490, "1.14.3"),
	(498, "1.14.4"),
	(573, "1.15"),
	(575, "1.15.1"),
	(578, "1.15.2"),
	(735, "1.16"),
	(736, "1.16.1"),
	(751, "1.16.2"),
	(753, "1.16.3"),
	(754, "1.16.4-5"),
	(755, "1.17"),
	(756, "1.17.1"),
	(757, "1.18-1.18.1"),
	(758, "1.18.2"),
	(759, "1.19"),
	(760, "1.19.1-2"),
	(761, "1.19.3"),
	(762, "1.19.4"),
	(763, "1.20-1.20.1"),
	(764, "1.20.2"),
	(765, "1.20.3-4"),
	(766, "1.20.5-6"),
	(767, "1.21-1.21.1"),
	(768, "1.21.2-3"),
	(769, "1.21.4"),
	(770, "1.21.5"),
	(771, "1.21.6"),
	(772, "1.21.7-8"),
];

/// Release name for a known id.
#[must_use]
pub fn name(id: i32) -> Option<&'static str> {
	VERSIONS.iter().find(|(known, _)| *known == id).map(|(_, name)| *name)
}

/// Bounded metrics label: the release name, or `other` for unknown ids.
#[must_use]
pub fn label(id: i32) -> &'static str {
	name(id).unwrap_or("other")
}

/// Whether `id` is a protocol id a real client can send.
///
/// Releases use small ids; development snapshots set bit 30 on top of a small
/// number. Anything else is a malformed or probing client.
#[must_use]
pub fn is_plausible(id: i32) -> bool {
	const SNAPSHOT_BIT: i32 = 0x4000_0000;
	const MAX_SMALL: i32 = 0xFFFF;
	id >= 0 && ((4..=MAX_SMALL).contains(&id) || (id & SNAPSHOT_BIT != 0 && (id & !SNAPSHOT_BIT) <= MAX_SMALL))
}
