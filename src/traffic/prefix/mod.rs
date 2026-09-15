//! Subnet-level (prefix) детектор распределённых атак.
//!
//! Источник данных — трейт [`PrefixStatsSource`]: карта XDP `prefix_stats`
//! (feature `xdp`) либо юзерспейс-агрегатор [`crate::engine::subnet_tracker`].
//! Контракт с XDP-агентом: [`PrefixKey`] / [`PrefixStatsVal`] должны совпадать
//! побайтово со структурами ядра.

mod key;
mod stats;

pub use key::{PREFIX_FAMILY_V4, PREFIX_FAMILY_V6, PrefixKey, prefix_of};
#[cfg(feature = "xdp")]
pub use stats::XdpPrefixStats;
pub use stats::{PrefixSnapshot, PrefixStatsSource, PrefixStatsVal, PrefixVerdict, SubnetDetector, SubnetVerdict};
