use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub target: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct BlacklistResponse {
    pub items: Vec<BlacklistEntry>,
    pub total: usize,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AddBlacklistRequest {
    pub target: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub reason: String,
    pub duration_secs: Option<u64>,
}

#[derive(Deserialize)]
pub struct RemoveBlacklistRequest {
    pub target: String,
}

#[cfg(feature = "store-redis")]
mod common;
#[cfg(feature = "store-redis")]
mod list;
#[cfg(feature = "store-redis")]
mod mutate;

#[cfg(feature = "store-redis")]
pub use list::list_blacklist;
#[cfg(feature = "store-redis")]
pub use mutate::{add_blacklist, remove_blacklist};
