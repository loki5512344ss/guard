use crate::AppState;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::time::{Duration, interval};

pub async fn start_heartbeat_check(state: Arc<AppState>) {
    let mut ticker = interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        if let Err(e) = check_nodes(&state).await {
            tracing::warn!("heartbeat check failed: {e}");
        }
    }
}

async fn check_nodes(state: &AppState) -> anyhow::Result<()> {
    let mut conn = state.redis_client.get_multiplexed_async_connection().await?;
    let keys: Vec<String> = redis::cmd("KEYS").arg("rampart:nodes:*").query_async(&mut conn).await?;

    let now = chrono::Utc::now().timestamp();

    for key in &keys {
        let raw: Option<String> = conn.get(key).await?;
        if let Some(json) = raw
            && let Ok(mut node) = serde_json::from_str::<serde_json::Value>(&json)
        {
            let hb = node["last_heartbeat"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.timestamp())
                .unwrap_or(0);
            if now - hb > 60 {
                if let Some(obj) = node.as_object_mut() {
                    obj.insert("status".to_string(), serde_json::Value::String("offline".to_string()));
                    if let Ok(updated) = serde_json::to_string(&node) {
                        let _: () = conn.set(key.as_str(), updated).await.unwrap_or_default();
                    }
                }
                tracing::warn!("Node {key} is offline (heartbeat expired)");
            }
        }
    }
    Ok(())
}
