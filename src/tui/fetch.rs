//! Получение тела `/metrics`: трейт [`Fetcher`] для мока в тестах и HTTP-реализация.

use std::time::Duration;

use futures::future::BoxFuture;
use thiserror::Error;

/// Ошибка загрузки метрик.
#[derive(Debug, Error, Clone)]
pub enum FetchError {
    /// Сетевая ошибка / DNS / таймаут.
    #[error("network error: {0}")]
    Network(String),
    /// Endpoint ответил не-200 статусом.
    #[error("http status {0}")]
    Status(u16),
}

/// Абстракция источника exposition-текста Prometheus.
pub trait Fetcher: Send + Sync {
    /// Загружает текущий срез метрик.
    ///
    /// # Errors
    /// Возвращает [`FetchError`] при сетевом сбое или плохом HTTP-статусе.
    fn fetch(&self) -> BoxFuture<'_, Result<String, FetchError>>;
}

/// Реализация [`Fetcher`] поверх reqwest GET.
pub struct HttpFetcher {
    url: String,
    client: reqwest::Client,
}

impl HttpFetcher {
    /// Создаёт fetcher с таймаутом запроса 5 секунд.
    pub fn new(url: impl Into<String>) -> Option<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;
        Some(Self {
            url: url.into(),
            client,
        })
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self) -> BoxFuture<'_, Result<String, FetchError>> {
        let url = self.url.clone();
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| FetchError::Network(e.to_string()))?;
            let status = response.status();
            if !status.is_success() {
                return Err(FetchError::Status(status.as_u16()));
            }
            response.text().await.map_err(|e| FetchError::Network(e.to_string()))
        })
    }
}
