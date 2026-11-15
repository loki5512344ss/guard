//! Fetching of the `/metrics` body: the [`Fetcher`] trait for test mocks plus
//! the HTTP implementation.
//!
//! Owns the transport boundary of the TUI; parsing lives in
//! [`crate::tui::prometheus`].

use std::time::Duration;

use futures::future::BoxFuture;
use thiserror::Error;

/// Metrics fetch failure.
#[derive(Debug, Error, Clone)]
pub enum FetchError {
	/// Network error, DNS failure or timeout.
	#[error("network error: {0}")]
	Network(String),
	/// The endpoint answered with a non-200 status.
	#[error("http status {0}")]
	Status(u16),
}

/// Abstraction over a source of Prometheus exposition text.
pub trait Fetcher: Send + Sync {
	/// Fetches the current metrics snapshot.
	///
	/// # Errors
	/// Returns [`FetchError`] on a network failure or a bad HTTP status.
	fn fetch(&self) -> BoxFuture<'_, Result<String, FetchError>>;
}

/// [`Fetcher`] implementation on top of a reqwest GET.
pub struct HttpFetcher {
	url: String,
	client: reqwest::Client,
}

impl HttpFetcher {
	/// Creates a fetcher with a 5 second request timeout.
	///
	/// Returns `None` when the HTTP client cannot be built.
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
