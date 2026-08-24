//! TUI-модуль Rampart: live-метрики edge-ноды/manager в терминале (ratatui).
//!
//! Используется бинарём `rampart-tui`; источник данных — Prometheus
//! exposition endpoint (`/metrics`).

pub mod app;
pub mod fetch;
pub mod prometheus;
pub mod state;
pub mod ui;
