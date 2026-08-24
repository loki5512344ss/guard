//! Общее состояние TUI: последний срез метрик, история pps/drops, расчёт rate.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use crate::tui::prometheus::MetricSet;

/// Максимальная длина скользящего окна графика.
pub const HISTORY_CAPACITY: usize = 120;

/// Один сэмпл истории (значения — rates, единиц/сек).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HistoryPoint {
    pub packets_per_sec: f64,
    pub drops_per_sec: f64,
}

/// Скользящее окно истории фиксированной ёмкости.
#[derive(Debug, Clone)]
pub struct History {
    points: VecDeque<HistoryPoint>,
}

impl Default for History {
    fn default() -> Self {
        Self {
            points: VecDeque::with_capacity(HISTORY_CAPACITY),
        }
    }
}

impl History {
    /// Добавляет точку, вытесняя старейшую при переполнении окна.
    pub fn push(&mut self, point: HistoryPoint) {
        if self.points.len() == HISTORY_CAPACITY {
            self.points.pop_front();
        }
        self.points.push_back(point);
    }

    /// Точки в хронологическом порядке.
    #[must_use]
    pub fn points(&self) -> &VecDeque<HistoryPoint> {
        &self.points
    }
}

/// Состояние приложения, общее между fetch-потоком и UI-циклом.
#[derive(Debug)]
pub struct AppState {
    url: String,
    snapshot: Mutex<Snapshot>,
    history: Mutex<History>,
    started_at: Instant,
}

impl AppState {
    /// Создаёт состояние с URL источника метрик (для статус-панели).
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            snapshot: Mutex::new(Snapshot::default()),
            history: Mutex::new(History::default()),
            started_at: Instant::now(),
        }
    }

    /// URL источника метрик.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Последний успешный/неуспешный результат fetch.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub metrics: Option<MetricSet>,
    pub fetched_at: Option<Instant>,
    pub error: Option<String>,
}

impl AppState {
    /// Записывает результат очередного fetch и обновляет историю rate.
    pub fn apply_fetch(&self, result: Result<MetricSet, String>, elapsed_secs: f64) {
        let mut snapshot = match self.snapshot.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match result {
            Ok(metrics) => {
                let mut history = match self.history.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let previous = snapshot.metrics.take();
                let point = HistoryPoint {
                    packets_per_sec: counter_rate(
                        previous.as_ref().map(|p| p.sum("rampart_xdp_total")),
                        Some(metrics.sum("rampart_xdp_total")),
                        elapsed_secs,
                    ),
                    drops_per_sec: counter_rate(
                        previous.as_ref().map(|p| p.sum("rampart_xdp_dropped")),
                        Some(metrics.sum("rampart_xdp_dropped")),
                        elapsed_secs,
                    ),
                };
                history.push(point);
                snapshot.metrics = Some(metrics);
                snapshot.fetched_at = Some(Instant::now());
                snapshot.error = None;
            },
            Err(message) => {
                snapshot.error = Some(message);
            },
        }
    }

    /// Копия среза метрик + истории для отрисовки кадра.
    ///
    /// UI не держит лок — рисуем по снимку.
    #[must_use]
    pub fn frame_data(&self) -> FrameData {
        let snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        FrameData {
            url: self.url.clone(),
            snapshot: snapshot.clone(),
            history,
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }
}

/// Снимок для одного кадра UI.
#[derive(Debug, Default, Clone)]
pub struct FrameData {
    /// URL источника метрик.
    pub url: String,
    pub snapshot: Snapshot,
    pub history: History,
    /// Время работы TUI (сек).
    pub uptime_secs: u64,
}

/// Rate счётчика из двух сэмплов: `(current - previous) / dt`.
///
/// `None` у предыдущего значения (первый сэмпл) даёт 0.0. Сброс счётчика
/// (`current < previous`) трактуетcя как рестарт процесса → 0.0.
#[must_use]
pub fn counter_rate(previous: Option<f64>, current: Option<f64>, elapsed_secs: f64) -> f64 {
    let (Some(previous), Some(current)) = (previous, current) else {
        return 0.0;
    };
    if !(elapsed_secs > 0.0 && current.is_finite()) || current < previous {
        return 0.0;
    }
    (current - previous) / elapsed_secs
}
