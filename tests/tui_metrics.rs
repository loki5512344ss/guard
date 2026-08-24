//! Тесты TUI-модуля: парсер Prometheus, расчёт rate, поведение при ошибках fetch.

use futures::future::BoxFuture;
use rampart::tui::fetch::{FetchError, Fetcher, HttpFetcher};
use rampart::tui::prometheus::{MetricSample, parse};
use rampart::tui::state::{AppState, counter_rate};

// ---------- парсер ----------

#[test]
fn parses_metric_with_labels_value_and_timestamp() {
    let set = parse("rampart_xdp_total{iface=\"eth0\",core=\"0\"} 123 1700000000000\n");
    assert_eq!(
        set.samples(),
        vec![MetricSample {
            name: "rampart_xdp_total".to_owned(),
            labels: [("iface", "eth0"), ("core", "0")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            value: 123.0,
        }]
    );
}

#[test]
fn parser_skips_comments_help_and_type() {
    let body = "\
# HELP rampart_xdp_dropped Packets dropped\n\
# TYPE rampart_xdp_dropped gauge\n\
# обычный комментарий\n\
rampart_xdp_dropped 42\n";
    let set = parse(body);
    assert_eq!(set.samples().len(), 1);
    assert_eq!(set.sum("rampart_xdp_dropped"), 42.0);
}

#[test]
fn parser_sums_counter_vec_series() {
    let body = "rampart_auto_bans_total{reason=\"cps\"} 3\nrampart_auto_bans_total{reason=\"syn\"} 4\n";
    assert_eq!(parse(body).sum("rampart_auto_bans_total"), 7.0);
}

#[test]
fn parser_missing_metric_is_zero() {
    assert_eq!(parse("# nothing here\n").sum("rampart_xdp_tcp"), 0.0);
}

#[test]
fn parser_tolerates_malformed_lines() {
    let set = parse("garbage\nm{unterminated=\"v} 1\nok_metric 5\n");
    assert_eq!(set.sum("ok_metric"), 5.0);
    assert_eq!(set.samples().len(), 1);
}

// ---------- rate ----------

#[test]
fn rate_from_two_samples_divides_by_elapsed() {
    // 1200 - 1100 = 100 пакетов за 2 сек
    assert_eq!(counter_rate(Some(1100.0), Some(1200.0), 2.0), 50.0);
}

#[test]
fn rate_first_sample_and_counter_reset_are_zero() {
    assert_eq!(counter_rate(None, Some(10.0), 1.0), 0.0);
    assert_eq!(counter_rate(Some(20.0), Some(10.0), 1.0), 0.0);
    assert_eq!(counter_rate(Some(10.0), Some(12.0), 0.0), 0.0);
}

#[test]
fn state_accumulates_history_rates() {
    let state = AppState::new("http://test/metrics");
    state.apply_fetch(Ok(parse("rampart_xdp_total 100\n")), 1.0);
    state.apply_fetch(Ok(parse("rampart_xdp_total 150\n")), 1.0);
    let frame = state.frame_data();
    assert_eq!(frame.history.points().len(), 2);
    assert_eq!(frame.history.points()[1].packets_per_sec, 50.0);
    assert!(frame.snapshot.error.is_none());
}

// ---------- ошибки fetch (мок Fetcher + локальный HTTP-сервер) ----------

struct FailingFetcher {
    error: FetchError,
}

impl Fetcher for FailingFetcher {
    fn fetch(&self) -> BoxFuture<'_, Result<String, FetchError>> {
        let error = self.error.clone();
        Box::pin(async { Err(error) })
    }
}

#[test]
fn network_error_sets_error_banner_not_panic() {
    let state = AppState::new("http://127.0.0.1:9/metrics");
    let fetcher = FailingFetcher {
        error: FetchError::Network("connection refused".to_owned()),
    };

    // Тот же путь, что и в spawn_fetch_loop: normalize → apply_fetch.
    let normalized = rampart::tui::app::normalize(Err(fetcher.error));
    assert!(normalized.is_err());
    let message = match normalized {
        Err(message) => message,
        Ok(_) => return,
    };

    state.apply_fetch(Err(message), 1.0);
    assert_eq!(state.frame_data().snapshot.error.as_deref(), Some("connection refused"));
}

#[tokio::test]
async fn http_fetcher_reads_prometheus_body_from_local_server() {
    let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(addr) = listener.local_addr() else {
        return;
    };
    let server = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if let Ok((mut stream, _)) = listener.accept().await {
            let body = "rampart_xdp_total 99\n";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
        }
    });

    let Some(fetcher) = HttpFetcher::new(format!("http://{addr}/metrics")) else {
        server.abort();
        return;
    };
    let Ok(body) = fetcher.fetch().await else {
        server.abort();
        return;
    };
    assert_eq!(parse(&body).sum("rampart_xdp_total"), 99.0);
    server.abort();
}

#[test]
fn failed_fetch_keeps_last_good_metrics_but_reports_error() {
    let state = AppState::new("http://test/metrics");
    state.apply_fetch(Ok(parse("rampart_xdp_total 7\n")), 1.0);
    state.apply_fetch(Err("connection refused".to_owned()), 1.0);

    let frame = state.frame_data();
    assert_eq!(frame.snapshot.error.as_deref(), Some("connection refused"));
    assert_eq!(
        frame.snapshot.metrics.as_ref().map(|m| m.sum("rampart_xdp_total")),
        Some(7.0)
    );
}
