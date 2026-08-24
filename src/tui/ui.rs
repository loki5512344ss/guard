//! Отрисовка кадра ratatui: статус-панель, таблица счётчиков, график pps/drops, помощь.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Row, Table};

use crate::tui::state::{FrameData, HistoryPoint};

/// Имена метрик edge/manager (см. src/metrics.rs и src/xdp/metrics.rs).
mod names {
    pub const XDP_TOTAL: &str = "rampart_xdp_total";
    pub const XDP_TCP: &str = "rampart_xdp_tcp";
    pub const XDP_UDP: &str = "rampart_xdp_udp";
    pub const XDP_PASSED: &str = "rampart_xdp_passed";
    pub const XDP_DROPPED: &str = "rampart_xdp_dropped";
    pub const XDP_THROTTLE: &str = "rampart_xdp_syn_throttle";
    pub const XDP_RATE_LIMIT: &str = "rampart_xdp_rate_limit";
    pub const XDP_BLACKLIST: &str = "rampart_xdp_blacklist";
    pub const RATE_LIMIT_HITS: &str = "rampart_rate_limit_hits";
    pub const AUTO_BANS_TOTAL: &str = "rampart_auto_bans_total";
    pub const INTEL_DROPS: &str = "rampart_intel_rate_limit_drops_total";
    pub const INTEL_CPS: &str = "rampart_intel_cps";
    pub const INTEL_ALERTS: &str = "rampart_intel_alerts_total";
    pub const ATTACK_STATUS: &str = "rampart_attack_status";
}

/// Рисует весь кадр.
pub fn render(frame: &mut Frame, data: &FrameData) {
    let [header, body, help] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    render_header(frame, header, data);
    let [table_area, chart_area] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);
    render_table(frame, table_area, data);
    render_chart(frame, chart_area, data);
    render_help(frame, help);
}

fn status_color(data: &FrameData) -> Color {
    match data.snapshot.error {
        Some(_) => Color::Red,
        None if data.snapshot.fetched_at.is_some() => Color::Green,
        None => Color::Yellow,
    }
}

fn render_header(frame: &mut Frame, area: Rect, data: &FrameData) {
    let dot = Span::styled(
        "● ",
        Style::default().fg(status_color(data)).add_modifier(Modifier::BOLD),
    );
    let title = Span::styled(" Rampart live metrics", Style::default().add_modifier(Modifier::BOLD));
    let state_text = match (&data.snapshot.error, data.snapshot.fetched_at) {
        (Some(err), _) => format!("ERROR: {err}"),
        (_, Some(at)) => format!("OK, last update {}s ago", at.elapsed().as_secs()),
        (None, None) => "waiting for first fetch...".to_owned(),
    };
    let line = Line::from(vec![
        dot,
        title,
        Span::raw(format!(
            "  {}  |  uptime {}s  |  {state_text}",
            data.url, data.uptime_secs
        )),
    ]);
    frame.render_widget(Paragraph::new(line).block(Block::new().borders(Borders::ALL)), area);
}

/// Пары «подпись → имя метрики» для таблицы.
const COUNTER_ROWS: &[(&str, &str)] = &[
    ("XDP total", names::XDP_TOTAL),
    ("XDP tcp", names::XDP_TCP),
    ("XDP udp", names::XDP_UDP),
    ("XDP passed", names::XDP_PASSED),
    ("XDP dropped", names::XDP_DROPPED),
    ("SYN throttle", names::XDP_THROTTLE),
    ("Rate limited", names::XDP_RATE_LIMIT),
    ("Blacklisted", names::XDP_BLACKLIST),
    ("HTTP rate-limit hits", names::RATE_LIMIT_HITS),
    ("Auto bans", names::AUTO_BANS_TOTAL),
    ("Intel rl drops", names::INTEL_DROPS),
    ("Intel cps", names::INTEL_CPS),
    ("Intel alerts", names::INTEL_ALERTS),
];

fn attack_status_label(value: Option<f64>) -> String {
    match value {
        None => "-".to_owned(),
        Some(v) if v <= 0.0 => "normal".to_owned(),
        Some(v) if v < 2.0 => "suspicious".to_owned(),
        Some(_) => "under attack".to_owned(),
    }
}

fn render_table(frame: &mut Frame, area: Rect, data: &FrameData) {
    let rows: Vec<Row> = COUNTER_ROWS
        .iter()
        .map(|(label, metric)| {
            let value = data.snapshot.metrics.as_ref().map(|m| m.sum(metric));
            Row::new(vec![(*label).to_owned(), fmt_value(value)])
        })
        .chain(std::iter::once(Row::new(vec![
            "Attack status".to_owned(),
            attack_status_label(data.snapshot.metrics.as_ref().map(|m| m.sum(names::ATTACK_STATUS))),
        ])))
        .collect();

    let table = Table::new(rows, [Constraint::Percentage(60), Constraint::Percentage(40)])
        .block(Block::new().borders(Borders::ALL).title(" Counters "))
        .header(Row::new(vec!["metric", "value"]).style(Style::default().add_modifier(Modifier::BOLD)));
    frame.render_widget(table, area);
}

#[allow(clippy::float_arithmetic)]
fn fmt_value(value: Option<f64>) -> String {
    match value {
        None => "-".to_owned(),
        Some(v) if !v.is_finite() => format!("{v}"),
        Some(v) if v.fract() == 0.0 => format!("{}", v as u64),
        Some(v) => format!("{v:.1}"),
    }
}

fn history_series(history: &[HistoryPoint], pick: impl Fn(&HistoryPoint) -> f64) -> Vec<(f64, f64)> {
    history
        .iter()
        .enumerate()
        .map(|(idx, point)| (f64::from(idx as u16), pick(point)))
        .collect()
}

fn render_chart(frame: &mut Frame, area: Rect, data: &FrameData) {
    let points: Vec<HistoryPoint> = data.history.points().iter().copied().collect();
    let pps_series = history_series(&points, |p| p.packets_per_sec);
    let drops_series = history_series(&points, |p| p.drops_per_sec);
    let pps = Dataset::default()
        .name("pps")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&pps_series);
    let drops = Dataset::default()
        .name("drops/s")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Red))
        .data(&drops_series);

    let x_max = points.len().max(2) as f64 - 1.0;
    let y_max = points
        .iter()
        .flat_map(|p| [p.packets_per_sec, p.drops_per_sec])
        .fold(1.0_f64, f64::max);

    let chart = Chart::new(vec![pps, drops])
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(" pps / drops (last 120 samples) "),
        )
        .x_axis(Axis::default().bounds([0.0, x_max]))
        .y_axis(Axis::default().bounds([0.0, y_max]));
    frame.render_widget(chart, area);
}

fn render_help(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" quit   "),
            Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" refresh now"),
        ])),
        area,
    );
}
