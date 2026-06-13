// src/bin/cachydpi-monitor.rs — Real-time TUI dashboard for CachyDPI
//
// Connects to the running CachyDPI daemon via Unix socket, reads JSON
// metrics snapshots, and renders a live dashboard in the terminal.
//
// Usage: cachydpi-monitor [socket-path]
// Default socket: /run/cachydpi/metrics.sock

use std::io::{self, BufRead, BufReader, stdout};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::prelude::*;
use ratatui::widgets::*;

use cachydpi::metrics::{DEFAULT_METRICS_SOCKET, FALLBACK_METRICS_SOCKET, MetricsSnapshot};

// ── Application state ──

struct App {
    snapshot: Option<MetricsSnapshot>,
    prev_snapshot: Option<MetricsSnapshot>,
    error: Option<String>,
    socket_path: String,
}

impl App {
    fn poll(&mut self) {
        self.prev_snapshot = self.snapshot.take();
        match fetch_snapshot(&self.socket_path) {
            Ok(s) => {
                self.error = None;
                self.snapshot = Some(s);
            }
            Err(e) => {
                self.error = Some(e);
            }
        }
    }

    fn out_rate(&self) -> f64 {
        rate_of(&self.prev_snapshot, &self.snapshot, |s| s.outbound.total)
    }

    fn in_rate(&self) -> f64 {
        rate_of(&self.prev_snapshot, &self.snapshot, |s| s.inbound.total)
    }

    fn cpu_percent(&self) -> f64 {
        let (Some(prev), Some(curr)) = (&self.prev_snapshot, &self.snapshot) else {
            return 0.0;
        };
        let dt = (curr.timestamp_ms.saturating_sub(prev.timestamp_ms)) as f64 / 1000.0;
        if dt < 0.1 {
            return 0.0;
        }
        let cpu_delta = curr.resources.cpu_secs - prev.resources.cpu_secs;
        if cpu_delta < 0.0 {
            return 0.0;
        }
        (cpu_delta / dt) * 100.0
    }
}

fn rate_of(
    prev: &Option<MetricsSnapshot>,
    curr: &Option<MetricsSnapshot>,
    extract: impl Fn(&MetricsSnapshot) -> u64,
) -> f64 {
    let (Some(p), Some(c)) = (prev, curr) else {
        return 0.0;
    };
    let dt = (c.timestamp_ms.saturating_sub(p.timestamp_ms)) as f64 / 1000.0;
    if dt < 0.1 {
        return 0.0;
    }
    let delta = extract(c).saturating_sub(extract(p));
    delta as f64 / dt
}

// ── Entry point ──

fn main() -> io::Result<()> {
    // Install panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        original_hook(info);
    }));

    let result = run();

    // Always restore terminal
    let _ = terminal::disable_raw_mode();
    let _ = stdout().execute(LeaveAlternateScreen);

    result
}

fn run() -> io::Result<()> {
    let socket_path = std::env::args()
        .nth(1)
        .or_else(find_socket)
        .unwrap_or_else(|| {
            eprintln!(
                "error: CachyDPI metrics socket not found.\n\
                 Is the daemon running? Checked:\n  {}\n  {}",
                DEFAULT_METRICS_SOCKET, FALLBACK_METRICS_SOCKET
            );
            std::process::exit(1);
        });

    terminal::enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        snapshot: None,
        prev_snapshot: None,
        error: None,
        socket_path,
    };

    loop {
        app.poll();

        terminal.draw(|frame| render_ui(frame, &app))?;

        if event::poll(Duration::from_secs(1))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                _ => {}
            }
        }
    }

    Ok(())
}

// ── Socket client ──

fn fetch_snapshot(path: &str) -> Result<MetricsSnapshot, String> {
    let stream = UnixStream::connect(path).map_err(|e| format!("connect: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("timeout: {}", e))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read: {}", e))?;
    serde_json::from_str(&line).map_err(|e| format!("parse: {}", e))
}

fn find_socket() -> Option<String> {
    for path in &[DEFAULT_METRICS_SOCKET, FALLBACK_METRICS_SOCKET] {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

// ── UI Rendering ──

fn render_ui(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // If terminal is too small, just show a message
    if area.width < 60 || area.height < 16 {
        let msg = Paragraph::new("Terminal too small. Need at least 60x16.")
            .style(Style::default().fg(Color::Red));
        frame.render_widget(msg, area);
        return;
    }

    let outer = Layout::vertical([
        Constraint::Length(3), // Header
        Constraint::Min(8),    // Main panels
        Constraint::Length(3), // Errors
        Constraint::Length(7), // Recent events
        Constraint::Length(1), // Footer
    ])
    .split(area);

    render_header(frame, outer[0], app);
    render_main_panels(frame, outer[1], app);
    render_errors(frame, outer[2], app);
    render_events(frame, outer[3], app);
    render_footer(frame, outer[4], app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let (status_text, status_color) = if let Some(ref s) = app.snapshot {
        let age_ms = cachydpi::metrics::epoch_ms().saturating_sub(s.health.last_out_packet_ms);
        if age_ms < 10_000 {
            ("● RUNNING", Color::Green)
        } else {
            ("● IDLE", Color::Yellow)
        }
    } else if app.error.is_some() {
        ("● DISCONNECTED", Color::Red)
    } else {
        ("○ CONNECTING", Color::DarkGray)
    };

    let (mode_str, uptime_str, pid_str) = if let Some(ref s) = app.snapshot {
        (
            format!("{} ({})", s.service.mode_name, s.service.mode),
            fmt_duration(s.uptime_secs),
            format!("{}", s.service.pid),
        )
    } else {
        ("—".into(), "—".into(), "—".into())
    };

    let cpu = app.cpu_percent();
    let (ram_str, threads_str, fds_str) = if let Some(ref s) = app.snapshot {
        (
            fmt_bytes(s.resources.rss_bytes),
            format!("{}", s.resources.threads),
            format!("{}", s.resources.open_fds),
        )
    } else {
        ("—".into(), "—".into(), "—".into())
    };

    let line1 = Line::from(vec![
        Span::styled(" CachyDPI ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("│ "),
        Span::styled(status_text, Style::default().fg(status_color).bold()),
        Span::raw(" │ Mode: "),
        Span::styled(&mode_str, Style::default().fg(Color::White)),
        Span::raw(" │ Up: "),
        Span::styled(&uptime_str, Style::default().fg(Color::White)),
        Span::raw(" │ PID: "),
        Span::styled(&pid_str, Style::default().fg(Color::DarkGray)),
    ]);

    let line2 = Line::from(vec![
        Span::raw(" CPU: "),
        Span::styled(
            format!("{:.1}%", cpu),
            Style::default().fg(if cpu > 10.0 {
                Color::Yellow
            } else {
                Color::White
            }),
        ),
        Span::raw("  RAM: "),
        Span::styled(&ram_str, Style::default().fg(Color::White)),
        Span::raw("  Threads: "),
        Span::styled(&threads_str, Style::default().fg(Color::DarkGray)),
        Span::raw("  FDs: "),
        Span::styled(&fds_str, Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let header = Paragraph::new(vec![line1, line2]).block(block);
    frame.render_widget(header, area);
}

fn render_main_panels(frame: &mut Frame, area: Rect, app: &App) {
    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);

    let left_rows =
        Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(cols[0]);
    let right_rows =
        Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(cols[1]);

    render_throughput(frame, left_rows[0], app);
    render_passive(frame, left_rows[1], app);
    render_strategies(frame, right_rows[0], app);
    render_health(frame, right_rows[1], app);
}

fn render_throughput(frame: &mut Frame, area: Rect, app: &App) {
    let s = app.snapshot.as_ref();
    let out_rate = app.out_rate();
    let in_rate = app.in_rate();

    let lines = vec![
        kv_line(
            "Out",
            &format!("{}/s", fmt_rate(out_rate)),
            &format!("Total: {}", fmt_num(s.map_or(0, |s| s.outbound.total))),
            Color::Cyan,
        ),
        kv_line(
            "In",
            &format!("{}/s", fmt_rate(in_rate)),
            &format!("Total: {}", fmt_num(s.map_or(0, |s| s.inbound.total))),
            Color::Cyan,
        ),
        Line::raw(""),
        stat_line(
            "Accepted",
            s.map_or(0, |s| s.outbound.accepted),
            Color::Green,
        ),
        stat_line(
            "Fragmented",
            s.map_or(0, |s| s.outbound.fragmented),
            Color::Yellow,
        ),
        stat_line(
            "Fakes Sent",
            s.map_or(0, |s| s.strategies.fake_packets),
            Color::Yellow,
        ),
        stat_line(
            "Modified",
            s.map_or(0, |s| s.outbound.modified),
            Color::DarkGray,
        ),
        stat_line(
            "Dropped",
            s.map_or(0, |s| s.outbound.dropped),
            if s.map_or(0, |s| s.outbound.dropped) > 0 {
                Color::Red
            } else {
                Color::DarkGray
            },
        ),
    ];

    let block = Block::default()
        .title(" Throughput ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_passive(frame: &mut Frame, area: Rect, app: &App) {
    let s = app.snapshot.as_ref();
    let rst = s.map_or(0, |s| s.inbound.forged_rst);
    let alert = s.map_or(0, |s| s.inbound.forged_alert);
    let redir = s.map_or(0, |s| s.inbound.forged_redirect);
    let total = rst + alert + redir;

    let lines = vec![
        stat_line(
            "RST Dropped",
            rst,
            if rst > 0 {
                Color::Green
            } else {
                Color::DarkGray
            },
        ),
        stat_line(
            "TLS Alert",
            alert,
            if alert > 0 {
                Color::Green
            } else {
                Color::DarkGray
            },
        ),
        stat_line(
            "Redirect",
            redir,
            if redir > 0 {
                Color::Green
            } else {
                Color::DarkGray
            },
        ),
        Line::raw(""),
        stat_line(
            "Total Forged",
            total,
            if total > 0 {
                Color::Cyan
            } else {
                Color::DarkGray
            },
        ),
    ];

    let block = Block::default()
        .title(" Passive Defense ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_strategies(frame: &mut Frame, area: Rect, app: &App) {
    let s = app.snapshot.as_ref();

    let lines = vec![
        stat_line(
            "TLS Fragment",
            s.map_or(0, |s| s.strategies.tls_splits),
            Color::Cyan,
        ),
        stat_line(
            "HTTP Fragment",
            s.map_or(0, |s| s.strategies.http_splits),
            Color::Cyan,
        ),
        stat_line(
            "QUIC Desync",
            s.map_or(0, |s| s.strategies.quic_desyncs),
            Color::DarkGray,
        ),
        stat_line(
            "Window Mod",
            s.map_or(0, |s| s.strategies.window_mods),
            Color::DarkGray,
        ),
        Line::raw(""),
        stat_line(
            "Domains Matched",
            s.map_or(0, |s| s.strategies.domains_matched),
            Color::White,
        ),
        stat_line(
            "Domains Skipped",
            s.map_or(0, |s| s.strategies.domains_skipped),
            Color::DarkGray,
        ),
        Line::raw(""),
        Line::from(vec![
            Span::raw(" Auto-TTL: "),
            Span::styled(
                format!(
                    "{} learned",
                    fmt_num(s.map_or(0, |s| s.strategies.ttl_detections))
                ),
                Style::default().fg(Color::White),
            ),
            Span::raw("  Cache: "),
            Span::styled(
                format!("{}", s.map_or(0, |s| s.strategies.ttl_cache_entries)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" Strategies ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_health(frame: &mut Frame, area: Rect, app: &App) {
    let now = cachydpi::metrics::epoch_ms();
    let s = app.snapshot.as_ref();

    let out_age = s.map_or(0, |s| {
        if s.health.last_out_packet_ms > 0 {
            now.saturating_sub(s.health.last_out_packet_ms)
        } else {
            0
        }
    });
    let in_age = s.map_or(0, |s| {
        if s.health.last_in_packet_ms > 0 {
            now.saturating_sub(s.health.last_in_packet_ms)
        } else {
            0
        }
    });
    let err_age = s.map_or(0, |s| {
        if s.health.last_error_ms > 0 {
            now.saturating_sub(s.health.last_error_ms)
        } else {
            0
        }
    });

    let out_label = if out_age == 0 {
        ("○ No data yet", Color::DarkGray)
    } else if out_age < 5_000 {
        ("● Active", Color::Green)
    } else {
        ("● Stale", Color::Yellow)
    };
    let in_label = if in_age == 0 {
        ("○ No data yet", Color::DarkGray)
    } else if in_age < 5_000 {
        ("● Active", Color::Green)
    } else {
        ("● Stale", Color::Yellow)
    };
    let err_label = if err_age == 0 {
        ("● Clean", Color::Green)
    } else if err_age < 60_000 {
        ("● Recent", Color::Yellow)
    } else {
        ("● OK", Color::Green)
    };

    let lines = vec![
        Line::from(vec![
            Span::raw(" Outbound:  "),
            Span::styled(out_label.0, Style::default().fg(out_label.1)),
            if out_age > 0 {
                Span::styled(
                    format!(" ({}ms ago)", fmt_num(out_age)),
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::raw(" Inbound:   "),
            Span::styled(in_label.0, Style::default().fg(in_label.1)),
            if in_age > 0 {
                Span::styled(
                    format!(" ({}ms ago)", fmt_num(in_age)),
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::raw(" Errors:    "),
            Span::styled(err_label.0, Style::default().fg(err_label.1)),
        ]),
    ];

    let block = Block::default()
        .title(" Health ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_errors(frame: &mut Frame, area: Rect, app: &App) {
    let s = app.snapshot.as_ref();
    let parse = s.map_or(0, |s| s.errors.parse_failures);
    let queue = s.map_or(0, |s| s.errors.queue_errors);
    let rate = s.map_or(0, |s| s.errors.rate_limit_drops);
    let sock = s.map_or(0, |s| s.errors.socket_errors);
    let total = parse + queue + rate + sock;

    let color = if total > 0 {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let line = Line::from(vec![
        Span::raw(" Parse: "),
        Span::styled(
            fmt_num(parse),
            Style::default().fg(if parse > 0 {
                Color::Red
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw("  Queue: "),
        Span::styled(
            fmt_num(queue),
            Style::default().fg(if queue > 0 {
                Color::Red
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw("  RateLimit: "),
        Span::styled(
            fmt_num(rate),
            Style::default().fg(if rate > 0 {
                Color::Yellow
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw("  Socket: "),
        Span::styled(
            fmt_num(sock),
            Style::default().fg(if sock > 0 {
                Color::Red
            } else {
                Color::DarkGray
            }),
        ),
    ]);

    let block = Block::default()
        .title(Span::styled(
            format!(" Errors ({}) ", total),
            Style::default().fg(color),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(vec![line]).block(block);
    frame.render_widget(widget, area);
}

fn render_events(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(ref err) = app.error {
        lines.push(Line::from(Span::styled(
            format!(" ✗ {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    if let Some(ref s) = app.snapshot {
        // Show events in reverse chronological order
        for event in s
            .recent_events
            .iter()
            .rev()
            .take(area.height.saturating_sub(2) as usize)
        {
            let (icon, color) = match event.level {
                cachydpi::metrics::EventLevel::Info => ("▸", Color::Cyan),
                cachydpi::metrics::EventLevel::Warning => ("▴", Color::Yellow),
                cachydpi::metrics::EventLevel::Error => ("✗", Color::Red),
            };
            let ts = fmt_timestamp(event.timestamp_ms);
            lines.push(Line::from(vec![
                Span::styled(format!(" [{}] ", ts), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} {}", icon, event.message),
                    Style::default().fg(color),
                ),
            ]));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No events yet",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .title(" Recent Events ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow)),
        Span::raw(": quit  "),
        Span::styled("Socket", Style::default().fg(Color::DarkGray)),
        Span::raw(": "),
        Span::styled(&app.socket_path, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled("Refresh", Style::default().fg(Color::DarkGray)),
        Span::raw(": 1s"),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

// ── Formatting helpers ──

fn stat_line(label: &str, value: u64, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!(" {:<18}", label)),
        Span::styled(fmt_num(value), Style::default().fg(color)),
    ])
}

fn kv_line(label: &str, rate: &str, total: &str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" ▸ {}: ", label), Style::default().fg(Color::White)),
        Span::styled(rate.to_string(), Style::default().fg(color).bold()),
        Span::raw("  "),
        Span::styled(total.to_string(), Style::default().fg(Color::DarkGray)),
    ])
}

fn fmt_num(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn fmt_rate(r: f64) -> String {
    if r < 0.1 {
        "0".into()
    } else if r < 10.0 {
        format!("{:.1}", r)
    } else if r < 1000.0 {
        format!("{:.0}", r)
    } else {
        format!("{:.1}k", r / 1000.0)
    }
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".into();
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{:.0} KB", kb);
    }
    let mb = kb / 1024.0;
    format!("{:.1} MB", mb)
}

fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    if secs < 3600 {
        return format!("{}m {}s", secs / 60, secs % 60);
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h < 24 {
        return format!("{}h {}m", h, m);
    }
    let d = h / 24;
    format!("{}d {}h", d, h % 24)
}

fn fmt_timestamp(epoch_ms: u64) -> String {
    // Simple HH:MM:SS from epoch — avoids chrono dependency
    let secs = epoch_ms / 1000;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}
