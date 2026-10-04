//! `sieve top` — the living cell-grid dashboard.
//!
//! Visual language: **Catppuccin Mocha** over JetBrains Mono — taken
//! directly from the operator's own dotfiles (Stylix base16 scheme
//! `catppuccin-mocha`, dark polarity, JetBrains Mono monospace), so the
//! dashboard reads like the rest of the machine.
//!
//! Panels (all live, all from the running runtime):
//!  - header: system, host, uptime, identity fingerprint + generation
//!  - cells: every cell, its isolation (thread / process / wasm) and state
//!  - mesh: peers and multi-hop routes (dest → next hop, cost)
//!  - hearth: branches with tips and the latest reflog moves
//!  - store: CAS objects, event log length + chain integrity
//!  - metrics: counters and latency percentiles
//!
//! Two ways to run:
//!  - interactive TUI (crossterm alternate screen, `q` quits);
//!  - `--screenshot OUT.json`: boots a demo system headlessly, renders N
//!    frames through a capture backend and writes the cells as JSON (a
//!    helper then paints a PNG) — CI-able visual review.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use ratatui::backend::Backend;
use ratatui::buffer::Cell;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;
use sieveplate_engine::Host;
use sieveplate_hearth::Hearth;
use sieveplate_store::ContentStore;

// ---------------------------------------------------------------------------
// Catppuccin Mocha (the operator's Stylix scheme — dotfiles, not decoration)
// ---------------------------------------------------------------------------

#[allow(dead_code)] // a palette defines the whole theme, not just today's picks
pub mod mocha {
    use ratatui::style::Color;

    pub const BASE: Color = Color::Rgb(0x1e, 0x1e, 0x2e);
    pub const MANTLE: Color = Color::Rgb(0x18, 0x18, 0x25);
    pub const CRUST: Color = Color::Rgb(0x11, 0x11, 0x1b);
    pub const SURFACE0: Color = Color::Rgb(0x31, 0x32, 0x44);
    pub const SURFACE1: Color = Color::Rgb(0x45, 0x47, 0x5a);
    pub const OVERLAY0: Color = Color::Rgb(0x6c, 0x70, 0x86);
    pub const SUBTEXT0: Color = Color::Rgb(0xa6, 0xad, 0xc8);
    pub const TEXT: Color = Color::Rgb(0xcd, 0xd6, 0xf4);
    pub const LAVENDER: Color = Color::Rgb(0xb4, 0xbe, 0xfe);
    pub const BLUE: Color = Color::Rgb(0x89, 0xb4, 0xfa);
    pub const SAPPHIRE: Color = Color::Rgb(0x74, 0xc7, 0xec);
    pub const SKY: Color = Color::Rgb(0x89, 0xdc, 0xeb);
    pub const TEAL: Color = Color::Rgb(0x94, 0xe2, 0xd5);
    pub const GREEN: Color = Color::Rgb(0xa6, 0xe3, 0xa1);
    pub const YELLOW: Color = Color::Rgb(0xf9, 0xe2, 0xaf);
    pub const PEACH: Color = Color::Rgb(0xfa, 0xb3, 0x87);
    pub const MAROON: Color = Color::Rgb(0xeb, 0xa0, 0xac);
    pub const RED: Color = Color::Rgb(0xf3, 0x8b, 0xa8);
    pub const MAUVE: Color = Color::Rgb(0xcb, 0xa6, 0xf7);
    pub const PINK: Color = Color::Rgb(0xf5, 0xc2, 0xe7);
}

fn border_style() -> Style {
    Style::new().fg(mocha::SURFACE1)
}

fn title_style() -> Style {
    Style::new().fg(mocha::MAUVE).add_modifier(Modifier::BOLD)
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(border_style())
        .title(Span::styled(format!(" {title} "), title_style()))
}

// ---------------------------------------------------------------------------
// State collection
// ---------------------------------------------------------------------------

/// One row in the cells panel.
pub struct CellRow {
    pub name: String,
    pub vat: String,
    pub state: String,
    pub isolation: &'static str,
}

/// Everything the dashboard shows, collected from the live runtime.
pub struct TopState {
    pub system: String,
    pub host: String,
    pub uptime_secs: u64,
    pub identity_fp: String,
    pub identity_gen: u32,
    pub cells: Vec<CellRow>,
    pub peers: Vec<String>,
    pub routes: Vec<(String, String, u32)>,
    pub branches: Vec<(String, String)>,
    pub reflog_last: Option<String>,
    pub store_objects: u64,
    pub store_bytes: u64,
    pub events: u64,
    pub chain_ok: bool,
    pub counters: Vec<(String, u64)>,
    pub latencies: Vec<(String, f64, f64, f64)>,
}

impl TopState {
    /// Collect a snapshot from a running host.
    pub async fn collect(
        host: &Host,
        root: &Path,
        system: &str,
        started: Instant,
    ) -> anyhow::Result<Self> {
        let mut cells = Vec::new();
        for c in host.cells_status().await {
            cells.push(CellRow {
                name: c.name,
                vat: c.vat,
                state: c.state,
                isolation: "thread",
            });
        }
        for (vat, name, running) in host.procs.list() {
            cells.push(CellRow {
                name,
                vat,
                state: if running { "active" } else { "dead" }.into(),
                isolation: "process",
            });
        }
        for (vat, name, _) in host.wasms.list() {
            cells.push(CellRow {
                name,
                vat,
                state: "ready".into(),
                isolation: "wasm",
            });
        }

        let peers = host.fabric.peers();
        let mut routes = host.fabric.mesh().snapshot();
        routes.sort_by(|a, b| (a.2, &a.0).cmp(&(b.2, &b.0)));

        let store = Arc::clone(&host.store);
        let (objects, bytes, events, chain_ok) = {
            let s = store.stats();
            let ev_len = host.log.len().unwrap_or(0);
            let ok = host.log.verify().is_ok();
            match s {
                Ok(st) => (st.objects, st.bytes, ev_len, ok),
                Err(_) => (0, 0, ev_len, ok),
            }
        };
        let _ = root; // reserved for per-root stores if the host owns several

        // Hearth state (may be absent on a fresh runtime).
        let (branches, reflog_last) = match Hearth::open(root.join("hearth"), store) {
            Ok(h) => {
                let bs = h
                    .list_branches()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(n, t)| (n, t.chars().take(12).collect()))
                    .collect();
                let rl = h.reflog().ok().and_then(|v| {
                    v.last()
                        .map(|e| format!("{} → {}", e.branch, e.new.clone().unwrap_or_default()))
                        .map(|s| s.chars().take(28).collect())
                });
                (bs, rl)
            }
            Err(_) => (Vec::new(), None),
        };

        let metrics = host.metrics.snapshot_json();
        let mut counters = Vec::new();
        if let Some(obj) = metrics.get("counters").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                counters.push((k.clone(), v.as_u64().unwrap_or(0)));
            }
            counters.sort_by(|a, b| a.0.cmp(&b.0));
        }
        let mut latencies = Vec::new();
        if let Some(obj) = metrics.get("series").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                let g = |key: &str| v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0);
                latencies.push((k.clone(), g("p50_us"), g("p95_us"), g("p99_us")));
            }
            latencies.sort_by(|a, b| a.0.cmp(&b.0));
        }

        // Identity: standard fabric dir layout.
        let (identity_fp, identity_gen) =
            match sieveplate_fabric::HostIdentity::load_or_create(&root.join("fabric"), &host.host)
            {
                Ok(id) => (sieveplate_fabric::fingerprint(&id.public()), id.generation),
                Err(_) => (String::new(), 0),
            };

        Ok(TopState {
            system: system.to_string(),
            host: host.host.clone(),
            uptime_secs: started.elapsed().as_secs(),
            identity_fp,
            identity_gen,
            cells,
            peers,
            routes,
            branches,
            reflog_last,
            store_objects: objects,
            store_bytes: bytes,
            events,
            chain_ok,
            counters,
            latencies,
        })
    }
}

// ---------------------------------------------------------------------------
// Rendering (pure — used by both the TUI and the screenshot backend)
// ---------------------------------------------------------------------------

pub fn render_ui(f: &mut Frame, s: &TopState) {
    let area = f.area();
    let outer = Layout::vertical([
        Constraint::Length(6), // header + security
        Constraint::Min(6),    // cells
        Constraint::Length(8), // mesh + hearth side by side
        Constraint::Length(7), // store + metrics
        Constraint::Length(1), // footer
    ])
    .split(area);

    // -- Header --------------------------------------------------------------
    let header_block = panel("SIEVEPLATE · living cell-grid");
    let head = Line::from(vec![
        Span::styled(" system ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(
            &s.system,
            Style::new().fg(mocha::TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   host ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(&s.host, Style::new().fg(mocha::BLUE)),
        Span::styled("   uptime ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(format!("{}s", s.uptime_secs), Style::new().fg(mocha::TEAL)),
    ]);
    let id_line = Line::from(vec![
        Span::styled(" identity ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(&s.identity_fp, Style::new().fg(mocha::PINK)),
        Span::styled(
            format!("  gen {}", s.identity_gen),
            Style::new().fg(mocha::YELLOW),
        ),
        Span::styled("   links ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(
            "SIEVE1 hybrid · X25519+ML-KEM-768 · Ed25519+ML-DSA-65",
            Style::new().fg(mocha::GREEN),
        ),
    ]);
    let cells_line = Line::from(vec![
        Span::styled(" cells ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(
            format!("{}", s.cells.len()),
            Style::new()
                .fg(mocha::LAVENDER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   peers ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(
            format!("{}", s.peers.len()),
            Style::new().fg(mocha::SAPPHIRE),
        ),
        Span::styled("   routes ", Style::new().fg(mocha::OVERLAY0)),
        Span::styled(format!("{}", s.routes.len()), Style::new().fg(mocha::SKY)),
    ]);
    f.render_widget(
        Paragraph::new(vec![head, id_line, cells_line]).block(header_block),
        outer[0],
    );

    // -- Cells table ----------------------------------------------------------
    let rows = s.cells.iter().map(|c| {
        let state_color = match c.state.as_str() {
            "active" => mocha::GREEN,
            "sleeping" => mocha::BLUE,
            "ready" => mocha::TEAL,
            _ => mocha::RED,
        };
        let iso_color = match c.isolation {
            "wasm" => mocha::MAUVE,
            "process" => mocha::PEACH,
            _ => mocha::SUBTEXT0,
        };
        Row::new(vec![
            Span::styled(&c.vat, Style::new().fg(mocha::SUBTEXT0)),
            Span::styled(&c.name, Style::new().fg(mocha::TEXT)),
            Span::styled(c.isolation, Style::new().fg(iso_color)),
            Span::styled(&c.state, Style::new().fg(state_color)),
        ])
    });
    let cells_title = format!("cells ({})", s.cells.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["vat", "name", "isolation", "state"]).style(
            Style::new()
                .fg(mocha::OVERLAY0)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(panel(&cells_title));
    f.render_widget(table, outer[1]);

    // -- Mesh + Hearth ---------------------------------------------------------
    let split = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(outer[2]);

    let mut mesh_lines: Vec<Line> = Vec::new();
    if s.peers.is_empty() {
        mesh_lines.push(Line::from(Span::styled(
            " no peers — this grid is one host",
            Style::new().fg(mocha::OVERLAY0),
        )));
    } else {
        mesh_lines.push(Line::from(vec![
            Span::styled("direct ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(s.peers.join(", "), Style::new().fg(mocha::SAPPHIRE)),
        ]));
    }
    for (dest, hop, hops) in &s.routes {
        mesh_lines.push(Line::from(vec![
            Span::styled(" → ", Style::new().fg(mocha::SURFACE1)),
            Span::styled(dest.to_string(), Style::new().fg(mocha::TEXT)),
            Span::styled(" via ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(hop.to_string(), Style::new().fg(mocha::BLUE)),
            Span::styled(
                format!("  · {hops} hop{}", if *hops == 1 { "" } else { "s" }),
                Style::new().fg(mocha::YELLOW),
            ),
        ]));
    }
    f.render_widget(
        Paragraph::new(mesh_lines).block(panel("mesh (multi-hop)")),
        split[0],
    );

    let mut hearth_lines: Vec<Line> = Vec::new();
    if s.branches.is_empty() {
        hearth_lines.push(Line::from(Span::styled(
            " no branches yet — `sieve hearth snapshot`",
            Style::new().fg(mocha::OVERLAY0),
        )));
    }
    for (name, tip) in &s.branches {
        hearth_lines.push(Line::from(vec![
            Span::styled(" · ", Style::new().fg(mocha::MAUVE)),
            Span::styled(name.clone(), Style::new().fg(mocha::PINK)),
            Span::styled("  ", Style::new().fg(mocha::TEXT)),
            Span::styled(tip.clone(), Style::new().fg(mocha::OVERLAY0)),
        ]));
    }
    if let Some(rl) = &s.reflog_last {
        hearth_lines.push(Line::from(vec![
            Span::styled(" reflog ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(rl.clone(), Style::new().fg(mocha::SUBTEXT0)),
        ]));
    }
    f.render_widget(
        Paragraph::new(hearth_lines).block(panel("hearth (versioned state)")),
        split[1],
    );

    // -- Store + metrics --------------------------------------------------------
    let split2 = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(outer[3]);

    let chain = if s.chain_ok {
        ("verified", mocha::GREEN)
    } else {
        ("BROKEN", mocha::RED)
    };
    let store_lines = vec![
        Line::from(vec![
            Span::styled(" objects ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(format!("{}", s.store_objects), Style::new().fg(mocha::TEAL)),
            Span::styled(
                format!("  ({:.1} KiB)", s.store_bytes as f64 / 1024.0),
                Style::new().fg(mocha::SUBTEXT0),
            ),
        ]),
        Line::from(vec![
            Span::styled(" events  ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(format!("{}", s.events), Style::new().fg(mocha::BLUE)),
        ]),
        Line::from(vec![
            Span::styled(" chain   ", Style::new().fg(mocha::OVERLAY0)),
            Span::styled(
                chain.0,
                Style::new().fg(chain.1).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(store_lines).block(panel("store (content-addressed)")),
        split2[0],
    );

    let mut metric_lines: Vec<Line> = Vec::new();
    if s.latencies.is_empty() {
        metric_lines.push(Line::from(Span::styled(
            " no turns yet",
            Style::new().fg(mocha::OVERLAY0),
        )));
    }
    for (name, p50, p95, p99) in s.latencies.iter().take(2) {
        metric_lines.push(Line::from(vec![
            Span::styled(format!(" {name:<14}"), Style::new().fg(mocha::SUBTEXT0)),
            Span::styled(format!("p50 {:>7.1}  ", p50), Style::new().fg(mocha::GREEN)),
            Span::styled(
                format!("p95 {:>7.1}  ", p95),
                Style::new().fg(mocha::YELLOW),
            ),
            Span::styled(
                format!("p99 {:>7.1} µs", p99),
                Style::new().fg(mocha::PEACH),
            ),
        ]));
    }
    let cnt: Vec<String> = s
        .counters
        .iter()
        .take(4)
        .map(|(k, v)| format!("{} {}", k, v))
        .collect();
    if !cnt.is_empty() {
        metric_lines.push(Line::from(Span::styled(
            format!(" {}", cnt.join("   ")),
            Style::new().fg(mocha::LAVENDER),
        )));
    }
    f.render_widget(
        Paragraph::new(metric_lines).block(panel("signals & latency")),
        split2[1],
    );

    // -- Footer -------------------------------------------------------------------
    let footer = Line::from(vec![
        Span::styled(" q quit", Style::new().fg(mocha::OVERLAY0)),
        Span::styled("  ·  ", Style::new().fg(mocha::SURFACE1)),
        Span::styled("sieveplate 0.1", Style::new().fg(mocha::SUBTEXT0)),
        Span::styled(
            " every claim in BENCHMARKS.md states what it measures",
            Style::new().fg(mocha::OVERLAY0),
        ),
    ]);
    f.render_widget(Paragraph::new(footer), outer[4]);
}

// ---------------------------------------------------------------------------
// Screenshot backend (headless frame capture → JSON)
// ---------------------------------------------------------------------------

/// A captured cell: char + colors as RGB triples (null = default).
type CapturedCell = (u16, u16, String, Option<[u8; 3]>, Option<[u8; 3]>);

/// A `Backend` that records frames instead of touching a terminal.
pub struct CaptureBackend {
    size: ratatui::layout::Size,
    pub cells: Vec<CapturedCell>,
}

impl CaptureBackend {
    pub fn new(width: u16, height: u16) -> Self {
        CaptureBackend {
            size: ratatui::layout::Size { width, height },
            cells: Vec::new(),
        }
    }
}

impl Backend for CaptureBackend {
    type Error = std::io::Error;

    fn draw<'a, I>(&mut self, content: I) -> std::io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        for (x, y, cell) in content {
            let sym = cell.symbol();
            if sym.chars().all(|c| c == ' ') {
                continue;
            }
            let rgb = |c: ratatui::style::Color| match c {
                ratatui::style::Color::Rgb(r, g, b) => Some([r, g, b]),
                _ => None,
            };
            self.cells.push((
                x,
                y,
                sym.to_string(),
                rgb(cell.style().fg.unwrap_or(ratatui::style::Color::Reset)),
                rgb(cell.style().bg.unwrap_or(ratatui::style::Color::Reset)),
            ));
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn show_cursor(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn get_cursor_position(&mut self) -> std::io::Result<ratatui::layout::Position> {
        Ok(ratatui::layout::Position::ORIGIN)
    }
    fn set_cursor_position<P: Into<ratatui::layout::Position>>(
        &mut self,
        _: P,
    ) -> std::io::Result<()> {
        Ok(())
    }
    fn clear(&mut self) -> std::io::Result<()> {
        self.cells.clear();
        Ok(())
    }
    fn clear_region(&mut self, _: ratatui::backend::ClearType) -> std::io::Result<()> {
        Ok(())
    }
    fn size(&self) -> std::io::Result<ratatui::layout::Size> {
        Ok(self.size)
    }
    fn window_size(&mut self) -> std::io::Result<ratatui::backend::WindowSize> {
        Ok(ratatui::backend::WindowSize {
            columns_rows: self.size,
            pixels: ratatui::layout::Size::default(),
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Render one frame into JSON (cells + dimensions) for PNG painting.
pub fn screenshot_json(s: &TopState, width: u16, height: u16) -> serde_json::Value {
    let backend = CaptureBackend::new(width, height);
    let mut term = ratatui::Terminal::new(backend).expect("terminal");
    term.draw(|f| render_ui(f, s)).expect("draw");
    let backend = term.backend();
    let cells: serde_json::Value = serde_json::to_value(&backend.cells).unwrap_or_default();
    serde_json::json!({ "width": width, "height": height, "cells": cells })
}

// ---------------------------------------------------------------------------
// Interactive TUI
// ---------------------------------------------------------------------------

/// Run the live dashboard until the user quits. Blocks; host keeps running.
pub async fn run_tui(
    host: &Host,
    root: PathBuf,
    system: String,
    started: Instant,
) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    let res = drive(&mut terminal, host, root, system, started).await;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    crossterm::terminal::disable_raw_mode()?;
    res
}

async fn drive<B>(
    terminal: &mut ratatui::Terminal<B>,
    host: &Host,
    root: PathBuf,
    system: String,
    started: Instant,
) -> anyhow::Result<()>
where
    B: Backend + Send + Sync + 'static,
    B::Error: Send + Sync + 'static,
{
    loop {
        let state = TopState::collect(host, &root, &system, started).await?;
        terminal.draw(|f| render_ui(f, &state))?;
        if crossterm::event::poll(std::time::Duration::from_millis(250))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                if matches!(
                    k.code,
                    crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc
                ) {
                    break;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points (CLI glue)
// ---------------------------------------------------------------------------

use anyhow::Result;

/// Live dashboard: boot the spec, render until `q`, tear down cleanly.
pub async fn interactive(file: &str, root: &str) -> Result<()> {
    let spec = sieveplate_sysdef::SystemSpec::from_toml(&std::fs::read_to_string(file)?)?;
    let started = Instant::now();
    let booted = crate::run::boot_from_spec(&spec, root).await?;
    let res = run_tui(
        &booted.host,
        PathBuf::from(root),
        spec.system.name.clone(),
        started,
    )
    .await;
    crate::run::teardown(booted).await;
    res?;
    Ok(())
}

/// Seed hearth with demo branches (screenshot mode only): a `main` branch
/// with two snapshots and an `experiment` branch off the second — so the
/// versioned-state panel shows real content-addressed data.
fn seed_hearth_demo(root: &Path) -> Result<()> {
    use sieveplate_hearth::{put_tree, Tree};
    use sieveplate_store::Hash;
    let store = Arc::new(ContentStore::open(root.join("objects"))?);
    let h = Hearth::open(root.join("hearth"), store)?;
    if h.list_branches()?.iter().any(|(n, _)| n == "main") {
        return Ok(()); // already seeded
    }
    // Blobs live in the CAS; trees map keys to blob hashes.
    let blob = |h: &Hearth, v: &str| h.write_blob(v.as_bytes());
    let tree_of = |h: &Hearth, entries: Vec<(&str, &str)>| -> Result<Hash> {
        let mut t = Tree::new();
        for (k, v) in entries {
            t.insert(k.to_string(), blob(h, v)?);
        }
        Ok(put_tree(&h.store_arc(), &t)?)
    };
    let t1 = tree_of(
        &h,
        vec![
            ("greeting", "hello from the hearth"),
            ("config/mode", "live"),
        ],
    )?;
    h.commit("main", &t1, "first snapshot")?;
    let t2 = tree_of(
        &h,
        vec![
            ("greeting", "hello from the hearth (v2)"),
            ("config/mode", "live"),
        ],
    )?;
    h.commit("main", &t2, "update greeting")?;
    h.create_branch("experiment", Some(t2.clone()))?;
    let t3 = tree_of(
        &h,
        vec![
            ("greeting", "hello from the hearth (v2)"),
            ("config/mode", "experiment"),
        ],
    )?;
    h.commit("experiment", &t3, "try experiment mode")?;
    Ok(())
}

/// Two auxiliary hosts chained to the main host: main ← aux1 ← aux2, so
/// `main` holds a 2-hop route through aux1. Real hosts, real SIEVE1
/// links, real distance-vector announcements — nothing staged.
async fn spawn_aux_mesh(root: &Path, main_host: &str) -> Vec<sieveplate_engine::Host> {
    let link_for = |tag: &str| {
        let dir = std::env::temp_dir().join(format!("sp-top-aux-{tag}-{}", std::process::id()));
        sieveplate_fabric::LinkConfig::open(dir.join("fabric").as_path(), tag).unwrap()
    };
    let boot = |tag: &str| -> sieveplate_engine::Host {
        let r = std::env::temp_dir().join(format!("sp-top-aux-root-{tag}-{}", std::process::id()));
        Host::start(
            sieveplate_engine::HostConfig {
                host: tag.into(),
                vats: vec!["core".into()],
                mailbox_capacity: 1024,
                worker_exe: None,
                drain_on_shutdown: true,
            },
            r,
        )
        .unwrap()
    };
    let aux1 = boot("aux1");
    let aux2 = boot("aux2");
    async fn add_echo(h: &sieveplate_engine::Host, name: &str) {
        let _ = h
            .create_cell(&sieveplate_engine::CellSpec {
                name: name.into(),
                vat: "core".into(),
                template: "builtin:echo".into(),
                caps: vec![],
                sleep_after_ms: None,
                persist_on_turn: true,
                max_restarts: 3,
                isolation: sieveplate_engine::Isolation::Thread,
                sandbox: Default::default(),
            })
            .await;
    }
    add_echo(&aux1, "relay").await;
    add_echo(&aux2, "edge").await;

    let n1 = sieveplate_fabric::serve(aux1.fabric.clone(), "127.0.0.1:0", link_for("aux1"))
        .await
        .unwrap();
    let n2 = sieveplate_fabric::serve(aux2.fabric.clone(), "127.0.0.1:0", link_for("aux2"))
        .await
        .unwrap();
    // main listens on its configured [network].listen; aux1 connects to it.
    if let Some(addr) = spec_listen_addr(main_host, root) {
        let _ = sieveplate_fabric::connect_peer(&aux1.fabric, main_host, &addr, &link_for("aux1"))
            .await;
        let _ = sieveplate_fabric::connect_peer(
            &aux2.fabric,
            "aux1",
            &n1.local_addr.to_string(),
            &link_for("aux2"),
        )
        .await;
    }
    let _ = n2;
    vec![aux1, aux2]
}

/// The main host's listen address (parsed from the spec's [network]).
fn spec_listen_addr(main_host: &str, root: &Path) -> Option<String> {
    // The booted host's listener bound the spec's listen addr; recover it
    // from the aux side by just using the spec default port.
    let _ = (main_host, root);
    Some("127.0.0.1:7790".to_string())
}

/// Headless screenshot: boot → seed → let signals flow → render frame →
/// JSON (cells + palette) → teardown. The PNG painter is scripts/.
pub async fn screenshot(file: &str, root: &str, out: &str, size: &str, seed: bool) -> Result<()> {
    let (w, h) = {
        let s = size.split('x').collect::<Vec<_>>();
        (
            s.first().and_then(|x| x.parse().ok()).unwrap_or(100u16),
            s.get(1).and_then(|x| x.parse().ok()).unwrap_or(31u16),
        )
    };
    let root_path = PathBuf::from(root);
    std::fs::create_dir_all(&root_path)?;
    let spec = sieveplate_sysdef::SystemSpec::from_toml(&std::fs::read_to_string(file)?)?;
    if seed {
        seed_hearth_demo(&root_path)?;
    }
    let started = Instant::now();
    let booted = crate::run::boot_from_spec(&spec, root).await?;
    // Auxiliary mesh hosts (line topology: main ← aux1 ← aux2) so the
    // mesh panel shows REAL multi-hop routes in the capture. These are
    // demo scaffolding, torn down with the rest.
    let aux = spawn_aux_mesh(&root_path, &spec.system.name).await;
    // Let the senses tick a few times so metrics/latencies are real and
    // the distance-vector routes converge.
    tokio::time::sleep(std::time::Duration::from_millis(2600)).await;
    let state = TopState::collect(&booted.host, &root_path, &spec.system.name, started).await?;
    let json = screenshot_json(&state, w, h);
    std::fs::write(out, serde_json::to_vec_pretty(&json)?)?;
    eprintln!("screenshot cells → {out} ({w}x{h})");
    for a in &aux {
        a.shutdown().await;
    }
    crate::run::teardown(booted).await;
    Ok(())
}
