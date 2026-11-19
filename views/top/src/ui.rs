//! Terminal rendering for `scope top`. Pure: `App::render` draws into any
//! ratatui backend, `App::key` updates state, so both are snapshot-testable.

use crate::{Level, Model, Row};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TRow, Sparkline, Table, TableState};
use telemetry::VmId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Col {
    Id,
    Cpu,
    Guest,
    Vmm,
    Wait,
    Throttle,
    Rss,
    Mem,
    Disk,
    Net,
    Exits,
    Uptime,
}

impl Col {
    const ALL: [Col; 12] = [
        Col::Id,
        Col::Cpu,
        Col::Guest,
        Col::Vmm,
        Col::Wait,
        Col::Throttle,
        Col::Rss,
        Col::Mem,
        Col::Disk,
        Col::Net,
        Col::Exits,
        Col::Uptime,
    ];

    fn title(self) -> &'static str {
        match self {
            Col::Id => "VM",
            Col::Cpu => "CPU%",
            Col::Guest => "GUEST%",
            Col::Vmm => "VMM%",
            Col::Wait => "WAIT%",
            Col::Throttle => "THR%",
            Col::Rss => "RSS",
            Col::Mem => "MEM%",
            Col::Disk => "DISK R/W",
            Col::Net => "NET RX/TX",
            Col::Exits => "EXITS/s",
            Col::Uptime => "UP",
        }
    }

    fn width(self) -> u16 {
        match self {
            Col::Id => 20,
            Col::Disk | Col::Net => 15,
            Col::Uptime => 8,
            _ => 7,
        }
    }

    /// Sort key; missing values sort as smallest.
    fn key(self, r: &Row) -> f64 {
        let f = |v: Option<f64>| v.unwrap_or(-1.0);
        match self {
            Col::Id => 0.0,
            Col::Cpu => f(r.cpu_pct),
            Col::Guest => f(r.guest_pct),
            Col::Vmm => f(r.vmm_pct),
            Col::Wait => f(r.max_wait_pct),
            Col::Throttle => f(r.throttle_pct),
            Col::Rss => r.rss_bytes.map_or(-1.0, |v| v as f64),
            Col::Mem => f(r.mem_pct),
            Col::Disk => f(r.disk_read_bps.zip(r.disk_write_bps).map(|(a, b)| a + b)),
            Col::Net => f(r.net_rx_bps.zip(r.net_tx_bps).map(|(a, b)| a + b)),
            Col::Exits => f(r.exits_per_s),
            Col::Uptime => r.uptime_s.map_or(-1.0, |v| v as f64),
        }
    }

    fn cell(self, r: &Row) -> String {
        match self {
            Col::Id => r.id.clone(),
            Col::Cpu => pct(r.cpu_pct),
            Col::Guest => pct(r.guest_pct),
            Col::Vmm => pct(r.vmm_pct),
            Col::Wait => pct(r.max_wait_pct),
            Col::Throttle => pct(r.throttle_pct),
            Col::Rss => r.rss_bytes.map_or("-".into(), bytes),
            Col::Mem => pct(r.mem_pct),
            Col::Disk => pair(r.disk_read_bps, r.disk_write_bps),
            Col::Net => pair(r.net_rx_bps, r.net_tx_bps),
            Col::Exits => r.exits_per_s.map_or("-".into(), si),
            Col::Uptime => r.uptime_s.map_or("-".into(), dur),
        }
    }
}

pub fn pct(v: Option<f64>) -> String {
    v.map_or("-".into(), |v| format!("{v:.1}"))
}

pub fn bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b}B") } else { format!("{v:.1}{}", U[i]) }
}

fn si(v: f64) -> String {
    match v {
        v if v >= 1e6 => format!("{:.1}M", v / 1e6),
        v if v >= 1e3 => format!("{:.1}k", v / 1e3),
        v => format!("{v:.0}"),
    }
}

fn pair(a: Option<f64>, b: Option<f64>) -> String {
    match (a, b) {
        (Some(a), Some(b)) => format!("{}/{}", bytes(a as u64), bytes(b as u64)),
        _ => "-".into(),
    }
}

pub fn dur(s: u64) -> String {
    match s {
        s if s >= 86400 => format!("{}d{}h", s / 86400, s % 86400 / 3600),
        s if s >= 3600 => format!("{}h{}m", s / 3600, s % 3600 / 60),
        s => format!("{}m{}s", s / 60, s % 60),
    }
}

fn level_style(l: Level) -> Style {
    match l {
        Level::Ok => Style::default(),
        Level::Warn => Style::default().fg(Color::Yellow),
        Level::Crit => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

#[derive(Debug)]
pub struct App {
    pub model: Model,
    pub sort: Col,
    pub desc: bool,
    pub filter: String,
    pub editing_filter: bool,
    pub selected: usize,
    pub detail: Option<VmId>,
    pub now_ms: Option<u64>,
}

impl App {
    pub fn new(model: Model) -> Self {
        Self {
            model,
            sort: Col::Cpu,
            desc: true,
            filter: String::new(),
            editing_filter: false,
            selected: 0,
            detail: None,
            now_ms: None,
        }
    }

    pub fn visible_rows(&self) -> Vec<Row> {
        let mut rows: Vec<Row> = self
            .model
            .rows(self.now_ms)
            .into_iter()
            .filter(|r| self.filter.is_empty() || r.id.contains(&self.filter) || r.pid.to_string() == self.filter)
            .collect();
        if self.sort == Col::Id {
            rows.sort_by(|a, b| a.id.cmp(&b.id));
        } else {
            rows.sort_by(|a, b| self.sort.key(a).total_cmp(&self.sort.key(b)).then_with(|| a.id.cmp(&b.id)));
        }
        if self.desc && self.sort != Col::Id {
            rows.reverse();
        }
        rows
    }

    /// Returns true when the user asked to quit.
    pub fn key(&mut self, k: KeyEvent) -> bool {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            return true;
        }
        if self.editing_filter {
            match k.code {
                KeyCode::Enter | KeyCode::Esc => self.editing_filter = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.selected = 0;
            return false;
        }
        let n = self.visible_rows().len();
        match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc if self.detail.is_some() => self.detail = None,
            KeyCode::Esc if !self.filter.is_empty() => self.filter.clear(),
            KeyCode::Esc => return true,
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(n.saturating_sub(1)),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Char('r') => self.desc = !self.desc,
            KeyCode::Right | KeyCode::Char('>') => self.sort = cycle(self.sort, 1),
            KeyCode::Left | KeyCode::Char('<') => self.sort = cycle(self.sort, Col::ALL.len() - 1),
            KeyCode::Enter => {
                self.detail = self.visible_rows().get(self.selected).map(|r| VmId(r.id.clone()));
            }
            _ => {}
        }
        false
    }

    pub fn render(&self, f: &mut Frame) {
        let [head, body, foot] =
            Layout::vertical([Constraint::Length(2), Constraint::Min(3), Constraint::Length(1)]).areas(f.area());
        f.render_widget(self.header(), head);
        match self.detail.as_ref().and_then(|id| self.model.row(id, self.now_ms).map(|r| (id, r))) {
            Some((id, r)) => self.render_detail(f, body, id, &r),
            None => self.render_table(f, body),
        }
        let help = if self.editing_filter {
            format!("filter: {}▏ (enter to apply)", self.filter)
        } else if self.detail.is_some() {
            "esc back  q quit".into()
        } else {
            format!(
                "↑↓ select  enter detail  / filter{}  ←→ sort ({})  r reverse  q quit",
                if self.filter.is_empty() { String::new() } else { format!(" [{}]", self.filter) },
                self.sort.title()
            )
        };
        f.render_widget(Paragraph::new(help).style(Style::default().add_modifier(Modifier::DIM)), foot);
    }

    fn header(&self) -> Paragraph<'static> {
        let h = self.model.header();
        let ratio = |v: Option<f64>| v.map_or("-".into(), |v| format!("{v:.2}"));
        let l1 = Line::from(vec![
            Span::styled("scope top", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("  {} vms  host cpu {}%  cores {}", h.vm_count, pct(h.host_cpu_pct), h.ncpus)),
        ]);
        let l2 = Line::from(format!(
            "vcpus:cores {}:{} ({})  guest mem:host mem {}:{} ({})  available {}",
            h.vcpus,
            h.ncpus,
            ratio(h.cpu_overcommit),
            bytes(h.guest_mem_bytes),
            bytes(h.host_mem_bytes),
            ratio(h.mem_overcommit),
            bytes(h.host_mem_available),
        ));
        Paragraph::new(vec![l1, l2])
    }

    fn render_table(&self, f: &mut Frame, area: Rect) {
        let rows = self.visible_rows();
        let head = TRow::new(Col::ALL.iter().map(|c| {
            let mut t = c.title().to_owned();
            if *c == self.sort {
                t.push(if self.desc { '▼' } else { '▲' });
            }
            Cell::from(t)
        }))
        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED));
        let body = rows.iter().map(|r| {
            TRow::new(Col::ALL.iter().map(|c| Cell::from(c.cell(r)))).style(level_style(r.level))
        });
        let t = Table::new(body, Col::ALL.iter().map(|c| Constraint::Length(c.width())))
            .header(head)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut st = TableState::default().with_selected((!rows.is_empty()).then_some(self.selected.min(rows.len() - 1)));
        f.render_stateful_widget(t, area, &mut st);
    }

    fn render_detail(&self, f: &mut Frame, area: Rect, id: &VmId, r: &Row) {
        let vcpu_h = r.vcpus.len().max(1) as u16 + 2;
        let [top, sparks, info] = Layout::vertical([
            Constraint::Length(vcpu_h),
            Constraint::Length(6),
            Constraint::Min(3),
        ])
        .areas(area);

        let bar = |run: f64, wait: f64, w: usize| {
            // run fills with '█', wait with '░', rest idle.
            let cells = |p: f64| ((p / 100.0) * w as f64).round().clamp(0.0, w as f64) as usize;
            let (a, b) = (cells(run), cells(wait).min(w - cells(run)));
            vec![
                Span::styled("█".repeat(a), Style::default().fg(Color::Green)),
                Span::styled("░".repeat(b), Style::default().fg(Color::Red)),
                Span::raw("·".repeat(w - a - b)),
            ]
        };
        let lines: Vec<Line> = r
            .vcpus
            .iter()
            .map(|v| {
                let mut s = vec![Span::raw(format!("vcpu{:<3} ", v.index))];
                s.extend(bar(v.run_pct, v.wait_pct, 40));
                s.push(Span::raw(format!(" run {:5.1}%  wait {:5.1}%  guest {:5.1}%", v.run_pct, v.wait_pct, v.guest_pct)));
                Line::from(s)
            })
            .collect();
        let title = format!(" {} (pid {}{}) {} ", r.id, r.pid, if r.jailed { ", jailed" } else { "" }, flags_text(r));
        f.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title).border_style(level_style(r.level))),
            top,
        );

        let [cpu, wait] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(sparks);
        let hist: Vec<_> = self.model.history(id).copied().collect();
        let cpu_d: Vec<u64> = hist.iter().map(|p| p.cpu_pct as u64).collect();
        let wait_d: Vec<u64> = hist.iter().map(|p| (p.wait_pct * 10.0) as u64).collect();
        let tail = |d: &[u64], w: u16| d[d.len().saturating_sub(w as usize)..].to_vec();
        f.render_widget(
            Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title(format!(" cpu% {} ", pct(r.cpu_pct))))
                .data(tail(&cpu_d, cpu.width.saturating_sub(2))),
            cpu,
        );
        f.render_widget(
            Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title(format!(" max vcpu wait% {} ", pct(r.max_wait_pct))))
                .style(Style::default().fg(Color::Red))
                .data(tail(&wait_d, wait.width.saturating_sub(2))),
            wait,
        );

        let mut lines = vec![];
        if let Some(vm) = self.model.vm(id) {
            lines.push(format!("taps     {}", if vm.taps.is_empty() { "-".into() } else { vm.taps.join(", ") }));
            lines.push(format!("api      {}", vm.api_sock.as_ref().map_or("-".into(), |p| p.display().to_string())));
            lines.push(format!("metrics  {}", vm.metrics_path.as_ref().map_or("-".into(), |p| p.display().to_string())));
            lines.push(format!("cgroup   {}", vm.cgroup.as_ref().map_or("-".into(), |p| p.display().to_string())));
        }
        lines.push(format!(
            "memory   rss {}  pss {}  cgroup {} / {}  oom kills {}",
            r.rss_bytes.map_or("-".into(), bytes),
            r.pss_bytes.map_or("-".into(), bytes),
            r.mem_current.map_or("-".into(), bytes),
            r.mem_max.map_or("max".into(), bytes),
            r.oom_kills.map_or("-".into(), |v| v.to_string()),
        ));
        lines.push(format!(
            "cpu      guest {}%  vmm {}%  throttled {}% ({} periods/s)",
            pct(r.guest_pct),
            pct(r.vmm_pct),
            pct(r.throttle_pct),
            pct(r.throttled_per_s),
        ));
        lines.push(format!(
            "io       disk r/w {}  net rx/tx {}  drops/s {}",
            pair(r.disk_read_bps, r.disk_write_bps),
            pair(r.net_rx_bps, r.net_tx_bps),
            pct(r.net_drops_per_s),
        ));
        lines.push(format!(
            "kvm      exits/s {}  halt exits/s {}",
            r.exits_per_s.map_or("-".into(), si),
            r.halt_exits_per_s.map_or("-".into(), si),
        ));
        if let Some(i) = self.model.info(id) {
            lines.push(format!(
                "config   {} vcpus, {} MiB, {} {}  drives [{}]  ifaces [{}]",
                i.vcpu_count.map_or("?".into(), |v| v.to_string()),
                i.mem_size_mib.map_or("?".into(), |v| v.to_string()),
                i.vmm_version.as_deref().unwrap_or("?"),
                i.state.as_deref().unwrap_or(""),
                i.drives.join(", "),
                i.ifaces.join(", "),
            ));
        }
        if let Some(fc) = self.model.firecracker(id) {
            lines.push(format!(
                "fc       {} flushes  rate-limiter throttles {}  seccomp faults {}",
                fc.flushes,
                r.fc_throttle_events.unwrap_or(0),
                fc.gauges.get("seccomp.num_faults").copied().unwrap_or(0),
            ));
        }
        f.render_widget(
            Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>())
                .block(Block::default().borders(Borders::ALL).title(" details ")),
            info,
        );
    }
}

fn flags_text(r: &Row) -> String {
    r.flags.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(" ")
}

fn cycle(c: Col, step: usize) -> Col {
    let i = Col::ALL.iter().position(|x| *x == c).unwrap_or(0);
    Col::ALL[(i + step) % Col::ALL.len()]
}
