//! Guest memory as a grid of cells; each cell covers a run of pages and is
//! coloured by the earliest first-touch time inside it.

use telemetry::trace::Trace;

#[derive(Debug, Clone, PartialEq)]
pub struct Heatmap {
    pub cols: usize,
    pub rows: usize,
    pub pages_per_cell: u64,
    /// first touch in ns since t0, per cell; None = never touched.
    pub cells: Vec<Option<u64>>,
    pub max_ns: u64,
}

pub fn build(t: &Trace, cols: usize, rows: usize) -> Heatmap {
    let ps = u64::from(t.header.page_size.max(1));
    let pages = t.header.mem_size().div_ceil(ps).max(1);
    let n = (cols * rows).max(1) as u64;
    let per = pages.div_ceil(n).max(1);
    let cells_used = pages.div_ceil(per) as usize;
    let mut cells = vec![None; cells_used];
    let mut max_ns = 0;
    for e in t.iter() {
        let i = (e.fault.offset / ps / per) as usize;
        if let Some(c) = cells.get_mut(i) {
            *c = Some(c.map_or(e.fault.ts_ns, |v: u64| v.min(e.fault.ts_ns)));
            max_ns = max_ns.max(e.fault.ts_ns);
        }
    }
    Heatmap { cols, rows: cells_used.div_ceil(cols.max(1)), pages_per_cell: per, cells, max_ns }
}

/// 0.0 (first) ..= 1.0 (last touch).
fn frac(h: &Heatmap, ns: u64) -> f64 {
    if h.max_ns == 0 { 0.0 } else { ns as f64 / h.max_ns as f64 }
}

/// viridis-ish ramp, early = dark purple, late = yellow.
fn rgb(f: f64) -> (u8, u8, u8) {
    const STOPS: [(f64, (f64, f64, f64)); 5] = [
        (0.0, (68.0, 1.0, 84.0)),
        (0.25, (59.0, 82.0, 139.0)),
        (0.5, (33.0, 145.0, 140.0)),
        (0.75, (94.0, 201.0, 98.0)),
        (1.0, (253.0, 231.0, 37.0)),
    ];
    let f = f.clamp(0.0, 1.0);
    let i = STOPS.iter().rposition(|s| s.0 <= f).unwrap_or(0).min(STOPS.len() - 2);
    let (a, b) = (STOPS[i], STOPS[i + 1]);
    let t = (f - a.0) / (b.0 - a.0);
    let l = |x: f64, y: f64| (x + (y - x) * t).round() as u8;
    (l(a.1.0, b.1.0), l(a.1.1, b.1.1), l(a.1.2, b.1.2))
}

/// Terminal rendering with 24-bit colour; untouched cells are a dim dot.
pub fn ansi(h: &Heatmap) -> String {
    let mut s = String::new();
    for row in h.cells.chunks(h.cols.max(1)) {
        for c in row {
            match c {
                Some(ns) => {
                    let (r, g, b) = rgb(frac(h, *ns));
                    s.push_str(&format!("\x1b[38;2;{r};{g};{b}m█"));
                }
                None => s.push_str("\x1b[0m\x1b[2m·"),
            }
        }
        s.push_str("\x1b[0m\n");
    }
    s
}

pub fn svg(h: &Heatmap, title: &str) -> String {
    const CELL: usize = 8;
    let (w, ht) = (h.cols * CELL, h.rows * CELL + 24);
    let mut s = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{ht}\" font-family=\"monospace\" font-size=\"12\">\
         <rect width=\"100%\" height=\"100%\" fill=\"#111\"/><text x=\"4\" y=\"16\" fill=\"#ddd\">{}</text>",
        xml_escape(title)
    );
    for (i, c) in h.cells.iter().enumerate() {
        let Some(ns) = c else { continue };
        let (r, g, b) = rgb(frac(h, *ns));
        let (x, y) = (i % h.cols * CELL, i / h.cols * CELL + 24);
        s.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{CELL}\" height=\"{CELL}\" fill=\"rgb({r},{g},{b})\"><title>cell {i}: first touch {:.3} ms</title></rect>", *ns as f64 / 1e6));
    }
    s.push_str("</svg>\n");
    s
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
