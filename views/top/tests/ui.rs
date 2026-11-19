#![allow(clippy::unwrap_used)]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::path::PathBuf;
use top::Model;
use top::ui::App;

/// fixtures/replay/top.jsonl: two vms, three ticks.
fn app() -> App {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/replay/top.jsonl");
    let mut m = Model::default();
    for ev in replay::read_all(std::fs::File::open(p).unwrap()).unwrap() {
        m.apply(&ev);
    }
    App::new(m)
}

fn screen(app: &App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| app.render(f)).unwrap();
    let buf = t.backend().buffer().clone();
    (0..h)
        .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_owned()).collect::<String>().trim_end().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn key(app: &mut App, c: KeyCode) -> bool {
    app.key(KeyEvent::new(c, KeyModifiers::NONE))
}

#[test]
fn table_sorted_by_cpu() {
    let a = app();
    let s = screen(&a, 160, 8);
    assert!(s.contains("2 vms"), "{s}");
    assert!(s.contains("CPU%▼"), "{s}");
    let busy = s.find("busy").unwrap();
    let idle = s.find("idle").unwrap();
    assert!(busy < idle, "busier vm must sort first:\n{s}");
    assert!(s.contains("150.0"), "{s}");
}

#[test]
fn filter_and_detail() {
    let mut a = app();
    key(&mut a, KeyCode::Char('/'));
    for c in "idl".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.visible_rows().len(), 1);

    key(&mut a, KeyCode::Enter);
    let s = screen(&a, 160, 24);
    assert!(s.contains("idle (pid 20"), "{s}");
    assert!(s.contains("vcpu0"), "{s}");
    assert!(s.contains("taps     tap-idle"), "{s}");

    assert!(!key(&mut a, KeyCode::Esc), "esc leaves detail first");
    assert!(a.detail.is_none());
    assert!(!key(&mut a, KeyCode::Esc), "then clears filter");
    assert!(a.filter.is_empty());
    assert!(key(&mut a, KeyCode::Char('q')));
}

#[test]
fn sort_cycles_and_reverses() {
    let mut a = app();
    key(&mut a, KeyCode::Left);
    assert_eq!(a.sort, top::ui::Col::Id);
    key(&mut a, KeyCode::Right);
    key(&mut a, KeyCode::Char('r'));
    let rows = a.visible_rows();
    assert_eq!(rows[0].id, "idle");
}

#[test]
fn units() {
    use top::ui::{bytes, dur};
    assert_eq!(bytes(512), "512B");
    assert_eq!(bytes(1536), "1.5K");
    assert_eq!(bytes(3 << 30), "3.0G");
    assert_eq!(dur(59), "0m59s");
    assert_eq!(dur(90061), "1d1h");
}
