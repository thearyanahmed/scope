//! JSON-lines interchange: line 1 is the header, then one entry per line.
//! For traces from other handlers, and for eyeballing.

use std::io::{BufRead, Write};
use telemetry::trace::{Entry, Header, Trace, Writer};

pub fn export(t: &Trace, mut w: impl Write) -> std::io::Result<()> {
    serde_json::to_writer(&mut w, &t.header)?;
    w.write_all(b"\n")?;
    for e in t.iter() {
        serde_json::to_writer(&mut w, &e)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

pub fn import(r: impl BufRead, w: impl Write) -> Result<u64, String> {
    let mut lines = r.lines();
    let head = lines.next().ok_or("empty input")?.map_err(|e| e.to_string())?;
    let h: Header = serde_json::from_str(&head).map_err(|e| format!("header: {e}"))?;
    let mut tw = Writer::new(w, &h).map_err(|e| e.to_string())?;
    let mut n = 0;
    for (i, l) in lines.enumerate() {
        let l = l.map_err(|e| e.to_string())?;
        if l.trim().is_empty() {
            continue;
        }
        let e: Entry = serde_json::from_str(&l).map_err(|e| format!("line {}: {e}", i + 2))?;
        tw.push(&e).map_err(|e| e.to_string())?;
        n += 1;
    }
    tw.flush().map_err(|e| e.to_string())?;
    Ok(n)
}
