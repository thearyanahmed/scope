//! `/metrics` endpoint. Blocking, one thread; scrapes are rare and cheap.

use crate::State;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// `:9184` binds loopback only. The output names every VM and device on the
/// host, so exposing it beyond localhost needs an explicit `0.0.0.0:9184`.
pub fn parse_addr(s: &str) -> Result<SocketAddr, String> {
    let full = if s.starts_with(':') { format!("127.0.0.1{s}") } else { s.to_owned() };
    full.parse().map_err(|e| format!("bad listen address {s:?}: {e}"))
}

pub fn spawn(addr: SocketAddr, state: Arc<Mutex<State>>) -> Result<std::thread::JoinHandle<()>, String> {
    let server = tiny_http::Server::http(addr).map_err(|e| format!("listen {addr}: {e}"))?;
    std::thread::Builder::new()
        .name("scope-http".into())
        .spawn(move || {
            for req in server.incoming_requests() {
                let resp = if req.method() == &tiny_http::Method::Get && req.url() == "/metrics" {
                    let body = state.lock().unwrap_or_else(|e| e.into_inner()).render();
                    let ct = tiny_http::Header::from_bytes("Content-Type", "text/plain; version=0.0.4").ok();
                    let r = tiny_http::Response::from_string(body);
                    match ct {
                        Some(h) => r.with_header(h),
                        None => r,
                    }
                } else {
                    tiny_http::Response::from_string("not found\n").with_status_code(404)
                };
                let _ = req.respond(resp);
            }
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn loopback_by_default() {
        assert_eq!(parse_addr(":9184").unwrap().to_string(), "127.0.0.1:9184");
        assert_eq!(parse_addr("0.0.0.0:1").unwrap().to_string(), "0.0.0.0:1");
        assert!(parse_addr("nope").is_err());
    }

    #[test]
    fn serves_metrics() {
        let state = Arc::new(Mutex::new(State::default()));
        state.lock().unwrap().apply(&telemetry::Event::Host(telemetry::HostSample { ncpus: 2, ..Default::default() }));
        // bind to an ephemeral port by probing one first.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        spawn(addr, state).unwrap();
        let get = |path: &str| {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        let ok = get("/metrics");
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("scope_host_cpus 2"));
        assert!(get("/").starts_with("HTTP/1.1 404"));
    }
}
