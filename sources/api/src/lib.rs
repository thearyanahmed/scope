//! Static VM facts from the firecracker API socket.
//!
//! Write access to this socket is full control of the VM, so the only
//! request this crate can build is `GET` ([`get`] hard-codes the method).
//! Responses are bounded by [`MAX_BODY`] and every socket op has a timeout:
//! the API thread is single-threaded and a wedged VMM must not wedge scope.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use telemetry::{Event, Privilege, Sample, SampleData, Source, SourceError, StopToken, VmId, VmInfo, VmSet, mono_ns};

pub const MAX_BODY: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Status(u16, String),
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Status(c, b) => write!(f, "http {c}: {b}"),
            Error::Protocol(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// `GET <path>` and parse the JSON body.
pub fn get(sock: &Path, path: &str) -> Result<serde_json::Value, Error> {
    if !path.starts_with('/') || path.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
        return Err(Error::Protocol(format!("refusing request path {path:?}")));
    }
    let mut s = UnixStream::connect(sock)?;
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")?;

    let mut r = BufReader::new(s.take(MAX_BODY as u64 + 16 * 1024));
    let mut status = String::new();
    r.read_line(&mut status)?;
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| Error::Protocol(format!("status line {status:?}")))?;

    let mut len = None;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 {
            return Err(Error::Protocol("eof in headers".into()));
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse::<usize>().ok();
        }
    }
    let mut body = vec![];
    match len {
        Some(n) if n > MAX_BODY => return Err(Error::Protocol(format!("body of {n} bytes"))),
        Some(n) => {
            body.resize(n, 0);
            r.read_exact(&mut body)?;
        }
        // 204 and friends carry no body.
        None => {}
    }
    if !(200..300).contains(&code) {
        return Err(Error::Status(code, String::from_utf8_lossy(&body).into_owned()));
    }
    if body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&body).map_err(|e| Error::Protocol(e.to_string()))
}

fn ids(v: &serde_json::Value, list: &str, key: &str) -> Vec<String> {
    v.get(list)
        .and_then(|l| l.as_array())
        .map(|a| a.iter().filter_map(|d| d.get(key)?.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// `GET /` for version and state, `GET /vm/config` for sizes and devices.
/// Older firecrackers without `/vm/config` fall back to `/machine-config`.
pub fn info(sock: &Path) -> Result<VmInfo, Error> {
    let root = get(sock, "/")?;
    let mut i = VmInfo {
        vmm_version: root.get("vmm_version").and_then(|v| v.as_str()).map(str::to_owned),
        state: root.get("state").and_then(|v| v.as_str()).map(str::to_owned),
        ..Default::default()
    };
    let mc = match get(sock, "/vm/config") {
        Ok(cfg) => {
            i.drives = ids(&cfg, "drives", "drive_id");
            i.ifaces = ids(&cfg, "network-interfaces", "iface_id");
            cfg.get("machine-config").cloned().unwrap_or_default()
        }
        Err(_) => get(sock, "/machine-config")?,
    };
    i.vcpu_count = mc.get("vcpu_count").and_then(|v| v.as_u64()).map(|v| v as u32);
    i.mem_size_mib = mc.get("mem_size_mib").and_then(|v| v.as_u64());
    Ok(i)
}

/// Fetches [`VmInfo`] once per VM and again every `refresh` (state changes on
/// InstanceStart, pause/resume). VMs without a reachable socket are retried at the same pace.
#[derive(Debug)]
pub struct Api {
    pub refresh: Duration,
}

impl Default for Api {
    fn default() -> Self {
        Self { refresh: Duration::from_secs(30) }
    }
}

impl Source for Api {
    fn name(&self) -> &'static str {
        "api"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[Privilege::ApiSocket]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        let mut last: BTreeMap<VmId, (u32, Instant)> = BTreeMap::new();
        loop {
            let current = vms.snapshot();
            last.retain(|id, _| current.iter().any(|v| &v.id == id));
            for vm in current {
                let due = last.get(&vm.id).is_none_or(|(pid, t)| *pid != vm.pid || t.elapsed() >= self.refresh);
                let Some(sock) = vm.api_sock.as_deref().filter(|_| due) else { continue };
                last.insert(vm.id.clone(), (vm.pid, Instant::now()));
                if let Ok(i) = info(sock) {
                    let ev = Event::Sample(vm.id, Sample { ts_ns: mono_ns(), data: SampleData::Info(i) });
                    if out.send(ev).is_err() {
                        return Ok(());
                    }
                }
            }
            if !stop.sleep(Duration::from_secs(2)) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Minimal stand-in for firecracker's api server. Records request lines.
    fn serve(
        routes: Vec<(&'static str, u16, &'static str)>,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::thread::JoinHandle<Vec<String>>) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let n = routes.len();
        let h = std::thread::spawn(move || {
            let mut seen = vec![];
            for s in l.incoming().take(n) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                }
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                let (_, code, body) =
                    routes.iter().find(|r| r.0 == path).copied().unwrap_or(("", 404, "{\"fault_message\":\"no\"}"));
                write!(
                    s,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                seen.push(line.trim().to_owned());
            }
            seen
        });
        (dir, sock, h)
    }

    #[test]
    fn info_from_vm_config() {
        let (_d, sock, h) = serve(vec![
            ("/", 200, r#"{"id":"vm1","state":"Running","vmm_version":"1.10.0","app_name":"Firecracker"}"#),
            (
                "/vm/config",
                200,
                r#"{"machine-config":{"vcpu_count":2,"mem_size_mib":1024,"smt":false},"drives":[{"drive_id":"rootfs"}],"network-interfaces":[{"iface_id":"eth0","host_dev_name":"tap0"}]}"#,
            ),
        ]);
        let i = info(&sock).unwrap();
        assert_eq!(i.vmm_version.as_deref(), Some("1.10.0"));
        assert_eq!(i.state.as_deref(), Some("Running"));
        assert_eq!((i.vcpu_count, i.mem_size_mib), (Some(2), Some(1024)));
        assert_eq!(i.drives, ["rootfs"]);
        assert_eq!(i.ifaces, ["eth0"]);
        let seen = h.join().unwrap();
        assert!(seen.iter().all(|l| l.starts_with("GET ")), "{seen:?}");
    }

    #[test]
    fn falls_back_to_machine_config() {
        let (_d, sock, _h) = serve(vec![
            ("/", 200, r#"{"state":"Not started"}"#),
            ("/vm/config", 400, r#"{"fault_message":"Invalid request method"}"#),
            ("/machine-config", 200, r#"{"vcpu_count":1,"mem_size_mib":128}"#),
        ]);
        let i = info(&sock).unwrap();
        assert_eq!(i.vcpu_count, Some(1));
        assert!(i.drives.is_empty());
    }

    #[test]
    fn rejects_injection_and_missing_socket() {
        assert!(matches!(get(Path::new("/x"), "/ HTTP/1.1\r\nX: y"), Err(Error::Protocol(_))));
        assert!(matches!(get(Path::new("/nonexistent/sock"), "/"), Err(Error::Io(_))));
    }
}
