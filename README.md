# scope

Read-only, host-side observability for [Firecracker](https://github.com/firecracker-microvm/firecracker) microVMs.
No guest agent, no Firecracker patches, no orchestrator, no daemon.

| command | answers | needs |
|---|---|---|
| `scope top` | what are the microVMs on this host doing right now? | same uid as the VMs, or root (kvm exit counters: root + debugfs) |
| `scope flame <vm>` | why is this VM, or its VMM, slow? | `CAP_BPF` + `CAP_PERFMON` (root on < 5.8), kernel with BTF |
| `scope fault record <vm>` | which pages does a restored snapshot touch, and how long do vCPUs stall? (someone else's uffd handler) | `CAP_BPF` + `CAP_PERFMON` |
| `scope fault serve` | same, with scope as the uffd handler (dev/perf hosts) | access to the snapshot files; userfaultfd |
| `scope fault show/ws/heatmap/diff` | offline analysis of a fault trace | nothing |

`<vm>` is a firecracker `--id`, `pid-<pid>`, or a pid.

## top

```sh
scope top                         # TUI: ↑↓ select, enter detail, / filter, ←→ sort, r reverse, q quit
scope top --once --json | jq      # one measurement (two samples, one interval apart)
scope top --serve :9184           # Prometheus at 127.0.0.1:9184/metrics (use 0.0.0.0:9184 to expose)
scope top --record s.jsonl        # record events; replay with --replay s.jsonl
```

Per VM: CPU split into guest and VMM time, per-vCPU run and **run-queue wait** (the noisy-neighbour
signal, from `schedstat`), cgroup throttling, RSS/PSS and cgroup memory against `memory.max`, OOM kills,
disk and tap I/O, KVM exits/s. Optional enrichment: Firecracker's own metrics file (rate-limiter
throttles, seccomp faults), and vCPU count / memory size / devices via `GET` on the API socket.

Rows turn amber or red when a threshold is crossed: vCPU wait, throttling, memory near the cgroup limit,
exit storms, OOM kills (`views/top/src/thresholds.rs`).

## flame

```sh
sudo scope flame vm1 --duration 10s             # writes scope-flame-vm1/{vmm,exits}.svg + prints tables
sudo scope flame vm1 --format json > p.json
sudo scope flame vm1 --debug-file firecracker.debug   # release binaries are stripped
```

One recording produces:
1. **VMM flamegraph**: 99 Hz cpu-clock samples of the firecracker process, user and kernel stacks.
2. **Exit profile**: per exit reason, count, time out of guest, p50/p99 (log2 histograms).
   Decoded per arch: VMX/SVM exit codes on x86_64, ESR exception class on arm64.
3. **vCPU timeline**: share of time in guest / in KVM / in Firecracker (device emulation) / off-CPU.

`--guest --vmlinux <path>` adds an *exit-site* profile: the guest PC at each exit, symbolized against
the guest kernel. It is biased toward instructions that cause exits; it is not a guest CPU profile.
It reads guest state, so it is opt-in, prints what it reads, and writes an audit line to syslog.

## fault

```sh
# passive: observe faults while someone else's handler serves them
sudo scope fault record vm1 --trace restore.sft --duration 30s

# scope as the handler: firecracker connects to --socket during PUT /snapshot/load (backend_type Uffd)
scope fault serve --socket /run/uffd.sock --mem snap/mem --trace restore.sft [--prefetch ws.ws]

scope fault show restore.sft                 # faults, working set, resolve p50/p99, total stall
scope fault ws restore.sft --window 2s -o ws.ws
scope fault heatmap restore.sft [--svg h.svg]
scope fault diff a.sft b.sft                 # working-set overlap: is prefetching from a worth it for b?
```

`fault serve` is the only part of scope that affects a VM: if it stops, the guest stalls. It only runs
when an operator points firecracker at it. Trace format: `telemetry/src/trace.rs`.

## Security model

- **Read-only.** scope never sends anything but `GET` to a Firecracker API socket (the request builder
  hard-codes the method), never triggers `FlushMetrics`, and never opens a metrics FIFO unless told
  (`--own-metrics`), because reading a FIFO steals flushes from whoever else is reading it.
- **Inputs from the VMM are untrusted.** A guest escape controls the VMM process, so metrics lines,
  API responses and uffd region lists are size-bounded and validated before use.
- **Network exposure is opt-in.** `--serve :port` binds loopback.
- **Guest data is opt-in.** Only `flame --guest` reads guest state.
- **Sockets scope creates** are mode 0600 (`--chown` for a jailed firecracker), and an existing path is
  never replaced.

## Building

```sh
cargo build --release                        # linux: needs nightly + rust-src + bpf-linker for the eBPF object
cargo build --release --no-default-features  # stable only: top + fault serve/show, no flame / fault record
SCOPE_EBPF_OBJ=scope-probes cargo build --release   # use a prebuilt eBPF object
```

`lab/docker/ebpf.Dockerfile` is a working eBPF toolchain (nightly, LLVM, bpf-linker).
macOS builds everything except the Linux-only sources, so views and parsers can be developed there.

## Layout

```
telemetry/   shared types, fault trace format. no I/O
sources/     host (procfs/cgroup/sysfs), kvm (debugfs), metrics, api, probes (eBPF loader), uffd, replay
ebpf/        kernel-side programs (separate workspace, nightly)
views/       top (ratatui), flame (inferno), fault
export/      Prometheus text, folded stacks
cli/         the `scope` binary
lab/         boot real VMs (with and without jailer), load, snapshot/restore, smoke test
fixtures/    captured and synthetic /proc trees, metrics, tracefs formats, recordings
```

## Testing

- `cargo test --workspace`: parsers against `fixtures/`, views against recorded event streams,
  TUI against ratatui's `TestBackend`.
- Linux, as root: live tests boot a fake firecracker (`sources/host/tests/live.rs`), play firecracker's
  side of the uffd handshake (`sources/uffd/tests`, `cli/tests/fault.rs`), and profile the test process
  with the real eBPF programs (`sources/probes/tests/live.rs`).
- On a KVM host: `sudo lab/smoke.sh` boots VMs and checks every command end to end.

Tested Firecracker versions: none yet end to end. todo: record the two pinned minor versions here after `lab/smoke.sh` passes.

## License

Apache-2.0. The eBPF programs and `probe-abi` are `Apache-2.0 OR GPL-2.0-only`; the object declares GPL to the kernel.
