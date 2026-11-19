# fixtures

| path | what | origin |
|---|---|---|
| `host/two-vms/` | `/proc` + `/sys` subset: one plain firecracker (pid 1000), one jailed (pid 2000) with cgroup v2, taps, kvm debugfs | hand-written to the kernel formats; replace with `lab/capture-fixture.sh` output from a real host |
| `metrics/v1.flush.jsonl` | two firecracker metrics flushes | synthetic, field names checked against firecracker `src/vmm/src/logger/metrics.rs` (main, 2026-11) |
| `replay/top.jsonl` | recorded `Event` stream for `top` view tests | `replay/gen_top.py` |

Synthetic fixtures are marked here so nobody mistakes them for captured data.
todo: capture x86_64 and arm64 trees and two firecracker versions' metrics from `lab/`.
