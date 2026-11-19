#!/usr/bin/env python3
"""regenerates top.jsonl: two synthetic vms ("busy", "idle") over three 1 s ticks.

busy burns 1.5 cores with one vcpu waiting 30% of the time; idle does nothing.
"""
import json, sys

S = 1_000_000_000

def vm(id, pid, tap):
    return {"vm": {"appeared": {
        "id": id, "pid": pid, "jailed": True, "root": f"/proc/{pid}/root",
        "api_sock": f"/proc/{pid}/root/run/firecracker.socket", "metrics_path": None, "config_file": None,
        "vcpus": [{"index": 0, "tid": pid + 2}, {"index": 1, "tid": pid + 3}],
        "threads": [{"tid": pid, "name": "firecracker", "kind": "vmm"}, {"tid": pid + 1, "name": "fc_api", "kind": "api"}],
        "taps": [tap], "cgroup": f"/sys/fs/cgroup/firecracker/{id}", "started_ms": 0}}}

def vcpu(i, tid, run, wait):
    return {"index": i, "tid": tid, "cpu": {"user_ns": run, "system_ns": 0, "guest_ns": run * 8 // 10},
            "sched": {"run_ns": run, "wait_ns": wait, "timeslices": 0}}

def proc(id, pid, tap, t, busy):
    k = t if busy else 0
    return {"sample": [id, {"ts_ns": t * S, "data": {"proc": {
        "cpu": {"user_ns": k * 1_200_000_000, "system_ns": k * 300_000_000, "guest_ns": k * 1_200_000_000},
        "vcpus": [vcpu(0, pid + 2, k * 900_000_000, k * 50_000_000), vcpu(1, pid + 3, k * 600_000_000, k * 300_000_000)],
        "threads": [],
        "mem": {"rss_bytes": (1 << 30) if busy else (128 << 20), "pss_bytes": (1 << 30) if busy else (128 << 20)},
        "io": {"rchar": 0, "wchar": 0, "syscr": 0, "syscw": 0, "read_bytes": k * 4096, "write_bytes": k * 1 << 20},
        "net": [{"name": tap, "rx_bytes": k * 100, "tx_bytes": k * 1000, "rx_packets": 0, "tx_packets": 0, "rx_dropped": 0, "tx_dropped": 0}],
        "cgroup": None}}}]}

def host(t):
    return {"host": {"ts_ns": t * S, "ncpus": 4, "busy_ns": t * 2 * S, "idle_ns": t * 2 * S,
                     "mem_total_bytes": 4 << 30, "mem_available_bytes": 2 << 30}}

out = [vm("busy", 10, "tap-busy"), vm("idle", 20, "tap-idle")]
for t in (1, 2, 3):
    out += [proc("busy", 10, "tap-busy", t, True), proc("idle", 20, "tap-idle", t, False), host(t)]
sys.stdout.write("".join(json.dumps(e) + "\n" for e in out))
