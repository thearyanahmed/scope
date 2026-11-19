#!/usr/bin/env bash
# end-to-end checklist on a kvm host. boots lab vms, runs every scope command
# against them, checks the plan's "done when" criteria, tears down.
# usage: sudo lab/smoke.sh [path/to/scope]    (default: target/release/scope)
# needs: lab/fetch.sh done, jq, curl; guest network (NAT) for the fio step.
source "$(dirname "$0")/common.sh"
need_root; need jq; need curl
SCOPE=${1:-$LAB/../target/release/scope}
[ -x "$SCOPE" ] || die "build scope first: cargo build --release"
OUT=$(mktemp -d /tmp/scope-smoke.XXXXXX)
pass=0; fail=0
ok() { echo "  ok   $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
cleanup() { "$LAB/stop.sh" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$LAB/check-kvm.sh" || die "host cannot run firecracker"

echo "== boot: 4 vms, 2 jailed"
"$LAB/stop.sh" >/dev/null 2>&1 || true
"$LAB/launch.sh" -n 4 -j 2 | tee "$OUT/vms.txt"
sleep 3

echo "== top"
start=$(date +%s%N)
"$SCOPE" top --once --json > "$OUT/top.json"
ms=$(( ($(date +%s%N) - start) / 1000000 ))
lab_vms() { jq '[.vms[] | select(.id | startswith("lab-"))]' "$OUT/top.json"; }
check "discovers 4 lab vms" test "$(lab_vms | jq length)" = 4
check "2 are jailed" test "$(lab_vms | jq '[.[] | select(.jailed)] | length')" = 2
check "every vm has 2 vcpus" test "$(lab_vms | jq '[.[] | select(.vcpu_count == 2)] | length')" = 4
check "cpu rates measured" test "$(lab_vms | jq '[.[] | select(.cpu_pct != null)] | length')" = 4
check "jailed vms report cgroup memory" test "$(lab_vms | jq '[.[] | select(.jailed and .mem_max != null)] | length')" = 2
check "taps found" test "$(lab_vms | jq '[.[] | select(.net_rx_bps != null)] | length')" = 4
check "kvm exit counters" test "$(lab_vms | jq '[.[] | select(.exits_per_s != null)] | length')" = 4
echo "  info top --once took ${ms}ms (includes one 1s interval)"

echo "== top cpu overhead at 1s refresh (target < 2% of one core)"
"$SCOPE" top --json > /dev/null &
tp=$!
sleep 2; t0=$(awk '{print $14 + $15}' "/proc/$tp/stat"); sleep 10; t1=$(awk '{print $14 + $15}' "/proc/$tp/stat")
kill "$tp"; wait "$tp" 2>/dev/null || true
pct=$(( (t1 - t0) * 100 / (10 * $(getconf CLK_TCK)) ))
check "top uses < 2% cpu (${pct}%)" test "$pct" -lt 2

echo "== prometheus"
"$SCOPE" top --serve :19184 & sp=$!
sleep 3
curl -fsS localhost:19184/metrics > "$OUT/metrics.txt" || true
kill "$sp"; wait "$sp" 2>/dev/null || true
check "scope_vm_info for lab vms" test "$(grep -c 'scope_vm_info{vm="lab-' "$OUT/metrics.txt")" = 4
check "vcpu wait exported" grep -q scope_vcpu_wait_seconds_total "$OUT/metrics.txt"

echo "== flame under fio (vm 3, non-jailed)"
"$LAB/load.sh" 3 fio 20 & lp=$!
sleep 3
"$SCOPE" flame lab-3 --duration 10s -o "$OUT/flame" | tee "$OUT/flame.txt" || true
wait "$lp" || echo "  info fio failed (guest network?), flame ran on an idle vm"
check "vmm flamegraph" test -s "$OUT/flame/vmm.svg"
check "exit profile" test -s "$OUT/flame/exits.svg"
check "io/mmio exits present" grep -qE 'IO_INSTRUCTION|EPT_MISCONFIG|EPT_VIOLATION|DABT_LOW' "$OUT/flame.txt"
check "virtio block in vmm graph" grep -qi 'block' "$OUT/flame/vmm.svg"

echo "== fault: snapshot vm 4, restore twice under fault serve"
"$LAB/snapshot.sh" create 4
for n in 1 2; do
    sock="$OUT/uffd-$n.sock"
    "$SCOPE" fault serve --socket "$sock" --mem "$RUN/snap-4/mem" --trace "$OUT/restore-$n.sft" & hp=$!
    for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
    "$LAB/snapshot.sh" restore 4 "$sock"
    sleep 5
    pkill -f -- "--id[= ]lab-4( |$)" || true
    wait "$hp" || true
done
check "trace recorded" test -s "$OUT/restore-1.sft"
"$SCOPE" fault show "$OUT/restore-1.sft" --json > "$OUT/fault.json" || true
check "working set << guest memory" test "$(jq '.touched_pct < 50' "$OUT/fault.json")" = true
"$SCOPE" fault diff "$OUT/restore-1.sft" "$OUT/restore-2.sft" --json > "$OUT/diff.json" || true
check "two restores overlap > 90%" test "$(jq '.jaccard_pct > 90' "$OUT/diff.json")" = true

echo
echo "smoke: $pass passed, $fail failed. artifacts in $OUT"
[ "$fail" -eq 0 ]
