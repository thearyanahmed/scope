#!/usr/bin/env bash
# copy the /proc and /sys files scope reads for the given pids into a fixture tree.
# usage: capture-fixture.sh <out-dir> <pid>...
# cmdlines are copied verbatim: check them for secrets before committing the fixture.
source "$(dirname "$0")/common.sh"
out=${1:?out dir}; shift
mkdir -p "$out/proc"
cp /proc/stat /proc/meminfo "$out/proc/"
cp_if() { if [ -r "$1" ]; then mkdir -p "$out$(dirname "$1")"; cat "$1" > "$out$1" 2>/dev/null || true; fi; }
for pid in "$@"; do
    p=/proc/$pid
    for f in comm cmdline stat cgroup io smaps_rollup; do cp_if "$p/$f"; done
    for t in "$p"/task/*; do for f in comm stat schedstat; do cp_if "$t/$f"; done; done
    for fd in "$p"/fdinfo/*; do if grep -q '^iff:' "$fd" 2>/dev/null; then cp_if "$fd"; fi; done
    # root/cwd stay symlinks so jail detection sees the same target as on the host.
    ln -sfn "$(readlink "$p/root")" "$out$p/root"; ln -sfn "$(readlink "$p/cwd")" "$out$p/cwd"
    ppid=$(awk '{print $4}' "$p/stat"); cp_if "/proc/$ppid/comm"
    cg=$(sed -n 's/^0:://p' "$p/cgroup")
    for f in cpu.stat cpu.max memory.current memory.max memory.events io.stat; do cp_if "/sys/fs/cgroup$cg/$f"; done
    for tap in $(grep -h '^iff:' "$p"/fdinfo/* 2>/dev/null | awk '{print $2}'); do
        for f in /sys/class/net/"$tap"/statistics/{rx,tx}_{bytes,packets,dropped}; do cp_if "$f"; done
    done
    for d in /sys/kernel/debug/kvm/"$pid"-*; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 2 -type f | while read -r f; do cp_if "$f"; done
    done
done
echo "lab: fixture in $out (kernel $(uname -r), $ARCH)"
