#!/usr/bin/env bash
# kill every lab vm and remove the taps, jails, run dir and cgroups lab created.
source "$(dirname "$0")/common.sh"
need_root
pkill -f -- "--id[= ]lab-[0-9]+" || true
sleep 0.5
for t in $(ip -o link show | grep -oE 'fc-tap[0-9]+' | sort -u); do ip link del "$t" 2>/dev/null || true; done
# `if` rather than `[ ] &&`: a false test as the loop's last command would trip set -e.
for j in "${JAIL_BASE:?}"/firecracker/lab-*; do if [ -d "$j" ]; then rm -rf "${j:?}"; fi; done
rm -rf "${RUN:?}"
for c in /sys/fs/cgroup/firecracker/lab-*; do if [ -d "$c" ]; then rmdir "$c" 2>/dev/null || true; fi; done
echo "lab: stopped"
