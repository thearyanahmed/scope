#!/usr/bin/env bash
# is this host able to run firecracker? checks /dev/kvm and explains what is missing.
# usage: lab/check-kvm.sh        exit 0 = usable, 1 = not
source "$(dirname "$0")/common.sh"

fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=1; }
hint() { echo "       $*"; }

echo "== /dev/kvm ($ARCH, kernel $(uname -r))"

if [ ! -e /dev/kvm ]; then
    bad "/dev/kvm does not exist"
    # work out why: no hardware virt exposed, or kvm modules not loaded.
    case $ARCH in
    x86_64)
        if grep -qwE 'vmx|svm' /proc/cpuinfo; then
            hint "cpu advertises $(grep -owE 'vmx|svm' /proc/cpuinfo | head -1), so the kvm module is probably not loaded:"
            hint "  sudo modprobe kvm_intel   # or kvm_amd"
        else
            hint "cpu has no vmx/svm flag: hardware virtualization is not exposed to this machine."
            hint "on a cloud vm that means nested virtualization is off for this instance type."
        fi;;
    aarch64)
        hint "arm64 kvm needs the kernel booted at EL2 (bare metal or a host with nested virt)."
        [ -d /sys/module/kvm ] || hint "kvm module not present: sudo modprobe kvm";;
    esac
    exit 1
fi

# kvm is a misc device: character, major 10, minor 232.
if [ -c /dev/kvm ]; then
    # stat prints major/minor in hex; bash printf converts without needing gawk.
    IFS=: read -r maj min < <(stat -c '%t:%T' /dev/kvm)
    dev=$(printf '%d:%d' "0x$maj" "0x$min")
    if [ "$dev" = 10:232 ]; then ok "/dev/kvm is the kvm device (10:232)"; else bad "/dev/kvm is device $dev, not kvm (10:232)"; fi
else
    bad "/dev/kvm exists but is not a character device"
fi

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "read/write access as $(id -un)"
else
    bad "no read/write access as $(id -un) (owner $(stat -c '%U:%G %a' /dev/kvm))"
    hint "add yourself to its group: sudo usermod -aG $(stat -c '%G' /dev/kvm) $(id -un)  (then log in again)"
fi

# the node can exist without working (e.g. a container without the device cgroup rule),
# so open it and ask for the api version. KVM_GET_API_VERSION = _IO(0xAE, 0) and is always 12.
if [ "$fail" = 0 ]; then
    if command -v python3 >/dev/null; then
        ver=$(python3 -I -c '
import os, fcntl
try:
    fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    print(fcntl.ioctl(fd, 0xAE00))
except OSError as e:
    print(e.strerror)
' 2>&1) || true
        if [ "$ver" = 12 ]; then
            ok "KVM_GET_API_VERSION = 12"
        else
            bad "opening /dev/kvm failed: $ver"
        fi
    else
        hint "python3 not found; skipped the open + ioctl check"
    fi
fi

echo "== related"
for m in kvm_intel kvm_amd kvm; do
    if [ -d "/sys/module/$m" ]; then
        nested=$(cat "/sys/module/$m/parameters/nested" 2>/dev/null || echo n/a)
        ok "module $m loaded (nested: $nested)"
        break
    fi
done
# scope top reads per-vm exit counters from here; optional.
if [ -d /sys/kernel/debug/kvm ]; then ok "kvm debugfs present (scope top exit counters)"; else hint "kvm debugfs not readable (root + debugfs mounted): scope top runs without exit counters"; fi
# scope flame needs btf for its ebpf programs; optional for top/fault serve.
if [ -f /sys/kernel/btf/vmlinux ]; then ok "kernel btf present (scope flame, fault record)"; else hint "no /sys/kernel/btf/vmlinux: scope flame and fault record will not load"; fi

echo
if [ "$fail" = 0 ]; then echo "check-kvm: this host can run firecracker"; else echo "check-kvm: not usable yet"; fi
exit "$fail"
