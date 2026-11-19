#!/usr/bin/env bash
# boot N vms. usage: launch.sh [-n N] [-j JAILED] [-c VCPUS] [-m MIB] [--shared-ro]
#   -j: how many of the N run under the jailer (default: half).
#   --shared-ro: one read-only rootfs for all vms instead of a sparse copy each (for large N).
# prints "<id> <pid> <jailed>" per vm.
source "$(dirname "$0")/common.sh"
need_root; need ip; need curl
N=3; N_JAILED=-1; VCPUS=2; MEM=256; SHARED=0
while [ $# -gt 0 ]; do case $1 in
    -n) N=$2; shift 2;; -j) N_JAILED=$2; shift 2;; -c) VCPUS=$2; shift 2;; -m) MEM=$2; shift 2;;
    --shared-ro) SHARED=1; shift;; *) die "unknown arg $1";; esac; done
[ "$N_JAILED" -lt 0 ] && N_JAILED=$(( N / 2 ))
[ -x "$FC" ] || die "run lab/fetch.sh first"
"$LAB/check-kvm.sh" >/dev/null || die "no usable /dev/kvm; run lab/check-kvm.sh for details"
mkdir -p "$RUN"
# jailer puts each vm in /sys/fs/cgroup/firecracker/<id>; controllers must be delegated down to it.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "+cpu +memory +io" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    mkdir -p /sys/fs/cgroup/firecracker
    echo "+cpu +memory +io" > /sys/fs/cgroup/firecracker/cgroup.subtree_control 2>/dev/null || true
fi

config() { # i kernel rootfs metrics ro
    local i=$1
    cat <<JSON
{
  "boot-source": {"kernel_image_path": "$2",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=$(guest_ip "$i")::$(host_ip "$i"):255.255.255.252::eth0:off"},
  "drives": [{"drive_id": "rootfs", "path_on_host": "$3", "is_root_device": true, "is_read_only": $5}],
  "network-interfaces": [{"iface_id": "eth0", "guest_mac": "$(guest_mac "$i")", "host_dev_name": "$(tap_name "$i")"}],
  "machine-config": {"vcpu_count": $VCPUS, "mem_size_mib": $MEM},
  "metrics": {"metrics_path": "$4"}
}
JSON
}

for i in $(seq 1 "$N"); do
    id=$(vm_id "$i"); tap=$(tap_name "$i")
    ip link show "$tap" >/dev/null 2>&1 || { ip tuntap add dev "$tap" mode tap; ip addr add "$(host_ip "$i")/30" dev "$tap"; }
    ip link set "$tap" up
    ro=false; disk="$RUN/$id.ext4"
    if [ "$SHARED" = 1 ]; then ro=true; disk="$ROOTFS"; else [ -f "$disk" ] || cp --sparse=always "$ROOTFS" "$disk"; fi

    if [ "$i" -le "$N_JAILED" ]; then
        jail="$JAIL_BASE/firecracker/$id/root"
        mkdir -p "$jail"
        ln -f "$KERNEL" "$jail/vmlinux" 2>/dev/null || cp "$KERNEL" "$jail/vmlinux"
        ln -f "$disk" "$jail/rootfs.ext4" 2>/dev/null || cp --sparse=always "$disk" "$jail/rootfs.ext4"
        : > "$jail/metrics.json"
        config "$i" /vmlinux /rootfs.ext4 /metrics.json "$ro" > "$jail/config.json"
        chown -R 1000:1000 "$jail"
        "$JAILER" --id "$id" --exec-file "$FC" --uid 1000 --gid 1000 --chroot-base-dir "$JAIL_BASE" \
            --cgroup-version 2 --cgroup "memory.max=$(( (MEM + 128) << 20 ))" --daemonize \
            -- --config-file /config.json --api-sock /run/firecracker.socket
    else
        : > "$RUN/$id.metrics"
        config "$i" "$KERNEL" "$disk" "$RUN/$id.metrics" "$ro" > "$RUN/$id.json"
        rm -f "${RUN:?}/${id:?}.sock"
        setsid "$FC" --id "$id" --api-sock "$RUN/$id.sock" --config-file "$RUN/$id.json" \
            > "$RUN/$id.console" 2>&1 < /dev/null &
    fi
done

# wait for each vm's vcpu threads, then report.
for i in $(seq 1 "$N"); do
    id=$(vm_id "$i"); pid=""
    for _ in $(seq 50); do
        pid=$(pgrep -f -- "--id[= ]$id( |$)" | head -1 || true)
        if [ -n "$pid" ] && grep -qs fc_vcpu /proc/"$pid"/task/*/comm; then break; fi
        sleep 0.1
    done
    [ -n "$pid" ] || die "$id did not start (see $RUN/$id.console)"
    echo "$id $pid $([ "$i" -le "$N_JAILED" ] && echo true || echo false)"
done
