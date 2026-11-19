#!/usr/bin/env bash
# run a workload inside vm i over ssh. usage: load.sh <i> fio|cpu|net [seconds]
#   fio: random 4k read/write, exercises virtio-block emulation (flame test).
#   cpu: stress-ng on all vcpus (top wait/throttle test when the host is overcommitted).
#   net: ping flood to the host tap (exits + tap counters).
source "$(dirname "$0")/common.sh"
i=${1:?vm index}; what=${2:?fio|cpu|net}; secs=${3:-30}
ssh_vm() { ssh -q -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$(guest_ip "$i")" "$@"; }
# the guest has no default route until we add one; package installs need it (and host NAT, see lab/README.md).
install() { ssh_vm "command -v $1 >/dev/null || { ip route add default via $(host_ip "$i") 2>/dev/null; apt-get -qq update && apt-get -qq install -y $1; }"; }
case $what in
    fio) install fio
         ssh_vm "fio --name=r --filename=/root/fio.dat --size=256M --rw=randrw --bs=4k --direct=1 --ioengine=libaio --iodepth=16 --runtime=$secs --time_based --output-format=terse >/dev/null";;
    cpu) install stress-ng
         ssh_vm "stress-ng --cpu 0 --timeout ${secs}s >/dev/null";;
    net) ssh_vm "timeout $secs ping -q -f $(host_ip "$i") >/dev/null || true";;
    *) die "unknown workload $what";;
esac
