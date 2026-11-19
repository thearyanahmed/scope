#!/usr/bin/env bash
# snapshot a running non-jailed lab vm, then restore it with memory served over uffd by `scope fault serve`.
# usage:
#   snapshot.sh create <i>               pause + full snapshot into $RUN/snap-<i>/, then stop the vm
#   snapshot.sh restore <i> <uffd.sock>  start a new firecracker and load the snapshot with backend Uffd
# start `scope fault serve --socket <uffd.sock> --mem $RUN/snap-<i>/mem --trace out.sft` before restore.
source "$(dirname "$0")/common.sh"
need_root
cmd=${1:?create|restore}; i=${2:?vm index}; id=$(vm_id "$i"); dir="$RUN/snap-$i"
case $cmd in
create)
    sock="$RUN/$id.sock"; [ -S "$sock" ] || die "$id is not a running non-jailed lab vm"
    mkdir -p "$dir"
    fc_api PATCH "$sock" /vm '{"state":"Paused"}'
    fc_api PUT "$sock" /snapshot/create "{\"snapshot_type\":\"Full\",\"snapshot_path\":\"$dir/vmstate\",\"mem_file_path\":\"$dir/mem\"}"
    # a tap attaches to one process only, so the original must exit before a restore.
    pkill -f -- "--id[= ]$id( |$)" || true
    echo "lab: snapshot of $id in $dir ($(du -h --apparent-size "$dir/mem" | cut -f1) memory)";;
restore)
    uffd=${3:?uffd socket}; [ -S "$uffd" ] || die "no handler listening on $uffd"
    sock="$RUN/$id-restored.sock"
    rm -f "${sock:?}"
    setsid "$FC" --id "$id" --api-sock "$sock" > "$RUN/$id-restored.console" 2>&1 < /dev/null &
    for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
    fc_api PUT "$sock" /snapshot/load "{\"snapshot_path\":\"$dir/vmstate\",\"mem_backend\":{\"backend_type\":\"Uffd\",\"backend_path\":\"$uffd\"},\"resume_vm\":true}"
    echo "lab: restored $id from $dir via $uffd";;
*) die "unknown command $cmd";;
esac
