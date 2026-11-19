# shellcheck shell=bash disable=SC2034
# shared settings for lab scripts. source, don't run.
# every rm in lab/ uses ${VAR:?} so an unset variable aborts instead of widening the target.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${SCOPE_LAB_CACHE:-$LAB/.cache}"
ARCH="$(uname -m)"
RUN="${SCOPE_LAB_RUN:-/run/scope-lab}"
JAIL_BASE="${SCOPE_LAB_JAIL:-/srv/jailer}"
FC="$CACHE/firecracker"
JAILER="$CACHE/jailer"
KERNEL="$CACHE/vmlinux"
ROOTFS="$CACHE/rootfs.ext4"
SSH_KEY="$CACHE/id_rsa"

die() { echo "lab: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (taps, jailer, cgroups need it)"; }
need() { command -v "$1" >/dev/null || die "missing tool: $1"; }

# vm i gets tap fc-tap<i> with 172.16.<i>.1/30 on the host and .2 in the guest.
tap_name() { echo "fc-tap$1"; }
host_ip() { echo "172.16.$1.1"; }
guest_ip() { echo "172.16.$1.2"; }
guest_mac() { printf '06:00:ac:10:%02x:02' "$1"; }
vm_id() { echo "lab-$1"; }

# minimal http over the api socket. lab scripts only; scope itself never writes to the api.
fc_api() { # method sock path [json]
    local m=$1 s=$2 p=$3 d=${4:-}
    if [ -n "$d" ]; then
        curl -fsS -X "$m" --unix-socket "$s" -H 'Content-Type: application/json' -d "$d" "http://localhost$p"
    else
        curl -fsS -X "$m" --unix-socket "$s" "http://localhost$p"
    fi
}
