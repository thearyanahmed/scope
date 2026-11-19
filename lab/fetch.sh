#!/usr/bin/env bash
# download firecracker + jailer, a CI guest kernel and an ubuntu rootfs into lab/.cache.
# follows firecracker docs/getting-started.md. FC_VERSION=v1.x.y pins a release.
source "$(dirname "$0")/common.sh"
need curl; need unsquashfs; need mkfs.ext4; need ssh-keygen
mkdir -p "$CACHE"; cd "$CACHE" || exit 1

release_url="https://github.com/firecracker-microvm/firecracker/releases"
ver="${FC_VERSION:-$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$release_url/latest")")}"
if [ ! -x "$FC" ] || ! "$FC" --version | grep -q "${ver#v}"; then
    echo "lab: firecracker $ver"
    curl -fsSL "$release_url/download/$ver/firecracker-$ver-$ARCH.tgz" | tar -xz
    rel="release-$ver-$ARCH"
    mv "$rel/firecracker-$ver-$ARCH" "$FC"
    mv "$rel/jailer-$ver-$ARCH" "$JAILER"
    # debug info for scope flame --debug-file, when the release ships it.
    if [ -f "$rel/firecracker-$ver-$ARCH.debug" ]; then mv "$rel/firecracker-$ver-$ARCH.debug" "$CACHE/firecracker.debug"; fi
    rm -rf "${CACHE:?}/${rel:?}"
fi

S3="https://s3.amazonaws.com/spec.ccfc.min"
prefix=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oE '<Prefix>firecracker-ci/v[0-9]+\.[0-9]+/</Prefix>' | sed -E 's/<\/?Prefix>//g' | sort -V | tail -1)
[ -n "$prefix" ] || die "could not list CI artifacts"

if [ ! -f "$KERNEL" ]; then
    key=$(curl -fsSL "$S3?list-type=2&prefix=${prefix}${ARCH}/vmlinux-" \
        | grep -oE "<Key>${prefix}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3}</Key>" | sed -E 's/<\/?Key>//g' | sort -V | tail -1)
    echo "lab: kernel $key"
    curl -fsSL -o "$KERNEL" "$S3/$key"
fi

if [ ! -f "$ROOTFS" ]; then
    key=$(curl -fsSL "$S3?list-type=2&prefix=${prefix}${ARCH}/ubuntu-" \
        | grep -oE "<Key>${prefix}${ARCH}/ubuntu-[0-9]+\.[0-9]+\.squashfs</Key>" | sed -E 's/<\/?Key>//g' | sort -V | tail -1)
    echo "lab: rootfs $key"
    curl -fsSL -o rootfs.squashfs "$S3/$key"
    rm -rf "${CACHE:?}/squashfs-root"
    unsquashfs -q rootfs.squashfs
    [ -f "$SSH_KEY" ] || ssh-keygen -q -f "$SSH_KEY" -N ""
    mkdir -p squashfs-root/root/.ssh
    cp "$SSH_KEY.pub" squashfs-root/root/.ssh/authorized_keys
    # fio and stress-ng are installed on demand by lab/load.sh; keep the image stock.
    truncate -s 1G "$ROOTFS"
    mkfs.ext4 -q -d squashfs-root -F "$ROOTFS"
    rm -rf "${CACHE:?}/squashfs-root" "${CACHE:?}/rootfs.squashfs"
fi
echo "lab: ready in $CACHE ($("$FC" --version | head -1))"
