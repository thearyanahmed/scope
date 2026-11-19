# lab

Scripts to run real Firecracker VMs for scope's integration tests. Linux + KVM + root.
Tested shape: Ubuntu 24.04 droplet (x86_64, nested KVM). **Not yet run end-to-end; first run is on the droplet.**

```sh
sudo apt-get install -y squashfs-tools e2fsprogs curl jq   # fetch.sh needs these
lab/check-kvm.sh                  # /dev/kvm usable? explains what is missing
lab/fetch.sh                      # firecracker + jailer + CI kernel + ubuntu rootfs into lab/.cache
sudo lab/launch.sh -n 4 -j 2      # 4 vms, 2 under the jailer; prints "<id> <pid> <jailed>"
sudo scope top                    # or: sudo scope top --once --json | jq
lab/load.sh 1 fio 30              # workload in vm 1 (needs guest network, see below)
sudo lab/stop.sh                  # tear everything down
```

| script | does |
|---|---|
| `check-kvm.sh` | `/dev/kvm` exists, is the kvm char device, is read/writable, answers `KVM_GET_API_VERSION`; reports cpu virt flags, kvm module + nested, debugfs, BTF |
| `fetch.sh` | downloads release + CI artifacts (`FC_VERSION=v1.x.y` to pin) |
| `launch.sh` | taps `fc-tap<i>` (172.16.i.1/30), per-vm config file with `metrics_path`, jailer with cgroup v2 `memory.max` for the first `-j` vms |
| `load.sh` | `fio` (virtio-block), `cpu` (stress-ng), `net` (ping flood) over ssh |
| `snapshot.sh` | `create <i>`: pause + full snapshot; `restore <i> <uffd.sock>`: load it with `backend_type: Uffd` |
| `capture-fixture.sh` | copies the /proc + /sys files scope reads into a fixture tree (check cmdlines for secrets before committing) |
| `smoke.sh` | the integration checklist against running lab vms |

Guest packages (`fio`, `stress-ng`) need outbound network: enable forwarding + NAT as in
firecracker's getting-started (`ip_forward=1`, `iptables -t nat -A POSTROUTING -o <host if> -j MASQUERADE`).
lab does not touch iptables on its own.

uffd restore: firecracker creates the userfaultfd. On kernels where `vm.unprivileged_userfaultfd=0`
and firecracker runs without CAP_SYS_PTRACE, it relies on `UFFD_USER_MODE_ONLY` (5.11+).
