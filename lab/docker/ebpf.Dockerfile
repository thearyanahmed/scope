# toolchain for building and testing scope's ebpf programs on any docker host.
#   docker build -t scope-ebpf -f lab/docker/ebpf.Dockerfile lab/docker
#   docker run --rm --privileged -v $PWD:/src -w /src scope-ebpf cargo test -p probes
# llvm-sys finds llvm-config on PATH. bpf-linker links against the llvm major version of the nightly rustc that emits the bitcode.
FROM rust:1-bookworm
ARG LLVM=23
RUN apt-get update && apt-get install -y --no-install-recommends lsb-release wget gnupg software-properties-common libzstd-dev \
 && wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh && bash /tmp/llvm.sh ${LLVM} \
 && apt-get install -y --no-install-recommends libpolly-${LLVM}-dev llvm-${LLVM}-dev \
 && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --profile minimal --component rust-src \
 && rustup component add clippy rustfmt \
 && PATH="/usr/lib/llvm-${LLVM}/bin:$PATH" cargo install bpf-linker --no-default-features --features llvm-${LLVM}
