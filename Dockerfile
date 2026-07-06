# Vulnagent Sandbox Image — QEMU multi-arch + security toolchain
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    qemu-system-arm qemu-system-mips qemu-system-x86 \
    binutils-multiarch \
    gcc-arm-linux-gnueabi gcc-mipsel-linux-gnu \
    binwalk squashfs-tools \
    lz4 xz-utils zstd bzip2 gzip cpio \
    python3 python3-pip \
    curl wget netcat-openbsd \
    xxd file strings \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN useradd -m -s /bin/bash vulnagent
USER vulnagent
