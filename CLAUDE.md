# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the WireGuard kernel module for Linux kernels 3.10-5.5, providing a backport of the WireGuard VPN implementation that was later merged into kernel 5.6. The codebase is a Linux kernel module implementing secure VPN tunneling.

## Build Commands

**Basic build:**
```bash
make module
```

**Debug build with verbose output:**
```bash
make module-debug
```

**Clean build artifacts:**
```bash
make clean
```

**Install module:**
```bash
make install
```

**Code style checking:**
```bash
make style
```

**Static analysis:**
```bash
make check
```

**Coccinelle semantic analysis:**
```bash
make coccicheck
```

## Testing Commands

**Local testing (requires root):**
```bash
make test
```

**QEMU-based testing:**
```bash
make test-qemu
```

**Remote testing on configured hosts:**
```bash
make remote-test
```

## Architecture

**Core Components:**
- `main.c` - Module initialization and crypto subsystem setup
- `device.c/h` - WireGuard network device management  
- `peer.c/h` - Peer connection handling and lifecycle
- `noise.c/h` - Noise protocol implementation for cryptographic handshakes
- `send.c/receive.c` - Packet transmission and reception
- `socket.c/h` - UDP socket management
- `allowedips.c/h` - IP routing table for allowed peer addresses

**Crypto Subsystem (`crypto/zinc/`):**
- ChaCha20 stream cipher
- Poly1305 authenticator  
- ChaCha20Poly1305 AEAD
- Curve25519 key exchange
- BLAKE2s hash function
- Architecture-specific optimizations (x86_64, ARM, MIPS)

**Compatibility Layer (`compat/`):**
- Backports newer kernel APIs to older kernels
- Platform-specific implementations
- Network stack compatibility shims

**Build System:**
- `Kbuild` - Kernel build configuration
- `Makefile` - Main build orchestration
- `src/tests/debug.mk` - Development and testing targets
- Module built as `wireguard.ko`

The module integrates with Linux netlink for configuration and implements the WireGuard protocol specification with focus on performance and security.