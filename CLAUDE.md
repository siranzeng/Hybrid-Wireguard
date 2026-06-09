# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust implementation of **Hybrid-WireGuard** and **PQ-WireGuard** from the paper "A Tale of Two Worlds, a Story of WireGuard Hybridization" (USENIX 2025). Four implementations coexist in `src/`:

1. `wireguard/` — Original WireGuard (reference)
2. `wireguard_pq_star/` — Pure post-quantum WireGuard (PQ-WireGuard*)
3. `wireguard_hybrid/` — Hybrid WireGuard V1
4. `wireguard_hybrid_new/` — Hybrid WireGuard V2 with enhanced DoS protection

## Prerequisites

```bash
sh run_install-dep-rust-clang.sh
. "$HOME/.cargo/env"
```

Requires Clang 18.1.3+ and Rust 1.87.0+.

## Commands

```bash
cargo build                           # Debug build (opt-level=2)
cargo build --release                 # Release build
cargo build --features hybrid         # Hybrid mode
cargo build --features post_quantum   # PQ mode

cargo test                            # Run all tests
cargo test <module::path::test_name>  # Run single test

cargo run -- -b 100                   # Benchmarks (100 executions per handshake)
cargo run -- -f                       # Foreground mode
cargo run -- --disable-drop-privileges
```

Feature flags `hybrid` and `post_quantum` are **mutually exclusive** — enforced at compile time in `main.rs`.

## Architecture

### Module structure (repeated across all four implementations)

Each `wireguard*/` module has the same internal layers:

- **`handshake/`** — Noise protocol variant
  - `noise.rs` — Core Noise handshake logic
  - `device.rs` — Handshake state machine (peer indexing, message routing)
  - `peer.rs` — Per-peer handshake state
  - `messages.rs` — Message serialisation/deserialisation
  - `macs.rs` — Cookie reply MACs (DoS mitigation)
  - `ratelimiter.rs` — Handshake rate limiting
  - `crypto_params.rs` — KEM algorithm sizes and parameters (hybrid/PQ variants only)
- **`router/`** — Data-plane (encrypt/decrypt + routing)
  - `device.rs`, `peer.rs`, `send.rs`, `receive.rs`
  - `anti_replay.rs` — Sliding-window replay protection
  - `worker.rs` — Async crypto worker threads
- **`timers.rs`** — hjul timer wheel driving keepalive, rekey, and session expiry
- **`workers.rs`** — TUN reader, UDP handler, and handshake processor thread pools
- **`wireguard.rs`** — Top-level device: owns peers, timers, and thread lifecycle
- **`benchs.rs`** — Handshake benchmarking (construction + processing time, message sizes)

### Platform abstraction (`src/platform/`)

- `tun.rs`, `udp.rs`, `uapi.rs`, `endpoint.rs` — traits
- `linux/` — concrete Linux implementations
- `dummy/` — in-process stubs used by unit tests

### Configuration (`src/configuration*/`)

Separate crate-style modules for each variant (`configuration/`, `configuration_hybrid/`, `configuration_pq_star/`). Each contains a UAPI handler that translates `wg set` commands into device state.

### Entry point (`src/main.rs`)

Parses args, selects implementation via feature flags, initialises platform TUN + UDP, wires up UAPI socket, and launches the device.

### Post-quantum cryptography (via `oqs` crate / liboqs)

- **Ephemeral KEM**: ML-KEM-512 (pubkey 800 B, ciphertext 768 B, secret 32 B)
- **Static KEM**: Classic-McEliece-460896 (pubkey 524 160 B, ciphertext 156 B, secret 32 B)

These sizes drive message layout in `messages.rs` and `crypto_params.rs` for the hybrid/PQ variants.

### Key concurrency patterns

- `crossbeam-channel` for work queues between threads
- `dashmap` for concurrent peer maps
- `parking_lot` mutexes/rwlocks throughout
- `hjul` timer wheel for all protocol timers
- Worker pools: one per role (TUN read, UDP recv, handshake process)
