<div align="center">

# ⚡ NetZer

### NETwork analyZER

**A high-performance, zero-copy network packet analyzer for Linux — written in Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](#)
[![Language](https://img.shields.io/badge/language-Rust-red.svg)](#)

</div>

---

## Why NetZer?

Most packet analyzers (including `tcpdump`) rely on `libpcap` — a C library that introduces unnecessary memory copies and limits performance on high-throughput networks.

NetZer takes a different approach:

- **Direct kernel integration** via `AF_PACKET` raw sockets and `TPACKET_V3` ring buffers — no per-packet `recv` syscall
- **Zero-copy, zero-heap parsing** — packet headers are decoded using pointers into the original buffer, with no heap allocations
- **No runtime dependencies** — ships as a single static binary

---

## Features

### 🚀 High-Performance Capture
- `AF_PACKET` + `TPACKET_V3` ring buffer: shared `mmap` between userspace and kernel
- Lock-free producer/consumer pipeline (`crossbeam` / `ringbuf`) — capture thread is never stalled by analysis
- CPU affinity support: pin capture threads to dedicated cores to avoid cache migrations
- *(roadmap)* XDP/eBPF support for line-rate capture at 10+ Gbps

### 🔬 Protocol Analysis
- Zero-copy dissection: **Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP**
- **TCP stream reassembly** — reconstruct full sessions for application-layer analysis (HTTP, DNS...)
- **TLS SNI extraction** — identify destinations without decrypting traffic, straight from the ClientHello
- *(roadmap)* **Passive OS fingerprinting** — identify OS and browsers via TCP fields (TTL, Window Size, options), inspired by `p0f`

### 🎯 Smart Filtering
- **Kernel-level BPF filtering** via `setsockopt(SO_ATTACH_FILTER)` — only matching packets reach userspace
- No CPU waste on irrelevant traffic

### 🔒 Security-First Design
- **Privilege dropping**: NetZer opens the raw socket with `CAP_NET_RAW`, then permanently drops root privileges via `setuid`/`setgid` before any packet processing
- **Memory safety guaranteed by Rust** — no buffer overflows or memory corruption when decoding network headers

### 📤 Output & Integrations
- Structured, colorized terminal output with hex/ASCII payload display
- **`.pcap` export** — captures compatible with Wireshark and any libpcap-based tool
- **JSON / NDJSON streaming export** — pipe directly into ELK, Grafana Loki, or any log pipeline
- **"Follow stream" mode** — reconstruct and display a full TCP session in the terminal, Wireshark-style
- *(roadmap)* **Prometheus metrics endpoint** — real-time stats (packets/sec, bytes/sec, top IPs)
- *(roadmap)* **WASM plugin system** — load custom protocol dissectors at runtime, no recompilation needed

---

## Architecture

NetZer is organized as a Cargo workspace with three focused crates:

```
                        +-----------------------+
                        |      netzer-cli       |  (CLI/TUI interface & output)
                        +-----------+-----------+
                                    |
                        +-----------v-----------+
                        |    netzer-socket      |  (Linux raw sockets & ring buffer)
                        +-----------+-----------+
                                    |
                        +-----------v-----------+
                        |      netzer-core      |  (Zero-copy parsers & TCP reassembly)
                        +-----------------------+
```

| Crate | Responsibility |
|-------|---------------|
| `netzer-core` | Protocol parsers, TCP reassembly, TLS SNI extraction. Takes `&[u8]` slices and returns decoded structs with zero heap allocation. |
| `netzer-socket` | `AF_PACKET` socket lifecycle, `TPACKET_V3` ring buffer setup, BPF filter injection, privilege dropping. |
| `netzer-cli` | Argument parsing (`clap`), colorized output, hex/ASCII formatting, `.pcap` and JSON export. |

---

## Roadmap

### Phase 1 — Raw Capture (`netzer-socket`)
- [ ] Cargo workspace & crate structure
- [ ] `AF_PACKET` socket initialization and binding
- [ ] Socket lifecycle management and Linux error handling
- [ ] Privilege dropping (`setuid`/`setgid`) post-initialization

### Phase 2 — Zero-Copy Parser Engine (`netzer-core`)
- [ ] Binary parsers: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP
- [ ] Unit tests with real packet captures (`.pcap` fixtures)
- [ ] TCP stream reassembly
- [ ] TLS SNI extraction from ClientHello

### Phase 3 — Filtering & CLI (`netzer-cli`)
- [ ] CLI arguments: interface selection, filters, packet count, output format
- [ ] BPF filter integration into the raw socket
- [ ] Colorized console output + hex/ASCII payload view
- [ ] `.pcap` and JSON/NDJSON export

### Phase 4 — Performance & Optimization
- [ ] `TPACKET_V3` ring buffer migration
- [ ] Lock-free producer/consumer pipeline
- [ ] CPU affinity for capture threads
- [ ] Performance benchmarks and type safety audit

### Phase 5 — Ecosystem *(future)*
- [ ] Passive fingerprinting (OS/browser detection)
- [ ] XDP/eBPF support for 10+ Gbps throughput
- [ ] Prometheus metrics endpoint
- [ ] WASM plugin system for custom dissectors

---

## Getting Started

### Requirements

- Linux (kernel ≥ 4.x recommended for `TPACKET_V3`)
- Rust stable (edition 2021+)
- `CAP_NET_RAW` capability or root access to open raw sockets

### Build

```bash
git clone https://github.com/Nehonix-Team/NetZer
cd NetZer
cargo build --release
```

The resulting binary is **fully static with no runtime dependencies**.

### Run

```bash
# Capture on interface eth0
sudo ./target/release/netzer -i eth0

# Capture only TCP traffic on port 443
sudo ./target/release/netzer -i eth0 --filter "tcp port 443"

# Save to pcap for Wireshark analysis
sudo ./target/release/netzer -i eth0 -o capture.pcap

# Stream output as JSON
sudo ./target/release/netzer -i eth0 --format json
```

---

## Contributing

Contributions are welcome! Please open an issue before submitting a PR to discuss the proposed change.

```bash
# Run tests
cargo test --workspace

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --workspace
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ and Rust by the <a href="https://github.com/Nehonix-Team">Nehonix Team</a>
</div>
