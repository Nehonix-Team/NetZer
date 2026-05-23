# NetZer

**NETwork analyZER**

A high-performance, zero-copy network packet analyzer for Linux, written in Rust.

## Overview

Most packet analyzers rely on `libpcap`, a library that introduces memory copies and can limit performance on high-throughput networks. NetZer takes a different approach by focusing on direct kernel integration and minimizing overhead:

- **Direct kernel integration**: Uses `AF_PACKET` raw sockets and `TPACKET_V3` ring buffers to avoid per-packet `recv` system calls.
- **Zero-copy, zero-heap parsing**: Packet headers are decoded using pointers into the original buffer without heap allocations.
- **No runtime dependencies**: Designed to be shipped as a single static binary.

## Core Features

- **High-Performance Capture**: Leverages a shared `mmap` between userspace and the kernel, along with a lock-free producer/consumer pipeline, ensuring the capture thread is not stalled by analysis. CPU affinity support prevents cache migrations.
- **Protocol Analysis**: Performs zero-copy dissection for Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP. Capable of TCP stream reassembly for application-layer analysis and TLS SNI extraction to identify destinations without decryption.
- **Smart Filtering**: Applies kernel-level BPF filtering via `setsockopt(SO_ATTACH_FILTER)` to ensure only matching packets reach userspace, reducing CPU waste.
- **Security-First Design**: Operates by opening the raw socket with `CAP_NET_RAW` and permanently dropping root privileges via `setuid`/`setgid` before packet processing. Rust's memory safety prevents buffer overflows during header decoding.
- **Data Export & Integration**: Offers structured terminal output, `.pcap` export compatible with standard analysis tools, and JSON/NDJSON streaming export for integration into external logging pipelines.

## Architecture

NetZer is organized as a modular Cargo workspace consisting of three primary crates:

1. **`netzer-core`**: Responsible for protocol parsers, TCP reassembly, and TLS SNI extraction. It processes byte slices and returns decoded structures with zero heap allocation.
2. **`netzer-socket`**: Manages the `AF_PACKET` socket lifecycle, `TPACKET_V3` ring buffer setup, BPF filter injection, and the privilege dropping sequence.
3. **`netzer-cli`**: Handles the command-line interface, argument parsing, terminal formatting, and file export functionalities.

## License

This project is licensed under the MIT License.