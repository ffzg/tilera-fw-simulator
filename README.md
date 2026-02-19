# MikroTik Tilera Firewall Simulator

A Python-based simulator for MikroTik RouterOS firewall configurations (specifically tested against CCR1036/Tilera exports). This tool allows you to trace packet flow through Filter and NAT tables, validate rules against real-world logs, and debug complex stateful configurations.

## Features

- **Multi-Table Support**: Simulates `filter`, `nat`, and `mangle` tables.
- **Full Chain Logic**: Correctly models `input`, `output`, `forward`, `prerouting`, `postrouting`, `dstnat`, and `srcnat` chains.
- **Stateful Tracking (Conntrack)**: Maintains a connection table with $O(1)$ lookups to handle `established` and `related` traffic.
- **Automatic NAT**: Handles `src-nat`, `dst-nat`, `masquerade`, `redirect`, and `reverse-nat` for reply packets.
- **Smart Interface Detection**: Automatically determines `in-interface` and `out-interface` by parsing `/ip address` and `/ip route` sections.
- **Address List Integration**: Supports built-in address lists and external list files (e.g., `tilera.address-list.2`).
- **Protocol Support**: Deep matching for `tcp`, `udp`, and `icmp/icmpv6` (including type/code matching).
- **Mangle Support**: Support for `mark-packet`, `mark-connection`, and `mark-routing` actions.
- **Verification Tool**: Batch-test the simulator against `drop.log` to ensure parity with real hardware.

## Installation

```bash
# No external dependencies required (uses standard library)
git clone <repo-url>
cd tilera-fw-simulator
```

## Usage

### Single Packet Trace
```bash
python3 simulate_firewall.py --src 10.60.0.92 --dst 8.8.8.8 --proto udp --dport 53
```

### Advanced Debugging
```bash
python3 simulate_firewall.py --src 193.198.212.229 --dst 193.198.212.1 --proto tcp --dport 8291 --verbose
```

### Log Verification
```bash
python3 verify_simulator.py --limit 500
```

## Project Status & Roadmap

### Current Status: **STABLE (IPv4 & IPv6)**
Verified **100% parity** against the first 500 IPv4 entries of production `drop.log`.
Supports dual-stack configurations with full IPv6 firewall and Mangle table simulation.

### Completed Tasks
- [x] Single-pass RSC configuration parsing.
- [x] $O(1)$ Connection Tracking (Conntrack).
- [x] Filter, NAT, and Mangle table simulation.
- [x] Automatic Interface/Route lookups.
- [x] Response testing by default.
- [x] Untruncated rule output for better debugging.
- [x] **IPv6 Support**: Full dual-stack simulation.
- [x] **Mangle Table**: Implementation of `/ip firewall mangle` and routing marks.
- [x] **Advanced Matchers**: `content`, `tcp-flags`, and `packet-size`.

### Upcoming Tasks
- [ ] **Interactive Mode**: A "What-If" shell for real-time packet tracing.
- [ ] **Layer 2 Simulation**: Basic support for `/interface bridge filter`.

## License
MIT
