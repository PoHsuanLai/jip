# jip

[![CI](https://github.com/PoHsuanLai/jip/actions/workflows/ci.yml/badge.svg)](https://github.com/PoHsuanLai/jip/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/jip-cli.svg)](https://crates.io/crates/jip-cli)
[![License](https://img.shields.io/crates/l/jip-cli.svg)](LICENSE-MIT)

A Linux network diagnostic CLI that answers "what's wrong and why" instead of
dumping raw kernel state.

![jip demo](demo/demo.gif)

## The debugging workflow

```
$ jip                        # something feels off — check the overview
Health: DEGRADED (2 findings)
  - weak wifi signal: -78 dBm on Home_2G
  - DNS: upstream resolver not responding

$ jip check                  # drill down
check: BROKEN
[Dns]  BROKEN  upstream resolver not responding (3/3 timeouts)
               → try: jip reach 1.1.1.1
[Link] warn    weak signal: -78 dBm on Home_2G
               → check: run 'jip wifi' to see nearby networks

$ jip wifi                   # find a better AP
  Home_2G *    ▂▄__ 38%   2.4 GHz  WPA2
  Office_5G    ▂▄▆█ 78%   5 GHz    WPA3

$ jip use "Office_5G"        # switch

$ jip reach github.com       # verify
verdict: REACHABLE  (28ms, V4)
```

## Commands

| Command | What it answers |
|---------|-----------------|
| `jip` | Overview: link state, IPs, gateway health |
| `jip check` | Full diagnosis with findings and remedies |
| `jip reach <host>` | End-to-end path: DNS → gateway → TCP/TLS |
| `jip who` | Active flows with RTT and byte counters |
| `jip listen` | Listening ports, protocols, firewall exposure |
| `jip wifi` | Nearby APs: signal, band, security |
| `jip profiles` | All NetworkManager profiles and active state |
| `jip use <ssid>` | Connect to a network |
| `jip autoconnect <profile> on\|off` | Toggle autoconnect |

Every view supports `--json`, `-4`/`-6`, and `--all`.

## Install

**Prebuilt binary** (recommended):

```sh
curl -Lo jip.tar.gz https://github.com/PoHsuanLai/jip/releases/latest/download/jip-latest-x86_64-unknown-linux-musl.tar.gz
tar -xzf jip.tar.gz && sudo mv jip /usr/local/bin/
```

Replace `x86_64` with `aarch64` for ARM. Use `-gnu` instead of `-musl` if you prefer glibc.

**From crates.io** (requires Rust 1.85+):

```sh
cargo install jip-cli
```

**From source:**

```sh
cargo install --git https://github.com/PoHsuanLai/jip jip-cli
```

**Requirements:**
- Linux, kernel 5.2+
- NetworkManager — required for `wifi`, `profiles`, `use`, `autoconnect`; other commands work without it
- Root or `CAP_NET_ADMIN` — needed for some `jip check` and `jip listen` details; degrades gracefully without it

## License

MIT OR Apache-2.0.
