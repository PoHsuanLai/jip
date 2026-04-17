# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build -p jip-cli                        # build the CLI
cargo build --release -p jip-cli             # release build
cargo test --workspace                        # all tests
cargo test -p <crate> <test_name>            # single test
cargo clippy --workspace --all-targets        # lint
cargo fmt --all -- --check                    # format check
cargo install --path jip-cli                  # install locally
```

Integration tests that require root (nftables live kernel):
```bash
sudo cargo test -p nftables-netlink --features integration
```

## Architecture

**jip** is a Linux network CLI structured as a Cargo workspace. The crates form a strict dependency DAG — nothing outside `netcore` is imported by multiple crates:

```
jip-cli
├── netcore-diag       (diagnostic orchestration)
├── netcore-netlink    (kernel inventory via rtnetlink + sock_diag)
├── netcore-firewall   (nftables verdict via netlink)
│   └── nftables-netlink  (NETLINK_NETFILTER codec, pure Rust, no C FFI)
├── netcore-nm         (NetworkManager D-Bus actions)
├── netcore-probe      (ICMP / TCP / TLS / HTTP / traceroute probes)
├── netcore-resolver   (DNS via systemd-resolved, fallback to libc)
└── netcore            (domain types + capability traits — imported by all)
```

### Four conceptual layers in `netcore`

| Layer | Types | Seen by user |
|---|---|---|
| Kernel primitives | `Link`, `Addr`, `Route`, `Neighbor`, `Socket` | `jip raw *` |
| Domain concepts | `Connection`, `Service`, `Flow`, `Path` | `jip`, `jip listen`, `jip who` |
| Diagnostic judgments | `Finding`, `Health`, `Layer` | `jip check`, `jip reach` |
| Capability traits | `Inventory`, `Firewall`, `Resolver`, `Reachability`, `Diagnostician` | (internal) |

All capability traits in `netcore::traits` are **object-safe** — no generics on methods, no `Self` returns, no async. Backends are held as `Box<dyn Trait>` and composed in `DiagApp`.

### Key backend patterns

**No persistent runtimes.** Every backend (`netcore-netlink`, `netcore-nm`, `netcore-resolver`) builds a `tokio::runtime::current_thread` per call. `netcore-probe` is fully synchronous (no tokio at all). This keeps latency predictable for a CLI.

**Graceful degradation everywhere.** When a backend is unavailable (NM not on bus, `CAP_NET_ADMIN` missing, resolved unreachable), the system degrades silently rather than failing. Verdicts/findings surface this as `Unknown` or `Unavailable` states.

**netcore-netlink** uses `rtnetlink` for links/addresses/routes/neighbours and `NETLINK_SOCK_DIAG` for socket enumeration. Process ownership is resolved by walking `/proc/*/fd/*` to match socket inodes to PIDs. `EPERM` on a `/proc/<pid>/fd` directory is preserved as `ProcessInfo::PermissionDenied` (not hidden).

**nftables-netlink** is a custom pure-Rust `NETLINK_NETFILTER` codec (no `nft` binary, no `libnftnl` C FFI). The `recv` loop pattern is `sock.recv(&mut &mut buf[..], 0)` — the double-ref is required so `bytes::BufMut` overwrites from index 0 rather than appending to the `Vec`. See `sockdiag.rs` for the canonical template.

**netcore-firewall** reads the nftables ruleset once at `NftBackend::new()` and caches it. It only evaluates input-hooked chains and matches `tcp dport` / `udp dport` via the kernel's register model (three chained expressions: `meta l4proto` → `payload transport dport` → `cmp ==`).

### Render / theme system

`jip-cli/src/theme.rs` gates between **Pretty** (tabled, ANSI, headers) and **Plain** (tab-separated, no headers, no color) based on TTY detection. JSON output (`--json`) bypasses theme entirely for byte-for-byte stability.

All render modules follow the same structure: build a `Vec<[String; N]>`, apply `theme::paint()` inside cells, then either print tab-separated rows (plain) or build a `tabled` table with `TabColor::BOLD | TabColor::UNDERLINE` headers.

Color semantics are consistent: `ok`/`ok_soft` = green, `warn` = yellow, `bad` = red+bold, `dim` = secondary/placeholders, `info` = cyan, `accent`/`accent2` = tcp/udp proto labels.

### Testing

Unit tests are inline (`#[cfg(test)]` in each module). `netcore-diag` has fixture-driven integration tests using `netcore::fixture::Fixture` — an in-memory snapshot backend that implements all capability traits. Build test scenarios by constructing a `Fixture` and running `DiagApp` against it; no kernel access needed.

`nftables-netlink` codec tests (`codec::attr::tests`) work on raw byte slices with no kernel access. Live fixture binaries (captured from a root machine) go in `crates/nftables-netlink/tests/fixtures/` which is `.gitignore`d — never commit binary kernel captures.
