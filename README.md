# jip

A Linux network CLI that thinks in **connections**, **paths**, and **flows**
instead of netlink families. `jip` with no args answers "is my network
working?". `jip reach <host>` traces a single path end-to-end. `jip who`
shows who is talking to whom, with real byte counters and RTT from the
kernel.

## Install

```sh
cargo install --git https://github.com/PoHsuanLai/jip jip-cli
```

Linux only.

## Common commands

```sh
jip                         # overview + health
jip check                   # full diagnosis
jip reach cloudflare.com    # trace a path
jip reach https://github.com
jip who                     # established flows
jip listen                  # listening services + exposure
jip raw addr|link|route|neigh
```

Every view supports `--json`, `-4`/`-6`, and `--all`.

## License

MIT OR Apache-2.0.
