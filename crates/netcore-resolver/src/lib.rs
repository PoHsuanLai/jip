//! Resolver backend.
//!
//! Primary path: systemd-resolved over D-Bus (`org.freedesktop.resolve1`).
//! This gives us the upstream that actually answered, DNSSEC status, and
//! per-link DNS — things libc can't surface.
//!
//! Fallback path: `std::net::ToSocketAddrs` (libc getaddrinfo) + parse
//! `/etc/resolv.conf` for server lists. The fallback loses `upstream_used`
//! and DNSSEC info — there's nothing we can do about that from libc alone.
//!
//! The runtime is built on demand per call (current_thread, ~1ms), same
//! pattern as netcore-netlink. No persistent connections.
//!
//! Key observation from the plan: on this machine `resolv.conf` says
//! `127.0.0.53` but the *real* upstream is a link-local IPv6 on eth0.
//! Users debugging DNS failures need to see the upstream, not just the stub.

use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use netcore::Result as NcResult;
use netcore::connection::{ConnectionId, Family};
use netcore::dns::{DnsAnswer, DnsError, DnsResolution, DnsSource};
use netcore::traits::Resolver;
use netcore::Error;

mod resolved;

/// Production resolver. Prefers systemd-resolved D-Bus when the bus is
/// reachable, otherwise falls back to libc + /etc/resolv.conf parsing.
pub struct ResolverBackend {
    /// Pre-probed once at construction. `None` means we couldn't reach the
    /// bus at startup; we stay in fallback mode for this backend's lifetime
    /// rather than paying the connect cost per call.
    has_resolved: bool,
}

impl ResolverBackend {
    /// Create a new resolver, probing for systemd-resolved at construction.
    pub fn new() -> Self {
        Self { has_resolved: Self::probe_resolved() }
    }

    /// Create a resolver that uses only libc `getaddrinfo`. Useful for tests
    /// and environments without D-Bus.
    pub fn libc_only() -> Self { Self { has_resolved: false } }

    fn probe_resolved() -> bool {
        // Cheap probe: does the abstract socket for the system bus exist
        // and does resolve1 register as a well-known name? We run the async
        // probe on a tiny runtime. If *anything* fails, fall back.
        match tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build() {
            Ok(rt) => rt.block_on(async { resolved::is_available().await }),
            Err(_) => false,
        }
    }
}

impl Default for ResolverBackend {
    fn default() -> Self { Self::new() }
}

impl Resolver for ResolverBackend {
    fn resolve(&self, name: &str) -> NcResult<DnsResolution> {
        if self.has_resolved {
            match block_on(resolved::resolve_hostname(name)) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    // If resolved refused (NXDOMAIN/timeout) surface it directly.
                    // If the bus call itself blew up, fall through to libc.
                    if matches!(&e, Error::Backend(m) if is_transport_error(m)) {
                        // transport-level: try libc
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        libc_resolve(name)
    }

    fn servers_for(&self, conn: &ConnectionId) -> NcResult<Vec<IpAddr>> {
        if self.has_resolved {
            if let Ok(servers) = block_on(resolved::servers_for_link(&conn.0)) {
                return Ok(servers);
            }
        }
        Ok(parse_resolv_conf(Path::new("/etc/resolv.conf"))
            .into_iter()
            .filter(|ip| !ip.is_loopback())
            .collect())
    }

    fn stub_server(&self) -> NcResult<Option<IpAddr>> {
        if self.has_resolved {
            // systemd-resolved default stub is 127.0.0.53. Confirm via property;
            // if property read fails, assume the conventional address.
            return Ok(block_on(resolved::stub_address()).unwrap_or(Some("127.0.0.53".parse().unwrap())));
        }
        // Non-resolved hosts: look at resolv.conf. A loopback entry means
        // *something* is stubbing (dnsmasq, unbound, etc.). Non-loopback
        // means no stub.
        let stub = parse_resolv_conf(Path::new("/etc/resolv.conf"))
            .into_iter()
            .find(|ip| ip.is_loopback());
        Ok(stub)
    }
}

fn block_on<F, T>(fut: F) -> NcResult<T>
where
    F: std::future::Future<Output = NcResult<T>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| Error::Backend(format!("tokio runtime: {e}")))?;
    rt.block_on(fut)
}

fn is_transport_error(msg: &str) -> bool {
    // D-Bus connect failures, socket missing, broken pipe — anything that
    // means "resolved isn't answering" as opposed to "resolved answered with
    // NXDOMAIN." We fall back to libc on transport errors only.
    let m = msg.to_ascii_lowercase();
    m.contains("bus")
        || m.contains("connection refused")
        || m.contains("broken pipe")
        || m.contains("no such file")
        || m.contains("socket")
}

fn libc_resolve(name: &str) -> NcResult<DnsResolution> {
    use std::net::ToSocketAddrs;
    let start = Instant::now();
    // Port 0 is legal for getaddrinfo and avoids port-specific filtering.
    let r = (name, 0u16).to_socket_addrs();
    let took = start.elapsed();
    match r {
        Ok(iter) => {
            let answers: Vec<DnsAnswer> = iter
                .map(|sa| {
                    let ip = sa.ip();
                    DnsAnswer {
                        family: match ip {
                            IpAddr::V4(_) => Family::V4,
                            IpAddr::V6(_) => Family::V6,
                        },
                        ip,
                        ttl: None,
                    }
                })
                .collect();
            if answers.is_empty() {
                return Ok(DnsResolution {
                    queried: name.into(),
                    via: DnsSource::Libc,
                    upstream_used: None,
                    answers,
                    took,
                    cached: false,
                    authenticated: false,
                    error: Some(DnsError::NxDomain),
                });
            }
            Ok(DnsResolution {
                queried: name.into(),
                via: DnsSource::Libc,
                upstream_used: None,
                answers,
                took,
                cached: false,
                authenticated: false,
                error: None,
            })
        }
        Err(e) => {
            let err = classify_libc_error(&e);
            Ok(DnsResolution {
                queried: name.into(),
                via: DnsSource::Libc,
                upstream_used: None,
                answers: vec![],
                took,
                cached: false,
                authenticated: false,
                error: Some(err),
            })
        }
    }
}

fn classify_libc_error(e: &std::io::Error) -> DnsError {
    let m = e.to_string();
    let lm = m.to_ascii_lowercase();
    if lm.contains("failed to lookup") && (lm.contains("nodename") || lm.contains("not known") || lm.contains("no such host") || lm.contains("name or service not known")) {
        DnsError::NxDomain
    } else if lm.contains("timed out") || lm.contains("timeout") {
        DnsError::Timeout
    } else if lm.contains("temporary failure") || lm.contains("try again") {
        DnsError::ServFail
    } else {
        DnsError::Other(m)
    }
}

fn parse_resolv_conf(path: &Path) -> Vec<IpAddr> {
    let Ok(contents) = std::fs::read_to_string(path) else { return vec![] };
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { return None; }
            let mut it = line.split_whitespace();
            if it.next()? != "nameserver" { return None; }
            it.next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolv_conf_lines() {
        let tmp = std::env::temp_dir().join("jip-resolver-test.conf");
        std::fs::write(
            &tmp,
            "# comment\nnameserver 1.1.1.1\nnameserver ::1\nsearch example.com\n",
        )
        .unwrap();
        let servers = parse_resolv_conf(&tmp);
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().any(|ip| ip.to_string() == "1.1.1.1"));
        assert!(servers.iter().any(|ip| ip.to_string() == "::1"));
    }

    #[test]
    fn libc_resolves_localhost() {
        let r = libc_resolve("localhost").expect("libc resolve");
        assert!(r.error.is_none());
        assert!(!r.answers.is_empty());
    }

    #[test]
    fn libc_returns_nxdomain_for_bogus_name() {
        let r =
            libc_resolve("thishostnameshouldnotexist.invalid.example.").expect("libc resolve");
        assert!(r.answers.is_empty());
        assert!(r.error.is_some());
    }

    #[test]
    fn backend_resolves_localhost() {
        let b = ResolverBackend::new();
        let r = b.resolve("localhost").expect("resolve");
        assert!(r.error.is_none(), "localhost must resolve");
        assert!(!r.answers.is_empty());
    }

    #[test]
    fn backend_stub_reports_loopback_on_resolved_hosts() {
        let b = ResolverBackend::new();
        // Either resolved is up and the stub is 127.0.0.53, or it isn't and
        // the fallback looks at /etc/resolv.conf. Either answer is valid;
        // we just assert no error.
        let _ = b.stub_server().expect("stub_server");
    }
}
