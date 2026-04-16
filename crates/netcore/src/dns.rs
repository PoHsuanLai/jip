//! DNS resolution results.
//!
//! The stub-vs-upstream distinction matters. `/etc/resolv.conf` on this
//! machine says `127.0.0.53` but the real server answering queries is
//! `fe80::dead:beef:feed:cafe%eth0`. Users debugging DNS failures want to
//! see which server actually answered, not just "the stub."

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::connection::Family;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolution {
    pub queried: String,
    pub via: DnsSource,
    /// Upstream the stub forwarded to, if known (parsed from `resolvectl`).
    pub upstream_used: Option<IpAddr>,
    pub answers: Vec<DnsAnswer>,
    pub took: Duration,
    pub cached: bool,
    /// DNSSEC validated.
    pub authenticated: bool,
    pub error: Option<DnsError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsSource {
    /// systemd-resolved or dnsmasq listening on loopback.
    Stub(IpAddr),
    /// A non-loopback resolver was queried directly.
    Direct(IpAddr),
    /// Multicast DNS / .local.
    Mdns,
    /// Libc getaddrinfo; we don't know which server answered.
    Libc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub ip: IpAddr,
    pub family: Family,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsError {
    NxDomain,
    ServFail,
    Timeout,
    /// Name syntactically invalid or resolver refused.
    Other(String),
}
