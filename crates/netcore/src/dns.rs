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

/// Result of a single DNS resolution attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolution {
    /// The name that was queried.
    pub queried: String,
    /// Which resolver path was used.
    pub via: DnsSource,
    /// Upstream the stub forwarded to, if known (parsed from `resolvectl`).
    pub upstream_used: Option<IpAddr>,
    /// Answers returned for the query.
    pub answers: Vec<DnsAnswer>,
    /// How long the resolution took.
    pub took: Duration,
    /// True when the answer was served from the resolver's cache.
    pub cached: bool,
    /// True when the answer was DNSSEC-validated.
    pub authenticated: bool,
    /// Set when the resolver returned an error instead of answers.
    pub error: Option<DnsError>,
}

/// Which DNS resolver path was used to answer the query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "addr", rename_all = "snake_case")]
pub enum DnsSource {
    /// systemd-resolved or dnsmasq listening on loopback.
    Stub(IpAddr),
    /// A non-loopback resolver was queried directly.
    Direct(IpAddr),
    /// Multicast DNS / .local.
    Mdns,
    /// Libc `getaddrinfo`; the answering server is not known.
    Libc,
}

/// A single DNS A or AAAA record returned by a resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    /// The resolved IP address.
    pub ip: IpAddr,
    /// Address family of `ip`.
    pub family: Family,
    /// Time-to-live in seconds, when reported by the resolver.
    pub ttl: Option<u32>,
}

/// A DNS resolution error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsError {
    /// The name does not exist (`NXDOMAIN`).
    NxDomain,
    /// The server encountered an internal error (`SERVFAIL`).
    ServFail,
    /// The resolver did not respond within the deadline.
    Timeout,
    /// Name syntactically invalid or resolver refused.
    Other(String),
}
