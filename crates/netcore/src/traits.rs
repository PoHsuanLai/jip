//! Layer 4 — capability traits.
//!
//! Backends implement the subset they can. The CLI holds them as trait
//! objects (`Box<dyn Trait>`) so NetworkManager, netlink, or shell-out
//! backends can be selected at runtime based on what's available.
//!
//! All traits are object-safe: no generics on methods, no `Self` returns,
//! no async (we stay sync for a sub-100ms CLI).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::Result;
use crate::connection::{Connection, ConnectionId};
use crate::diag::{
    CheckScope, FirewallBackend, FirewallVerdict, Health, PingOpts, ProbeCapabilities, TraceOpts,
};
use crate::dns::DnsResolution;
use crate::link::{Addr, L4Proto, Link, Neighbor, Route, Socket};
use crate::path::{
    Egress, Hop, HttpProbeResult, Path, PingResult, Target, TcpProbeResult, TlsProbeResult,
};
use crate::service::{Flow, Service};

/// Raw kernel-primitive inventory. Backends implementing this expose
/// unfiltered data for `jip raw *`.
pub trait InventoryRaw: Send + Sync {
    fn links(&self) -> Result<Vec<Link>>;
    /// Addresses paired with the ifindex they belong to.
    fn addrs(&self) -> Result<Vec<(u32, Addr)>>;
    fn routes(&self) -> Result<Vec<Route>>;
    fn neighbors(&self) -> Result<Vec<Neighbor>>;
    fn sockets(&self) -> Result<Vec<Socket>>;
}

/// Domain-level inventory. Composes primitives into [`Connection`] etc.,
/// applies smart filtering (IPv6 collapse, APIPA, metadata IPs).
pub trait Inventory: Send + Sync {
    fn connections(&self) -> Result<Vec<Connection>>;
    fn services(&self) -> Result<Vec<Service>>;
    fn flows(&self) -> Result<Vec<Flow>>;
    /// Which [`Egress`] would carry traffic to `dst` — wraps `ip route get`.
    fn egress_for(&self, dst: IpAddr) -> Result<Egress>;
}

/// DNS resolution, per-link resolver discovery.
pub trait Resolver: Send + Sync {
    fn resolve(&self, name: &str) -> Result<DnsResolution>;
    /// Per-link resolvers (as reported by `resolvectl`). Falls back to the
    /// stub list when per-link info is unavailable.
    fn servers_for(&self, conn: &ConnectionId) -> Result<Vec<IpAddr>>;
    /// The local stub resolver, typically `127.0.0.53` on systemd-resolved hosts.
    fn stub_server(&self) -> Result<Option<IpAddr>>;
}

/// Active probes: ICMP, TCP connect, TLS handshake, HTTP HEAD, traceroute.
pub trait Reachability: Send + Sync {
    fn ping(&self, ip: IpAddr, opts: PingOpts) -> Result<PingResult>;
    fn tcp_connect(&self, sa: SocketAddr, timeout: Duration) -> Result<TcpProbeResult>;
    fn tls_handshake(
        &self,
        sa: SocketAddr,
        sni: &str,
        timeout: Duration,
    ) -> Result<TlsProbeResult>;
    fn http_head(&self, url: &Url, timeout: Duration) -> Result<HttpProbeResult>;
    fn trace(&self, ip: IpAddr, opts: TraceOpts) -> Result<Vec<Hop>>;
    /// What this backend can actually do on this system.
    fn capabilities(&self) -> ProbeCapabilities;
}

/// Firewall posture.
pub trait Firewall: Send + Sync {
    fn verdict_for_inbound(&self, port: u16, proto: L4Proto) -> Result<FirewallVerdict>;
    fn backend(&self) -> FirewallBackend;
}

/// Write operations on connections (requires NetworkManager or similar).
pub trait Actions: Send + Sync {
    fn prefer(&self, id: &ConnectionId) -> Result<()>;
    fn forget(&self, id: &ConnectionId) -> Result<()>;
    fn reconnect(&self, id: &ConnectionId) -> Result<()>;
    fn set_autoconnect(&self, id: &ConnectionId, on: bool) -> Result<()>;
}

/// Orchestrates the others into end-to-end health checks and path probes.
pub trait Diagnostician: Send + Sync {
    fn check(&self, scope: CheckScope) -> Result<Health>;
    fn trace_path(&self, target: Target) -> Result<Path>;
}
