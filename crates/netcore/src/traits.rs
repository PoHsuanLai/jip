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
    /// Return all kernel-visible network interfaces.
    fn links(&self) -> Result<Vec<Link>>;
    /// Return all addresses, each paired with the ifindex they belong to.
    fn addrs(&self) -> Result<Vec<(u32, Addr)>>;
    /// Return all routing table entries.
    fn routes(&self) -> Result<Vec<Route>>;
    /// Return all ARP/ND neighbor table entries.
    fn neighbors(&self) -> Result<Vec<Neighbor>>;
    /// Return all open sockets (TCP + UDP, IPv4 + IPv6).
    fn sockets(&self) -> Result<Vec<Socket>>;
}

/// Domain-level inventory. Composes primitives into [`Connection`] etc.,
/// applies smart filtering (IPv6 collapse, APIPA, metadata IPs).
pub trait Inventory: Send + Sync {
    /// Return all user-facing network connections.
    fn connections(&self) -> Result<Vec<Connection>>;
    /// Return all listening services.
    fn services(&self) -> Result<Vec<Service>>;
    /// Return all established flows.
    fn flows(&self) -> Result<Vec<Flow>>;
    /// Which [`Egress`] would carry traffic to `dst` — wraps `ip route get`.
    fn egress_for(&self, dst: IpAddr) -> Result<Egress>;
}

/// DNS resolution, per-link resolver discovery.
pub trait Resolver: Send + Sync {
    /// Resolve a hostname or IP string, returning the full resolution record.
    fn resolve(&self, name: &str) -> Result<DnsResolution>;
    /// Per-link resolvers (as reported by `resolvectl`). Falls back to the
    /// stub list when per-link info is unavailable.
    fn servers_for(&self, conn: &ConnectionId) -> Result<Vec<IpAddr>>;
    /// The local stub resolver, typically `127.0.0.53` on systemd-resolved hosts.
    fn stub_server(&self) -> Result<Option<IpAddr>>;
}

/// Active probes: ICMP, TCP connect, TLS handshake, HTTP HEAD, traceroute.
pub trait Reachability: Send + Sync {
    /// Send ICMP echo requests to `ip` according to `opts`.
    fn ping(&self, ip: IpAddr, opts: PingOpts) -> Result<PingResult>;
    /// Attempt a TCP three-way handshake to `sa` within `timeout`.
    fn tcp_connect(&self, sa: SocketAddr, timeout: Duration) -> Result<TcpProbeResult>;
    /// Perform a TLS handshake to `sa` with the given SNI within `timeout`.
    fn tls_handshake(
        &self,
        sa: SocketAddr,
        sni: &str,
        timeout: Duration,
    ) -> Result<TlsProbeResult>;
    /// Issue an HTTP HEAD request to `url` within `timeout`.
    fn http_head(&self, url: &Url, timeout: Duration) -> Result<HttpProbeResult>;
    /// Run a traceroute to `ip` using `opts`.
    fn trace(&self, ip: IpAddr, opts: TraceOpts) -> Result<Vec<Hop>>;
    /// What this backend can actually do on this system.
    fn capabilities(&self) -> ProbeCapabilities;
}

/// Firewall posture.
pub trait Firewall: Send + Sync {
    /// Determine the inbound firewall verdict for a given (port, proto) pair.
    fn verdict_for_inbound(&self, port: u16, proto: L4Proto) -> Result<FirewallVerdict>;
    /// Return which firewall tool this backend read from.
    fn backend(&self) -> FirewallBackend;
}

/// Write operations on connections (requires NetworkManager or similar).
pub trait Actions: Send + Sync {
    /// Activate the connection identified by `id`.
    fn prefer(&self, id: &ConnectionId) -> Result<()>;
    /// Delete the connection profile identified by `id`.
    fn forget(&self, id: &ConnectionId) -> Result<()>;
    /// Deactivate and then reactivate the connection identified by `id`.
    fn reconnect(&self, id: &ConnectionId) -> Result<()>;
    /// Enable or disable autoconnect for the connection identified by `id`.
    fn set_autoconnect(&self, id: &ConnectionId, on: bool) -> Result<()>;
}

/// Orchestrates the others into end-to-end health checks and path probes.
pub trait Diagnostician: Send + Sync {
    /// Run a layered health check at the given scope. Returns an overall
    /// [`Health`] value with any [`Finding`](crate::diag::Finding)s.
    fn check(&self, scope: CheckScope) -> Result<Health>;
    /// Resolve the target, select egress, run probes, and return the full
    /// [`Path`].
    fn trace_path(&self, target: Target) -> Result<Path>;
}
