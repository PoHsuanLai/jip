//! `Path` — the answer to "can I reach X, and if not, where does it die?"
//!
//! A path is the composition of three trait calls: resolve the target,
//! select egress, run probes. [`Diagnostician::trace_path`] assembles one.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::connection::{ConnectionId, Family};
use crate::diag::Finding;
use crate::dns::{DnsError, DnsResolution};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub target: Target,
    /// `None` when the target was given as an IP literal.
    pub resolution: Option<DnsResolution>,
    pub egress: Egress,
    pub probes: ProbeResults,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

/// What the user asked us to reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Target {
    Ip { ip: IpAddr, port: Option<u16> },
    Host { name: String, port: Option<u16> },
    /// Full URL — triggers TLS + HTTP probes.
    Url { url: String },
}

/// Which probes to run for a given target shape. The strategy is a function
/// of the target: LAN IP gets ARP+ping; bare hostname gets DNS+TCP:443; a
/// URL adds TLS+HTTP on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStrategy {
    LanIp,
    IcmpOnly,
    UnspecifiedTcp,
    SpecificPort,
    HttpUrl,
}

/// Which connection carries traffic to the target, as reported by
/// `ip route get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    pub connection_id: ConnectionId,
    pub iface: String,
    pub src: IpAddr,
    pub gateway: Option<IpAddr>,
    pub family_used: Family,
    /// Families for which the kernel said "Network is unreachable" — e.g. V6
    /// on an IPv4-only upstream.
    pub family_unreachable: Vec<Family>,
    /// True when `ip rule` matched on uid; egress may differ for other users
    /// (split-tunnel VPNs commonly do this).
    pub uid_scoped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResults {
    pub strategy: ProbeStrategy,
    /// ICMP to the gateway — cheap, almost always run.
    pub gateway_ping: Option<PingResult>,
    /// ICMP to the target — may be filtered, so not authoritative.
    pub target_ping: Option<PingResult>,
    pub tcp_connect: Option<TcpProbeResult>,
    pub tls_handshake: Option<TlsProbeResult>,
    pub http_head: Option<HttpProbeResult>,
    /// Traceroute. Lazy: only populated on failure or with `--trace`.
    pub trace: Option<Vec<Hop>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingResult {
    pub sent: u32,
    pub received: u32,
    pub rtt_min: Option<Duration>,
    pub rtt_avg: Option<Duration>,
    pub rtt_max: Option<Duration>,
}

impl PingResult {
    pub fn loss_pct(&self) -> f32 {
        if self.sent == 0 {
            return 0.0;
        }
        let lost = self.sent.saturating_sub(self.received);
        (lost as f32 / self.sent as f32) * 100.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpProbeResult {
    pub addr: SocketAddr,
    pub connected: bool,
    pub took: Duration,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsProbeResult {
    pub peer: SocketAddr,
    pub sni: String,
    pub negotiated: bool,
    pub took: Duration,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status: Option<u16>,
    pub took: Duration,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtt: Option<Duration>,
    pub hostname: Option<String>,
}

impl Eq for Hop {}

/// Outcome of a `reach` call. The CLI renders a one-line summary from this,
/// then the `findings` for detail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Verdict {
    Reachable { latency_ms: u64, family_used: Family },
    /// One family worked, the other didn't. Common on dual-stack hosts with
    /// broken IPv6.
    PartiallyReachable { working: Family, broken: Family },
    DnsFailed { error: DnsError },
    /// Kernel has no route to the target.
    NoEgress { reason: String },
    GatewayDown { gateway: IpAddr },
    PacketLoss { loss_pct: f32 },
    /// TCP RST — service up, port closed.
    TcpRefused { addr: SocketAddr },
    /// TCP silence — firewall dropping, or the host is off.
    TcpTimeout { addr: SocketAddr },
    TlsFailed { err: String },
    HttpFailed { status: u16 },
}

impl Eq for Verdict {}
