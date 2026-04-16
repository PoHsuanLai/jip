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

/// End-to-end path probe result: target resolution, egress selection, probe
/// outcomes, and the final verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    /// The target that was probed.
    pub target: Target,
    /// `None` when the target was given as an IP literal.
    pub resolution: Option<DnsResolution>,
    /// Which interface and source address carry traffic to the target.
    pub egress: Egress,
    /// All probe results collected for this path.
    pub probes: ProbeResults,
    /// The overall reachability verdict.
    pub verdict: Verdict,
    /// Diagnostic findings produced while tracing the path.
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
    /// The connection that owns the egress interface.
    pub connection_id: ConnectionId,
    /// Kernel interface name (e.g. `"eth0"`).
    pub iface: String,
    /// Preferred source address selected by the kernel.
    pub src: IpAddr,
    /// Next-hop gateway, when the destination is not directly connected.
    pub gateway: Option<IpAddr>,
    /// Address family used for the route lookup.
    pub family_used: Family,
    /// Families for which the kernel said "Network is unreachable" — e.g. V6
    /// on an IPv4-only upstream.
    pub family_unreachable: Vec<Family>,
    /// True when `ip rule` matched on uid; egress may differ for other users
    /// (split-tunnel VPNs commonly do this).
    pub uid_scoped: bool,
}

/// All probe results collected for a single path trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResults {
    /// Which probe strategy was selected for this target.
    pub strategy: ProbeStrategy,
    /// ICMP to the gateway — cheap, almost always run.
    pub gateway_ping: Option<PingResult>,
    /// ICMP to the target — may be filtered, so not authoritative.
    pub target_ping: Option<PingResult>,
    /// TCP connect probe result.
    pub tcp_connect: Option<TcpProbeResult>,
    /// TLS handshake probe result.
    pub tls_handshake: Option<TlsProbeResult>,
    /// HTTP HEAD probe result.
    pub http_head: Option<HttpProbeResult>,
    /// Traceroute. Lazy: only populated on failure or with `--trace`.
    pub trace: Option<Vec<Hop>>,
}

/// Result of an ICMP echo probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingResult {
    /// Number of echo requests sent.
    pub sent: u32,
    /// Number of echo replies received.
    pub received: u32,
    pub rtt_min: Option<Duration>,
    pub rtt_avg: Option<Duration>,
    pub rtt_max: Option<Duration>,
}

impl PingResult {
    /// Compute packet loss as a percentage (0.0–100.0).
    pub fn loss_pct(&self) -> f32 {
        if self.sent == 0 {
            return 0.0;
        }
        let lost = self.sent.saturating_sub(self.received);
        (lost as f32 / self.sent as f32) * 100.0
    }
}

/// Result of a TCP connect probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpProbeResult {
    /// The target socket address.
    pub addr: SocketAddr,
    /// Whether the three-way handshake completed.
    pub connected: bool,
    /// Time from start to connection or failure.
    pub took: Duration,
    /// Human-readable error string when `connected` is false.
    pub error: Option<String>,
}

/// Result of a TLS handshake probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsProbeResult {
    /// The target socket address.
    pub peer: SocketAddr,
    /// The SNI hostname presented.
    pub sni: String,
    /// Whether the handshake completed with a valid certificate chain.
    pub negotiated: bool,
    /// Time from start to handshake completion or failure.
    pub took: Duration,
    /// Human-readable error string when `negotiated` is false.
    pub error: Option<String>,
}

/// Result of an HTTP HEAD probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbeResult {
    /// The URL that was probed.
    pub url: String,
    /// HTTP response status code, when a response was received.
    pub status: Option<u16>,
    /// Time from request start to response or failure.
    pub took: Duration,
    /// Human-readable error string on failure.
    pub error: Option<String>,
}

/// A single traceroute hop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    /// TTL value for this hop.
    pub ttl: u8,
    /// IP address of the responding router, `None` on timeout.
    pub ip: Option<IpAddr>,
    /// Round-trip time to this hop, `None` on timeout.
    pub rtt: Option<Duration>,
    /// Reverse-DNS hostname, when available.
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
