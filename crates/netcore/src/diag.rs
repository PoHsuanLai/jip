//! Layer 3 — judgments. A typed vocabulary for health and failure.
//!
//! Every symptom gets tagged with a [`Layer`], so the diagnostician can sort
//! findings by layer and surface the lowest broken one first (fix L1 before
//! worrying about L7).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::connection::ConnectionId;
use crate::dns::DnsResolution;
use crate::link::{L4Proto, Link, Neighbor, Route};
use crate::path::ProbeResults;

/// Where in the stack a finding sits. Ordered roughly bottom-up so sorting by
/// layer surfaces the lowest broken piece first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Link,
    Address,
    Gateway,
    Dns,
    Internet,
    Firewall,
    Service,
}

/// How bad a finding is. Determines exit code and rendering color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational: something to be aware of, but not blocking.
    Info,
    /// Degraded: something is wrong but connectivity may still partially work.
    Warn,
    /// Broken: connectivity is impaired at this layer.
    Broken,
}

/// A single diagnostic observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub layer: Layer,
    pub severity: Severity,
    /// One-line plain English: "gateway 192.168.1.1 not responding to ARP".
    pub summary: String,
    /// Longer explanation with context, if useful.
    pub detail: Option<String>,
    pub remedy: Option<Remedy>,
    pub evidence: Evidence,
}

/// What the user can do about this finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Remedy {
    /// A specific command to try.
    Run { cmd: String },
    /// A physical/environmental thing to verify.
    Check { what: String },
    /// Ask the connection manager to reconnect this connection.
    Reconnect { id: ConnectionId },
    /// The operation requires more privilege than we have.
    ElevatePrivileges,
    /// No remedy suggested.
    None,
}

/// The raw data that led to a finding. Keeps findings self-contained — a
/// caller can always drill down from a finding to the evidence without
/// re-running inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    Link { link: Link },
    Neighbor { neighbor: Neighbor },
    Route { route: Route },
    Dns { dns: DnsResolution },
    Probe { probe: Box<ProbeResults> },
    Text { text: String },
}

/// Overall health summary for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Health {
    Ok,
    Degraded { findings: Vec<Finding> },
    Broken { findings: Vec<Finding> },
}

/// How deep `check()` should probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckScope {
    /// Inventory + gateway L2 + DNS stub up + one ICMP to gateway.
    Quick,
    /// Adds AAAA reachability, TCP:443 to a known public target, and the
    /// firewall posture check.
    Full,
}

/// Firewall verdict for a given inbound (port, proto).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallVerdict {
    Allow,
    Drop,
    Reject,
    /// No explicit rule matched — distinct from allow because a default policy
    /// of DROP leaves this as the "unknown" case.
    NoMatch,
    Unknown,
}

/// Which firewall tool provided the inbound verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    /// nftables via `nft -j list ruleset`.
    Nftables,
    /// iptables via `iptables -L`.
    Iptables,
    /// Neither tool present or accessible.
    Unknown,
}

/// What the reachability backend can actually do on this system.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCapabilities {
    pub has_ping: bool,
    pub has_traceroute: bool,
    pub has_mtr: bool,
    pub has_tracepath: bool,
    /// True when unprivileged ICMP sockets are usable (checked via
    /// `net.ipv4.ping_group_range` or a test probe).
    pub unprivileged_icmp: bool,
}

/// Options for an ICMP echo probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingOpts {
    /// Number of echo requests to send.
    pub count: u32,
    /// Per-packet timeout.
    pub timeout: Duration,
}

impl Default for PingOpts {
    fn default() -> Self {
        Self {
            count: 2,
            timeout: Duration::from_secs(1),
        }
    }
}

/// Options for a traceroute probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOpts {
    /// Maximum TTL before giving up.
    pub max_hops: u8,
    /// How long to wait for each hop to respond.
    pub timeout_per_hop: Duration,
    /// Transport protocol for probes.
    pub proto: L4Proto,
}

impl Default for TraceOpts {
    fn default() -> Self {
        Self {
            max_hops: 20,
            timeout_per_hop: Duration::from_secs(1),
            proto: L4Proto::Udp,
        }
    }
}
