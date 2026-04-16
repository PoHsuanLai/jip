//! Listening services and active flows.
//!
//! `Service` describes a listening socket plus its effective exposure to the
//! outside world, computed from the bind scope and the firewall posture.
//! `Flow` is an established connection.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::diag::FirewallVerdict;
use crate::link::{L4Proto, TcpState};
use crate::process::ProcessInfo;

/// Something listening for inbound connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub proto: L4Proto,
    pub bind: BindScope,
    pub process: ProcessInfo,
    /// Effective reachability, computed by joining [`BindScope`] with the
    /// firewall's inbound verdict for (port, proto).
    pub exposure: Exposure,
}

/// Where a listening socket is bound.
///
/// A Linux `[::]:22` listener accepts IPv4 connections as well unless the
/// `net.ipv6.bindv6only` sysctl is set — [`BindScope::AnyAddress`] is the
/// right variant in that dual-stack case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum BindScope {
    AnyAddress,
    Loopback,
    /// `%iface` suffix on the bind address (common with link-local IPv6).
    SpecificInterface(String),
    /// A specific non-loopback address (e.g. `127.0.0.53` for the systemd
    /// stub, or a LAN IP when the process bound to one).
    SpecificAddress(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Bound to loopback — only reachable from this host.
    LocalOnly,
    /// Firewall blocks WAN but LAN peers can reach the service.
    LanOnly,
    /// Reachable from any peer that can reach this host.
    Exposed,
    /// Firewall state unknown (no [`Firewall`](crate::Firewall) backend).
    Unknown,
}

impl Exposure {
    /// Combine a [`BindScope`] with a [`FirewallVerdict`] into an [`Exposure`].
    ///
    /// Loopback-bound services are always `LocalOnly` regardless of firewall.
    /// A specific-address bind on a non-loopback address is treated like
    /// any-address for firewall purposes (the firewall still governs WAN).
    pub fn from_scope_and_verdict(bind: &BindScope, verdict: FirewallVerdict) -> Self {
        match bind {
            BindScope::Loopback => Exposure::LocalOnly,
            BindScope::SpecificAddress(ip) if ip.is_loopback() => Exposure::LocalOnly,
            _ => match verdict {
                FirewallVerdict::Allow => Exposure::Exposed,
                FirewallVerdict::Drop | FirewallVerdict::Reject => Exposure::LanOnly,
                FirewallVerdict::NoMatch | FirewallVerdict::Unknown => Exposure::Unknown,
            },
        }
    }
}

/// An established or in-flight connection to/from this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    pub process: ProcessInfo,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Smoothed round-trip time in microseconds, when the kernel has one
    /// (TCP only, and only once the connection has carried data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_us: Option<u32>,
}
