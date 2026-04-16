//! Listening services and active flows.
//!
//! `Service` describes a listening socket plus its effective exposure to the
//! outside world, computed from the bind scope and the firewall posture.
//! `Flow` is an established connection.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

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
#[serde(tag = "type", rename_all = "snake_case")]
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
}
