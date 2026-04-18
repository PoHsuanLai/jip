//! Layer 2 — what users think a network connection *is*.
//!
//! A [`Connection`] joins a [`Link`](crate::Link), its addresses, its
//! default-route gateway (with L2 status), its resolvers, and any
//! NetworkManager profile into one coherent unit. This is the primary public
//! surface: `jip` (no args) renders a list of these.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::link::{Addr, Link, MacAddr, NeighState};

/// Stable identifier for a connection. When a NetworkManager profile is
/// present, this is the profile name (e.g. `"Wired connection 1"`). Otherwise
/// it is the link name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(pub String);

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ConnectionId {
    fn from(s: &str) -> Self {
        ConnectionId(s.to_owned())
    }
}

/// Address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// Return the [`Family`] for a given IP address.
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// A user-facing network connection: one link plus its interpreted state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Stable identifier, preferring the NM profile name over the link name.
    pub id: ConnectionId,
    /// What kind of connection this is (Ethernet, Wifi, VPN, etc.).
    pub medium: Medium,
    /// The underlying kernel link, preserved for detail views and `jip raw`.
    pub link: Link,
    /// Full list of addresses. Rendering uses [`Connection::primary_v4`] /
    /// [`Connection::primary_v6`] by default and collapses the rest.
    pub addresses: Vec<Addr>,
    /// The single IPv4 to show in the default view.
    pub primary_v4: Option<IpAddr>,
    /// The single IPv6 to show in the default view. Non-deprecated, global.
    pub primary_v6: Option<IpAddr>,
    /// Present when the IPv4 address is dynamic (DHCP).
    pub v4_lease: Option<DhcpLease>,
    /// L3 gateway and its L2 reachability state.
    pub gateway: Option<Gateway>,
    /// Per-link resolvers (from `resolvectl`). Falls back to the stub when
    /// per-link info is unavailable.
    pub dns: Vec<IpAddr>,
    /// True when the default route egresses through this connection.
    pub is_default: bool,
    /// Metric of the default route via this connection, if any. Lower = preferred.
    pub default_metric: Option<u32>,
    /// NetworkManager profile metadata, when one is attached.
    pub profile: Option<Profile>,
}

/// What kind of connection this is from the user's perspective.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Medium {
    /// Wired Ethernet (physical NIC).
    Ethernet,
    /// IEEE 802.11 wireless interface.
    Wifi {
        /// SSID of the associated BSS, if currently connected.
        ssid: Option<String>,
        signal: Option<WifiSignal>,
        security: Option<WifiSecurity>,
    },
    /// docker0, bridges, veth, tap, etc. — not a VPN, not a physical NIC.
    Virtual { kind: VirtualKind },
    /// VPN tunnel.
    Vpn { kind: VpnKind },
    /// Mobile broadband (LTE/5G).
    Cellular {
        /// Carrier name, when the modem reports it.
        operator: Option<String>,
    },
    /// Loopback interface.
    Loopback,
}

/// Subtype of a virtual (`Medium::Virtual`) link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualKind {
    /// Docker-managed bridge (name starts with `docker` or `br-`).
    Docker,
    /// Generic Linux bridge.
    Bridge,
    /// Virtual Ethernet pair.
    Veth,
    /// TAP device (L2 virtual interface).
    Tap,
    /// Unrecognised virtual interface.
    Other,
}

/// Subtype of a VPN (`Medium::Vpn`) link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnKind {
    /// WireGuard tunnel.
    Wireguard,
    /// OpenVPN tunnel.
    OpenVpn,
    /// Generic point-to-point tunnel.
    Tun,
    /// L2 tunnel (some VPNs create a tap device).
    Tap,
    /// Unrecognised VPN type.
    Other,
}

/// Signal strength and rate information for an associated wifi BSS.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WifiSignal {
    /// dBm, typically -30 (great) to -90 (unusable).
    pub rssi_dbm: i32,
    /// Optional signal quality as a 0–100 percentage if the driver reports it.
    pub quality_pct: Option<u8>,
    /// Link rate in Mbps, if known.
    pub rate_mbps: Option<u32>,
}

impl Eq for WifiSignal {}

/// Security mode of the associated wifi BSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiSecurity {
    /// No authentication.
    Open,
    /// WEP (deprecated).
    Wep,
    Wpa2Personal,
    Wpa2Enterprise,
    Wpa3Personal,
    Wpa3Enterprise,
    /// An unrecognised security mode; the raw string is preserved.
    Other(String),
}

/// A nearby wifi access point from an NM scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    /// Network name. Empty string when the SSID is hidden.
    pub ssid: String,
    /// BSSID (MAC address of the AP).
    pub bssid: String,
    /// Signal strength.
    pub signal: WifiSignal,
    /// Channel frequency in MHz (e.g. 2412, 5180).
    pub frequency_mhz: u32,
    /// Security classification decoded from NM's WpaFlags/RsnFlags.
    pub security: WifiSecurity,
    /// `true` when this is the currently associated AP.
    pub in_use: bool,
}

/// The L3 default-route next-hop plus its L2 ARP/ND state. Having both lets
/// the diagnostician say "your route points at 192.168.1.1 but it's not
/// answering ARP" rather than just "unreachable".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    pub ip: IpAddr,
    pub lladdr: Option<MacAddr>,
    pub l2_state: NeighState,
    pub is_router: bool,
}

/// Metadata from NetworkManager (or any future connection manager).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// NM connection UUID.
    pub uuid: String,
    pub autoconnect: bool,
    /// NM's raw type string: `"802-3-ethernet"`, `"wifi"`, `"vpn"`, `"bridge"`, ...
    pub kind: String,
    /// Interface this profile binds to, if any. `None` for VPN and unbound profiles.
    pub iface: Option<String>,
    /// Whether this profile is currently active (has an active connection in NM).
    pub active: bool,
}

/// Summary of the active DHCP lease on the IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpLease {
    /// Remaining lease time. Computed from `valid_lft` at inventory time.
    pub expires_in: Duration,
    /// The DHCP server that granted the lease, when known. Not surfaced by
    /// `ip -j`; requires NM or reading dhclient leases.
    pub server: Option<IpAddr>,
}
