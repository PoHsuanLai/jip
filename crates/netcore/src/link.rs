//! Layer 1 — thin typed wrappers over what the kernel exposes via netlink/sysfs.
//!
//! These are the primitives returned by [`InventoryRaw`](crate::InventoryRaw).
//! Users only see them via `jip raw *`.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::process::ProcessInfo;

/// A kernel-visible network interface (link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub kind: LinkKind,
    pub mac: Option<MacAddr>,
    pub mtu: u32,
    pub state: OperState,
    /// `DORMANT` distinguishes wifi-radio-on-but-not-associated from cable-unplugged.
    pub linkmode: LinkMode,
    pub flags: LinkFlags,
}

/// The type of network link, as inferred from the kernel's layer-2 type and
/// interface name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Ethernet,
    Wifi,
    Loopback,
    Bridge,
    Veth,
    Tun,
    Tap,
    Wireguard,
    Vlan,
    Bond,
    /// An unrecognised link-layer type; the raw name is preserved.
    Other(String),
}

/// RFC 2863 operational state as reported by the kernel via `IF_OPER_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperState {
    /// Link is up and ready to pass traffic.
    Up,
    /// Link is administratively or physically down.
    Down,
    /// Radio is on but not associated (wifi) or cable connected but no carrier.
    Dormant,
    /// State not reported or not applicable (e.g. loopback).
    Unknown,
}

/// Kernel link mode (`IFLA_LINKMODE`). `Dormant` means the link waits for an
/// upper layer (e.g. 802.1X authentication) before coming up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkMode {
    /// Normal operation.
    Default,
    /// Waiting for upper-layer confirmation before the link is usable.
    Dormant,
}

/// IFF_* style flags as reported by the kernel. Stored as strings to avoid a
/// brittle enum; query via helper methods.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkFlags(pub Vec<String>);

impl LinkFlags {
    /// Return `true` if the given flag name is present (case-insensitive).
    pub fn has(&self, flag: &str) -> bool {
        self.0.iter().any(|f| f.eq_ignore_ascii_case(flag))
    }
    /// Return `true` when `IFF_LOOPBACK` is set.
    pub fn is_loopback(&self) -> bool {
        self.has("LOOPBACK")
    }
    /// Return `true` when `IFF_LOWER_UP` is set (physical layer is up).
    pub fn lower_up(&self) -> bool {
        self.has("LOWER_UP")
    }
    /// Return `true` when the link is administratively up but has no carrier.
    pub fn no_carrier(&self) -> bool {
        self.has("NO-CARRIER")
    }
}

/// Six-byte link-layer address. Displayed as `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl std::str::FromStr for MacAddr {
    type Err = MacAddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 6];
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(MacAddrParseError);
        }
        for (i, p) in parts.iter().enumerate() {
            out[i] = u8::from_str_radix(p, 16).map_err(|_| MacAddrParseError)?;
        }
        Ok(MacAddr(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address")]
pub struct MacAddrParseError;

/// A single address bound to a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    /// The IP address.
    pub ip: IpAddr,
    /// Prefix length (CIDR).
    pub prefix: u8,
    pub scope: AddrScope,
    /// Address was assigned dynamically (DHCP or SLAAC).
    pub dynamic: bool,
    /// RFC 4941 privacy extension address (IPv6).
    pub temporary: bool,
    /// `preferred_lft == 0`. New outgoing connections avoid these.
    pub deprecated: bool,
    /// SLAAC "manage temporary addresses" — the stable base from which
    /// privacy addresses are derived.
    pub mngtmpaddr: bool,
    /// `IFA_F_NOPREFIXROUTE`: a connected prefix route was not installed.
    pub noprefixroute: bool,
    /// How long the address is valid. `Forever` for static addresses.
    pub valid_lft: Lifetime,
    /// How long the address is preferred for new outgoing connections.
    pub preferred_lft: Lifetime,
    /// Optional label string (from `ip addr`).
    pub label: Option<String>,
}

/// Scope of an IP address, as reported by the kernel (`RT_SCOPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrScope {
    /// Globally routable address.
    Global,
    /// Link-local address (fe80::/10 or 169.254.0.0/16).
    Link,
    /// Loopback address.
    Host,
    /// Site-local (deprecated, RFC 3879).
    Site,
    /// No scope / unreachable.
    Nowhere,
}

/// `valid_lft` / `preferred_lft` as reported by the kernel. `forever` is
/// `u32::MAX` (4294967295) in `ip -j`; backends lift that to [`Lifetime::Forever`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Lifetime {
    Forever,
    Seconds(u32),
}

impl Lifetime {
    /// Return `true` when the lifetime has reached zero (address expired).
    pub fn is_expired(self) -> bool {
        matches!(self, Lifetime::Seconds(0))
    }
    /// Convert to a [`Duration`], returning `None` for [`Lifetime::Forever`].
    pub fn as_duration(self) -> Option<Duration> {
        match self {
            Lifetime::Forever => None,
            Lifetime::Seconds(s) => Some(Duration::from_secs(u64::from(s))),
        }
    }
}

/// A kernel routing table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Destination prefix or `Default` for the default route.
    pub dst: RouteDst,
    /// Next-hop gateway IP, when present.
    pub gateway: Option<IpAddr>,
    /// Output interface name, when known.
    pub oif: Option<String>,
    /// Route metric (lower = preferred among equal destinations).
    pub metric: Option<u32>,
    /// Routing table number (254 = main).
    pub table: u32,
    /// Protocol that installed this route (e.g. `"dhcp"`, `"kernel"`).
    pub protocol: String,
    pub scope: RouteScope,
    /// Preferred source address for packets using this route.
    pub prefsrc: Option<IpAddr>,
    /// Route flags as strings (e.g. `"onlink"`).
    pub flags: Vec<String>,
}

/// Routing table destination: either the default route or a specific prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteDst {
    /// The default route (`0.0.0.0/0` or `::/0`).
    Default,
    /// A specific destination prefix.
    Prefix { ip: IpAddr, prefix: u8 },
}

/// Scope of a routing table entry (`RT_SCOPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteScope {
    /// Globally routable.
    Global,
    /// Equivalent to `Global`; used by the kernel for unicast routes.
    Universe,
    /// Site-scoped (deprecated).
    Site,
    /// Directly reachable on the link — no gateway needed.
    Link,
    /// Loopback route.
    Host,
    /// Unreachable destination.
    Nowhere,
}

/// A neighbor table entry (ARP/ND).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub lladdr: Option<MacAddr>,
    pub oif: String,
    pub state: NeighState,
    /// `ip -j neigh` encodes router-ness as `"router": null` (the key being
    /// present at all, with a null value). Backends must normalise that quirk.
    pub is_router: bool,
}

/// ARP/ND neighbor cache state (`NUD_*` flags from the kernel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NeighState {
    /// ARP/ND request sent; reply not yet received.
    Incomplete,
    /// L2 address confirmed reachable within the reachable time.
    Reachable,
    /// Entry valid but not recently confirmed.
    Stale,
    /// Waiting before sending a reachability probe.
    Delay,
    /// Actively probing for reachability.
    Probe,
    /// ARP/ND failed; address is unreachable at L2.
    Failed,
    /// Statically configured entry; never expires.
    Permanent,
    /// No ARP needed for this address (e.g. point-to-point links).
    Noarp,
    /// No state information available.
    None,
}

/// A listening or established socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socket {
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: TcpState,
    pub process: ProcessInfo,
    /// Set when the socket is bound with `SO_BINDTODEVICE` or a `%iface` suffix.
    pub bound_iface: Option<String>,
}

/// Layer 4 transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// Kernel TCP state names (also used for UDP: `Unconn` is the UDP "listen").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TcpState {
    Listen,
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Closing,
    Unconn,
    Unknown,
}
