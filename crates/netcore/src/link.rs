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
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperState {
    Up,
    Down,
    Dormant,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkMode {
    Default,
    Dormant,
}

/// IFF_* style flags as reported by the kernel. Stored as strings to avoid a
/// brittle enum; query via helper methods.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkFlags(pub Vec<String>);

impl LinkFlags {
    pub fn has(&self, flag: &str) -> bool {
        self.0.iter().any(|f| f.eq_ignore_ascii_case(flag))
    }
    pub fn is_loopback(&self) -> bool { self.has("LOOPBACK") }
    pub fn lower_up(&self) -> bool { self.has("LOWER_UP") }
    pub fn no_carrier(&self) -> bool { self.has("NO-CARRIER") }
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
    pub ip: IpAddr,
    pub prefix: u8,
    pub scope: AddrScope,
    pub dynamic: bool,
    /// RFC 4941 privacy extension address (IPv6).
    pub temporary: bool,
    /// `preferred_lft == 0`. New outgoing connections avoid these.
    pub deprecated: bool,
    /// SLAAC "manage temporary addresses" — the stable base from which
    /// privacy addresses are derived.
    pub mngtmpaddr: bool,
    pub noprefixroute: bool,
    pub valid_lft: Lifetime,
    pub preferred_lft: Lifetime,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrScope {
    Global,
    Link,
    Host,
    Site,
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
    pub fn is_expired(self) -> bool {
        matches!(self, Lifetime::Seconds(0))
    }
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
    pub dst: RouteDst,
    pub gateway: Option<IpAddr>,
    pub oif: Option<String>,
    pub metric: Option<u32>,
    pub table: u32,
    pub protocol: String,
    pub scope: RouteScope,
    pub prefsrc: Option<IpAddr>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteDst {
    Default,
    Prefix { ip: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteScope {
    Global,
    Universe,
    Site,
    Link,
    Host,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NeighState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Permanent,
    Noarp,
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
