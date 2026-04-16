//! Serde DTOs matching `ip -j addr/link/route/neigh` output shapes.
//!
//! These are intentionally forgiving: every optional field is `Option<_>` with
//! `#[serde(default)]`, and we never `deny_unknown_fields`. `ip -j` grows
//! fields across iproute2 versions and we want forward compatibility.

use std::net::IpAddr;

use serde::Deserialize;

/// One element in `ip -j addr` or `ip -j link`.
#[derive(Debug, Clone, Deserialize)]
pub struct RawLink {
    pub ifindex: u32,
    pub ifname: String,
    #[serde(default)]
    pub flags: Vec<String>,
    pub mtu: u32,
    #[serde(default)]
    pub operstate: Option<String>,
    #[serde(default)]
    pub linkmode: Option<String>,
    #[serde(default)]
    pub link_type: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub addr_info: Vec<RawAddr>,
}

/// One entry inside `addr_info[]`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RawAddr {
    pub family: String,
    pub local: String,
    pub prefixlen: u8,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub dynamic: bool,
    #[serde(default)]
    pub temporary: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub mngtmpaddr: bool,
    #[serde(default)]
    pub noprefixroute: bool,
    #[serde(default)]
    pub valid_life_time: Option<u64>,
    #[serde(default)]
    pub preferred_life_time: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
}

/// One entry in `ip -j route`.
#[derive(Debug, Clone, Deserialize)]
pub struct RawRoute {
    /// Either `"default"`, or a prefix like `"192.168.1.0/24"`, or a bare IP.
    pub dst: String,
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub dev: Option<String>,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub prefsrc: Option<IpAddr>,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// One entry in `ip -j neigh`.
#[derive(Debug, Clone, Deserialize)]
pub struct RawNeigh {
    pub dst: IpAddr,
    pub dev: String,
    #[serde(default)]
    pub lladdr: Option<String>,
    #[serde(default)]
    pub state: Vec<String>,
    /// Present as `"router":null` when the peer IS a router. Serde's
    /// `Option<()>` with `#[serde(default)]` captures "the key was there".
    #[serde(default, deserialize_with = "deserialize_router_flag")]
    pub router: bool,
}

fn deserialize_router_flag<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = Option::<serde_json::Value>::deserialize(d)?;
    Ok(true)
}

/// One entry in `ip -j route get <dst>`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RawRouteGet {
    pub dst: IpAddr,
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub dev: Option<String>,
    #[serde(default)]
    pub prefsrc: Option<IpAddr>,
    #[serde(default)]
    pub uid: Option<u32>,
}
