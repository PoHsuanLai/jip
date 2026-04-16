//! Map `raw::*` DTOs into netcore primitives.
//!
//! All translation is total: unknown kernel strings fall into `Other(..)` or
//! `Unknown` variants; no mapping function returns an error. Parse errors
//! happen at the serde layer, not here.

use std::net::IpAddr;
use std::str::FromStr;

use netcore::link::{
    Addr, AddrScope, Lifetime, Link, LinkFlags, LinkKind, LinkMode, MacAddr, NeighState, Neighbor,
    OperState, Route, RouteDst, RouteScope,
};

use crate::raw::{RawAddr, RawLink, RawNeigh, RawRoute};

const FOREVER_SENTINEL: u64 = u32::MAX as u64;

pub fn link_from_raw(raw: &RawLink) -> Link {
    Link {
        name: raw.ifname.clone(),
        index: raw.ifindex,
        kind: link_kind_from(raw),
        mac: raw
            .address
            .as_deref()
            .and_then(|s| MacAddr::from_str(s).ok())
            .filter(|m| m.0 != [0u8; 6] || raw.link_type.as_deref() == Some("loopback")),
        mtu: raw.mtu,
        state: oper_state_from(raw.operstate.as_deref()),
        linkmode: link_mode_from(raw.linkmode.as_deref()),
        flags: LinkFlags(raw.flags.clone()),
    }
}

fn link_kind_from(raw: &RawLink) -> LinkKind {
    let link_type = raw.link_type.as_deref().unwrap_or("");
    match link_type {
        "loopback" => LinkKind::Loopback,
        "ether" => classify_ether(&raw.ifname, &raw.flags),
        "ieee802.11" | "wlan" => LinkKind::Wifi,
        "none" | "void" | "ppp" => LinkKind::Tun,
        other => LinkKind::Other(other.to_owned()),
    }
}

fn classify_ether(ifname: &str, flags: &[String]) -> LinkKind {
    // iproute2 reports docker0 / br-* / virbr* as link_type ether. Use the name
    // prefix to disambiguate. Wifi also reports ether on some drivers but gets
    // disambiguated at the Connection layer where we have `iw` output.
    let n = ifname;
    if n.starts_with("docker") || n.starts_with("br-") || n.starts_with("virbr") {
        LinkKind::Bridge
    } else if n.starts_with("veth") {
        LinkKind::Veth
    } else if n.starts_with("wg") {
        LinkKind::Wireguard
    } else if n.starts_with("tun") {
        LinkKind::Tun
    } else if n.starts_with("tap") {
        LinkKind::Tap
    } else if n.starts_with("bond") {
        LinkKind::Bond
    } else if n.contains('.') && flags.iter().any(|f| f == "MULTICAST") {
        // e.g. eth0.100 — VLAN subinterface.
        LinkKind::Vlan
    } else if n.starts_with("wl") || n.starts_with("wlan") {
        LinkKind::Wifi
    } else {
        LinkKind::Ethernet
    }
}

fn oper_state_from(s: Option<&str>) -> OperState {
    match s.unwrap_or("UNKNOWN") {
        "UP" => OperState::Up,
        "DOWN" => OperState::Down,
        "DORMANT" => OperState::Dormant,
        _ => OperState::Unknown,
    }
}

fn link_mode_from(s: Option<&str>) -> LinkMode {
    match s.unwrap_or("DEFAULT") {
        "DORMANT" => LinkMode::Dormant,
        _ => LinkMode::Default,
    }
}

pub fn addrs_from_raw(raw: &RawLink) -> Vec<(u32, Addr)> {
    raw.addr_info
        .iter()
        .filter_map(|a| addr_from_raw(a).map(|addr| (raw.ifindex, addr)))
        .collect()
}

pub fn addrs_from_raw_single(raw: &RawAddr) -> Option<Addr> {
    addr_from_raw(raw)
}

fn addr_from_raw(raw: &RawAddr) -> Option<Addr> {
    let ip = IpAddr::from_str(&raw.local).ok()?;
    Some(Addr {
        ip,
        prefix: raw.prefixlen,
        scope: addr_scope_from(raw.scope.as_deref()),
        dynamic: raw.dynamic,
        temporary: raw.temporary,
        deprecated: raw.deprecated,
        mngtmpaddr: raw.mngtmpaddr,
        noprefixroute: raw.noprefixroute,
        valid_lft: lifetime_from(raw.valid_life_time),
        preferred_lft: lifetime_from(raw.preferred_life_time),
        label: raw.label.clone(),
    })
}

fn addr_scope_from(s: Option<&str>) -> AddrScope {
    match s.unwrap_or("global") {
        "global" => AddrScope::Global,
        "link" => AddrScope::Link,
        "host" => AddrScope::Host,
        "site" => AddrScope::Site,
        _ => AddrScope::Nowhere,
    }
}

fn lifetime_from(v: Option<u64>) -> Lifetime {
    match v {
        Some(FOREVER_SENTINEL) | None => Lifetime::Forever,
        Some(n) => Lifetime::Seconds(n as u32),
    }
}

pub fn route_from_raw(raw: &RawRoute) -> Option<Route> {
    let dst = parse_route_dst(&raw.dst)?;
    Some(Route {
        dst,
        gateway: raw.gateway,
        oif: raw.dev.clone(),
        metric: raw.metric,
        table: parse_table(raw.table.as_deref()),
        protocol: raw.protocol.clone().unwrap_or_else(|| "unspec".into()),
        scope: route_scope_from(raw.scope.as_deref()),
        prefsrc: raw.prefsrc,
        flags: raw.flags.clone(),
    })
}

fn parse_route_dst(s: &str) -> Option<RouteDst> {
    if s == "default" {
        return Some(RouteDst::Default);
    }
    if let Some((ip_s, prefix_s)) = s.split_once('/') {
        let ip = IpAddr::from_str(ip_s).ok()?;
        let prefix = prefix_s.parse::<u8>().ok()?;
        return Some(RouteDst::Prefix { ip, prefix });
    }
    // Bare IP — treat as /32 (v4) or /128 (v6).
    let ip = IpAddr::from_str(s).ok()?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    Some(RouteDst::Prefix { ip, prefix })
}

fn parse_table(s: Option<&str>) -> u32 {
    match s {
        None | Some("main") => 254,
        Some("local") => 255,
        Some("default") => 253,
        Some(other) => other.parse().unwrap_or(254),
    }
}

fn route_scope_from(s: Option<&str>) -> RouteScope {
    match s.unwrap_or("global") {
        "global" => RouteScope::Global,
        "universe" => RouteScope::Universe,
        "site" => RouteScope::Site,
        "link" => RouteScope::Link,
        "host" => RouteScope::Host,
        _ => RouteScope::Nowhere,
    }
}

pub fn neighbor_from_raw(raw: &RawNeigh) -> Neighbor {
    Neighbor {
        ip: raw.dst,
        lladdr: raw.lladdr.as_deref().and_then(|s| MacAddr::from_str(s).ok()),
        oif: raw.dev.clone(),
        state: neigh_state_from(raw.state.as_slice()),
        is_router: raw.router,
    }
}

fn neigh_state_from(states: &[String]) -> NeighState {
    let first = states.first().map(|s| s.as_str()).unwrap_or("NONE");
    match first {
        "REACHABLE" => NeighState::Reachable,
        "STALE" => NeighState::Stale,
        "DELAY" => NeighState::Delay,
        "PROBE" => NeighState::Probe,
        "FAILED" => NeighState::Failed,
        "INCOMPLETE" => NeighState::Incomplete,
        "PERMANENT" => NeighState::Permanent,
        "NOARP" => NeighState::Noarp,
        _ => NeighState::None,
    }
}

