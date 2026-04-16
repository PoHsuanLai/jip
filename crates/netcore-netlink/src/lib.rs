//! netlink backend for netcore.
//!
//! Implements [`InventoryRaw`] and [`Inventory`] by talking directly to the
//! kernel over rtnetlink.
//!
//! Runtime: a `current_thread` tokio runtime is built on demand for each
//! public call. Building takes ~1ms and each method returns <100 total rows
//! for a normal host, so we don't keep the runtime around.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use netlink_packet_route::link::{
    LinkAttribute, LinkFlags as NlLinkFlags, LinkLayerType, LinkMessage, LinkMode as NlLinkMode,
    State,
};
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteScope as NlRouteScope,
};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, RouteMessageBuilder};

use netcore::connection::{
    Connection, ConnectionId, DhcpLease, Family, Gateway, Medium, VirtualKind, VpnKind,
};
use netcore::link::{
    Addr, AddrScope, Lifetime, Link, LinkFlags, LinkKind, LinkMode, MacAddr, NeighState, Neighbor,
    OperState, Route as NcRoute, RouteDst, RouteScope as NcRouteScope, Socket, TcpState,
};
use netcore::path::Egress;
use netcore::service::{BindScope, Exposure, Flow, Service};
use netcore::traits::{Inventory, InventoryRaw};
use netcore::{Error, Result};

mod sockdiag;

/// Production netlink backend. Holds no state; each call builds a new
/// current_thread tokio runtime (~1ms) and a fresh netlink socket.
pub struct NetlinkBackend;

impl NetlinkBackend {
    pub fn new() -> Self { Self }

    fn block_on<F, T>(fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| Error::Backend(format!("tokio runtime: {e}")))?;
        rt.block_on(fut)
    }

    async fn with_handle<F, Fut, T>(f: F) -> Result<T>
    where
        F: FnOnce(Handle) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|e| Error::Backend(format!("netlink connect: {e}")))?;
        let conn_task = tokio::spawn(connection);
        let out = f(handle).await;
        conn_task.abort();
        out
    }
}

impl Default for NetlinkBackend {
    fn default() -> Self { Self::new() }
}

impl InventoryRaw for NetlinkBackend {
    fn links(&self) -> Result<Vec<Link>> {
        Self::block_on(async {
            Self::with_handle(|h| async move {
                let mut stream = h.link().get().execute();
                let mut out = Vec::new();
                while let Some(msg) = stream
                    .try_next()
                    .await
                    .map_err(|e| Error::Backend(format!("RTM_GETLINK: {e}")))?
                {
                    out.push(link_from_nl(&msg));
                }
                Ok(out)
            })
            .await
        })
    }

    fn addrs(&self) -> Result<Vec<(u32, Addr)>> {
        Self::block_on(async {
            Self::with_handle(|h| async move {
                let mut stream = h.address().get().execute();
                let mut out = Vec::new();
                while let Some(msg) = stream
                    .try_next()
                    .await
                    .map_err(|e| Error::Backend(format!("RTM_GETADDR: {e}")))?
                {
                    if let Some(addr) = addr_from_nl(&msg) {
                        out.push((msg.header.index, addr));
                    }
                }
                Ok(out)
            })
            .await
        })
    }

    fn routes(&self) -> Result<Vec<NcRoute>> {
        let links = self.links()?;
        Self::block_on(async {
            Self::with_handle(|h| async move {
                let mut out = Vec::new();
                for builder in [
                    RouteMessageBuilder::<Ipv4Addr>::new().build(),
                    RouteMessageBuilder::<Ipv6Addr>::new().build(),
                ] {
                    let mut stream = h.route().get(builder).execute();
                    while let Some(msg) = stream
                        .try_next()
                        .await
                        .map_err(|e| Error::Backend(format!("RTM_GETROUTE: {e}")))?
                    {
                        if let Some(r) = route_from_nl(&msg, &links) {
                            out.push(r);
                        }
                    }
                }
                Ok(out)
            })
            .await
        })
    }

    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        let links = self.links()?;
        Self::block_on(async {
            Self::with_handle(|h| async move {
                let mut stream = h.neighbours().get().execute();
                let mut out = Vec::new();
                while let Some(msg) = stream
                    .try_next()
                    .await
                    .map_err(|e| Error::Backend(format!("RTM_GETNEIGH: {e}")))?
                {
                    let oif = links
                        .iter()
                        .find(|l| l.index == msg.header.ifindex)
                        .map(|l| l.name.clone());
                    if let Some(n) = neighbor_from_nl(&msg, oif) {
                        out.push(n);
                    }
                }
                Ok(out)
            })
            .await
        })
    }

    fn sockets(&self) -> Result<Vec<Socket>> { sockdiag::dump_all() }
}

impl Inventory for NetlinkBackend {
    fn connections(&self) -> Result<Vec<Connection>> {
        let links = self.links()?;
        let addrs = self.addrs()?;
        let routes = self.routes()?;
        let neighbors = self.neighbors()?;
        let mut out = Vec::with_capacity(links.len());
        for link in &links {
            let link_addrs: Vec<Addr> = addrs
                .iter()
                .filter(|(idx, _)| *idx == link.index)
                .map(|(_, a)| a.clone())
                .collect();
            let default_route = routes.iter().find(|r| {
                matches!(r.dst, RouteDst::Default) && r.oif.as_deref() == Some(link.name.as_str())
            });
            let gateway = default_route
                .and_then(|r| r.gateway)
                .map(|ip| gateway_for(ip, &neighbors));
            out.push(Connection {
                id: ConnectionId(link.name.clone()),
                medium: medium_for(link),
                link: link.clone(),
                primary_v4: primary_v4(&link_addrs),
                primary_v6: primary_v6(&link_addrs),
                v4_lease: v4_lease(&link_addrs),
                addresses: link_addrs,
                gateway,
                dns: vec![],
                is_default: default_route.is_some(),
                default_metric: default_route.and_then(|r| r.metric),
                profile: None,
            });
        }
        Ok(out)
    }

    fn services(&self) -> Result<Vec<Service>> {
        use netcore::link::L4Proto;
        let sockets = self.sockets()?;
        let mut out = Vec::with_capacity(sockets.len() / 2);
        for s in sockets {
            // TCP listeners are explicit. UDP "sockets" come back as Close; treat
            // any UDP socket with no peer as a listener (UDP has no Listen state).
            let is_listener = match s.proto {
                L4Proto::Tcp => matches!(s.state, TcpState::Listen),
                L4Proto::Udp => s.remote.is_none(),
            };
            if !is_listener { continue; }
            out.push(Service {
                port: s.local.port(),
                proto: s.proto,
                bind: bind_scope_for(&s.local),
                process: s.process,
                // No firewall backend yet; leave verdict open.
                exposure: Exposure::Unknown,
            });
        }
        Ok(out)
    }

    fn flows(&self) -> Result<Vec<Flow>> {
        let sockets = self.sockets()?;
        let mut out = Vec::with_capacity(sockets.len() / 2);
        for s in sockets {
            if !matches!(s.state, TcpState::Established) { continue; }
            let Some(remote) = s.remote else { continue };
            out.push(Flow {
                proto: s.proto,
                local: s.local,
                remote,
                state: s.state,
                process: s.process,
                bytes_in: 0,
                bytes_out: 0,
            });
        }
        Ok(out)
    }

    fn egress_for(&self, dst: IpAddr) -> Result<Egress> {
        let links = self.links()?;
        Self::block_on(async {
            Self::with_handle(|h| async move {
                let req = match dst {
                    IpAddr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
                        .destination_prefix(v4, 32)
                        .build(),
                    IpAddr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
                        .destination_prefix(v6, 128)
                        .build(),
                };
                let mut stream = h.route().get(req).execute();
                let msg = stream
                    .try_next()
                    .await
                    .map_err(|e| {
                        let m = e.to_string();
                        if m.contains("Network is unreachable") || m.contains("network is unreachable") {
                            Error::Backend("Network is unreachable".into())
                        } else {
                            Error::Backend(format!("RTM_GETROUTE: {e}"))
                        }
                    })?
                    .ok_or_else(|| Error::NotFound(format!("no route for {dst}")))?;
                Ok(egress_from_route_get(&msg, dst, &links))
            })
            .await
        })
        .or_else(|e| {
            if matches!(&e, Error::Backend(m) if m.contains("Network is unreachable")) {
                Ok(unreachable_egress(dst))
            } else {
                Err(e)
            }
        })
    }
}

fn egress_from_route_get(msg: &RouteMessage, dst: IpAddr, links: &[Link]) -> Egress {
    let mut gateway = None;
    let mut prefsrc = None;
    let mut oif: Option<u32> = None;
    let mut uid: Option<u32> = None;
    for a in &msg.attributes {
        match a {
            RouteAttribute::Gateway(RouteAddress::Inet(v4)) => gateway = Some(IpAddr::V4(*v4)),
            RouteAttribute::Gateway(RouteAddress::Inet6(v6)) => gateway = Some(IpAddr::V6(*v6)),
            RouteAttribute::PrefSource(RouteAddress::Inet(v4)) => prefsrc = Some(IpAddr::V4(*v4)),
            RouteAttribute::PrefSource(RouteAddress::Inet6(v6)) => prefsrc = Some(IpAddr::V6(*v6)),
            RouteAttribute::Oif(idx) => oif = Some(*idx),
            RouteAttribute::Uid(u) => uid = Some(*u),
            _ => {}
        }
    }
    let iface = oif
        .and_then(|idx| links.iter().find(|l| l.index == idx))
        .map(|l| l.name.clone())
        .unwrap_or_else(|| "-".into());
    Egress {
        connection_id: ConnectionId(iface.clone()),
        iface,
        src: prefsrc.unwrap_or(dst),
        gateway,
        family_used: Family::of(dst),
        family_unreachable: vec![],
        uid_scoped: uid.is_some(),
    }
}

fn unreachable_egress(dst: IpAddr) -> Egress {
    Egress {
        connection_id: ConnectionId("-".into()),
        iface: "-".into(),
        src: dst,
        gateway: None,
        family_used: Family::of(dst),
        family_unreachable: vec![Family::of(dst)],
        uid_scoped: false,
    }
}

fn bind_scope_for(local: &std::net::SocketAddr) -> BindScope {
    let ip = local.ip();
    let is_unspecified = match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    if is_unspecified {
        BindScope::AnyAddress
    } else if ip.is_loopback() {
        BindScope::Loopback
    } else {
        BindScope::SpecificAddress(ip)
    }
}

fn gateway_for(ip: IpAddr, neighbors: &[Neighbor]) -> Gateway {
    if let Some(n) = neighbors.iter().find(|n| n.ip == ip) {
        Gateway { ip, lladdr: n.lladdr, l2_state: n.state, is_router: n.is_router }
    } else {
        Gateway { ip, lladdr: None, l2_state: NeighState::None, is_router: false }
    }
}

fn link_from_nl(msg: &LinkMessage) -> Link {
    let mut name = String::new();
    let mut mac: Option<MacAddr> = None;
    let mut mtu: u32 = 0;
    let mut operstate = OperState::Unknown;
    let mut linkmode = LinkMode::Default;
    for a in &msg.attributes {
        match a {
            LinkAttribute::IfName(n) => name = n.clone(),
            LinkAttribute::Address(bytes) if bytes.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(bytes);
                mac = Some(MacAddr(m));
            }
            LinkAttribute::Mtu(v) => mtu = *v,
            LinkAttribute::OperState(state) => {
                operstate = match state {
                    State::Up => OperState::Up,
                    State::Down => OperState::Down,
                    State::Dormant => OperState::Dormant,
                    _ => OperState::Unknown,
                };
            }
            LinkAttribute::Mode(m) => {
                linkmode = match m {
                    NlLinkMode::Dormant => LinkMode::Dormant,
                    _ => LinkMode::Default,
                };
            }
            _ => {}
        }
    }
    Link {
        index: msg.header.index,
        kind: link_kind_from(&name, msg.header.link_layer_type),
        mac,
        mtu,
        state: operstate,
        linkmode,
        flags: link_flags_from(msg.header.flags),
        name,
    }
}

fn link_flags_from(flags: NlLinkFlags) -> LinkFlags {
    let mut v = Vec::new();
    // Render each set bit as its uppercase name for parity with `ip` output.
    if flags.contains(NlLinkFlags::Up) { v.push("UP".into()); }
    if flags.contains(NlLinkFlags::Broadcast) { v.push("BROADCAST".into()); }
    if flags.contains(NlLinkFlags::Loopback) { v.push("LOOPBACK".into()); }
    if flags.contains(NlLinkFlags::Pointopoint) { v.push("POINTOPOINT".into()); }
    if flags.contains(NlLinkFlags::Running) { v.push("RUNNING".into()); }
    if flags.contains(NlLinkFlags::Noarp) { v.push("NOARP".into()); }
    if flags.contains(NlLinkFlags::Promisc) { v.push("PROMISC".into()); }
    if flags.contains(NlLinkFlags::Multicast) { v.push("MULTICAST".into()); }
    if flags.contains(NlLinkFlags::LowerUp) { v.push("LOWER_UP".into()); }
    if flags.contains(NlLinkFlags::Dormant) { v.push("DORMANT".into()); }
    if flags.contains(NlLinkFlags::Dynamic) { v.push("DYNAMIC".into()); }
    // Carrier is inferred from LOWER_UP; "NO-CARRIER" appears in `ip` output
    // when !LOWER_UP but the link is administratively UP. Preserve that.
    if flags.contains(NlLinkFlags::Up) && !flags.contains(NlLinkFlags::LowerUp) {
        v.push("NO-CARRIER".into());
    }
    LinkFlags(v)
}

fn link_kind_from(name: &str, ll: LinkLayerType) -> LinkKind {
    match ll {
        LinkLayerType::Loopback => LinkKind::Loopback,
        LinkLayerType::Ether => classify_ether(name),
        other => LinkKind::Other(format!("{:?}", other).to_lowercase()),
    }
}

fn classify_ether(name: &str) -> LinkKind {
    if name.starts_with("docker") || name.starts_with("br-") || name.starts_with("virbr") {
        LinkKind::Bridge
    } else if name.starts_with("veth") {
        LinkKind::Veth
    } else if name.starts_with("wg") {
        LinkKind::Wireguard
    } else if name.starts_with("tun") {
        LinkKind::Tun
    } else if name.starts_with("tap") {
        LinkKind::Tap
    } else if name.starts_with("bond") {
        LinkKind::Bond
    } else if name.starts_with("wl") || name.starts_with("wlan") {
        LinkKind::Wifi
    } else if name.contains('.') {
        LinkKind::Vlan
    } else {
        LinkKind::Ethernet
    }
}

fn addr_from_nl(msg: &AddressMessage) -> Option<Addr> {
    let mut ip: Option<IpAddr> = None;
    let mut label = None;
    let mut valid = None;
    let mut preferred = None;
    let mut full_flags: u32 = 0;
    let mut has_ext_flags = false;
    for a in &msg.attributes {
        match a {
            AddressAttribute::Address(addr) => ip = Some(*addr),
            AddressAttribute::Label(l) => label = Some(l.clone()),
            AddressAttribute::CacheInfo(ci) => {
                valid = Some(ci.ifa_valid);
                preferred = Some(ci.ifa_preferred);
            }
            AddressAttribute::Flags(fs) => {
                full_flags = fs.bits();
                has_ext_flags = true;
            }
            _ => {}
        }
    }
    // Fall back to the 8-bit header flags if no extended Flags attribute was present.
    if !has_ext_flags {
        full_flags = u32::from(msg.header.flags.bits());
    }

    let ip = ip?;
    let permanent = full_flags & 0x80 != 0; // IFA_F_PERMANENT
    let secondary = full_flags & 0x01 != 0; // IFA_F_SECONDARY (== temporary)
    let deprecated = full_flags & 0x20 != 0; // IFA_F_DEPRECATED
    let mngtmp = full_flags & 0x100 != 0; // IFA_F_MANAGETEMPADDR
    let noprefix = full_flags & 0x200 != 0; // IFA_F_NOPREFIXROUTE

    Some(Addr {
        ip,
        prefix: msg.header.prefix_len,
        scope: addr_scope_from(msg.header.scope),
        dynamic: !permanent,
        temporary: secondary,
        deprecated,
        mngtmpaddr: mngtmp,
        noprefixroute: noprefix,
        valid_lft: lifetime_from(valid),
        preferred_lft: lifetime_from(preferred),
        label,
    })
}

fn addr_scope_from(scope: AddressScope) -> AddrScope {
    match scope {
        AddressScope::Universe => AddrScope::Global,
        AddressScope::Site => AddrScope::Site,
        AddressScope::Link => AddrScope::Link,
        AddressScope::Host => AddrScope::Host,
        _ => AddrScope::Nowhere,
    }
}

fn lifetime_from(v: Option<u32>) -> Lifetime {
    match v {
        Some(u32::MAX) | None => Lifetime::Forever,
        Some(n) => Lifetime::Seconds(n),
    }
}

fn route_from_nl(msg: &RouteMessage, links: &[Link]) -> Option<NcRoute> {
    let mut dst_addr: Option<IpAddr> = None;
    let mut gateway = None;
    let mut oif_idx: Option<u32> = None;
    let mut metric = None;
    let mut prefsrc = None;
    let mut table = u32::from(msg.header.table);
    for a in &msg.attributes {
        match a {
            RouteAttribute::Destination(RouteAddress::Inet(v4)) => dst_addr = Some(IpAddr::V4(*v4)),
            RouteAttribute::Destination(RouteAddress::Inet6(v6)) => dst_addr = Some(IpAddr::V6(*v6)),
            RouteAttribute::Gateway(RouteAddress::Inet(v4)) => gateway = Some(IpAddr::V4(*v4)),
            RouteAttribute::Gateway(RouteAddress::Inet6(v6)) => gateway = Some(IpAddr::V6(*v6)),
            RouteAttribute::Oif(i) => oif_idx = Some(*i),
            RouteAttribute::Priority(p) => metric = Some(*p),
            RouteAttribute::PrefSource(RouteAddress::Inet(v4)) => prefsrc = Some(IpAddr::V4(*v4)),
            RouteAttribute::PrefSource(RouteAddress::Inet6(v6)) => prefsrc = Some(IpAddr::V6(*v6)),
            RouteAttribute::Table(t) => table = *t,
            _ => {}
        }
    }
    let dst = if msg.header.destination_prefix_length == 0 && dst_addr.is_none() {
        RouteDst::Default
    } else {
        RouteDst::Prefix {
            ip: dst_addr?,
            prefix: msg.header.destination_prefix_length,
        }
    };
    let oif = oif_idx.and_then(|i| links.iter().find(|l| l.index == i).map(|l| l.name.clone()));
    Some(NcRoute {
        dst,
        gateway,
        oif,
        metric,
        table,
        protocol: format!("{:?}", msg.header.protocol).to_lowercase(),
        scope: route_scope_from(msg.header.scope),
        prefsrc,
        flags: vec![],
    })
}

fn route_scope_from(s: NlRouteScope) -> NcRouteScope {
    match s {
        NlRouteScope::Universe => NcRouteScope::Universe,
        NlRouteScope::Site => NcRouteScope::Site,
        NlRouteScope::Link => NcRouteScope::Link,
        NlRouteScope::Host => NcRouteScope::Host,
        _ => NcRouteScope::Nowhere,
    }
}

fn neighbor_from_nl(msg: &NeighbourMessage, oif_name: Option<String>) -> Option<Neighbor> {
    let mut ip: Option<IpAddr> = None;
    let mut lladdr: Option<MacAddr> = None;
    for a in &msg.attributes {
        match a {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(v4)) => ip = Some(IpAddr::V4(*v4)),
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(v6)) => ip = Some(IpAddr::V6(*v6)),
            NeighbourAttribute::LinkLocalAddress(bytes) if bytes.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(bytes);
                lladdr = Some(MacAddr(m));
            }
            _ => {}
        }
    }
    Some(Neighbor {
        ip: ip?,
        lladdr,
        oif: oif_name.unwrap_or_else(|| format!("if{}", msg.header.ifindex)),
        state: neigh_state_from(msg.header.state),
        is_router: msg.header.flags.contains(NeighbourFlags::Router),
    })
}

fn neigh_state_from(state: NeighbourState) -> NeighState {
    match state {
        NeighbourState::Incomplete => NeighState::Incomplete,
        NeighbourState::Reachable => NeighState::Reachable,
        NeighbourState::Stale => NeighState::Stale,
        NeighbourState::Delay => NeighState::Delay,
        NeighbourState::Probe => NeighState::Probe,
        NeighbourState::Failed => NeighState::Failed,
        NeighbourState::Noarp => NeighState::Noarp,
        NeighbourState::Permanent => NeighState::Permanent,
        _ => NeighState::None,
    }
}

// Primary-address selection (simplified RFC 6724): prefer a global,
// non-deprecated, stable address; fall back to temporary privacy addresses.
fn primary_v4(addrs: &[Addr]) -> Option<IpAddr> {
    addrs
        .iter()
        .filter(|a| matches!(a.ip, IpAddr::V4(_)))
        .filter(|a| matches!(a.scope, AddrScope::Global))
        .filter(|a| !a.deprecated)
        .map(|a| a.ip)
        .next()
}

fn primary_v6(addrs: &[Addr]) -> Option<IpAddr> {
    let candidates = || {
        addrs
            .iter()
            .filter(|a| matches!(a.ip, IpAddr::V6(_)))
            .filter(|a| matches!(a.scope, AddrScope::Global))
            .filter(|a| !a.deprecated)
    };
    if let Some(stable) = candidates().find(|a| !a.temporary) {
        return Some(stable.ip);
    }
    candidates().map(|a| a.ip).next()
}

fn v4_lease(addrs: &[Addr]) -> Option<DhcpLease> {
    addrs
        .iter()
        .find(|a| matches!(a.ip, IpAddr::V4(_)) && a.dynamic)
        .and_then(|a| match a.valid_lft {
            Lifetime::Seconds(s) => Some(DhcpLease {
                expires_in: std::time::Duration::from_secs(s.into()),
                server: None,
            }),
            Lifetime::Forever => None,
        })
}

fn medium_for(link: &Link) -> Medium {
    match &link.kind {
        LinkKind::Ethernet => Medium::Ethernet,
        LinkKind::Wifi => Medium::Wifi { ssid: None, signal: None, security: None },
        LinkKind::Loopback => Medium::Loopback,
        LinkKind::Bridge => Medium::Virtual {
            kind: if link.name.starts_with("docker") { VirtualKind::Docker } else { VirtualKind::Bridge },
        },
        LinkKind::Veth => Medium::Virtual { kind: VirtualKind::Veth },
        LinkKind::Tap => Medium::Virtual { kind: VirtualKind::Tap },
        LinkKind::Tun => Medium::Virtual { kind: VirtualKind::Other },
        LinkKind::Wireguard => Medium::Vpn { kind: VpnKind::Wireguard },
        LinkKind::Vlan | LinkKind::Bond | LinkKind::Other(_) => Medium::Virtual { kind: VirtualKind::Other },
    }
}

// Touch a couple of types so their imports don't appear unused if inlining changes.
#[allow(dead_code)]
fn _touch(_: AddressFamily, _: Ipv4Addr, _: Ipv6Addr) {}

#[cfg(test)]
mod live_tests {
    //! Smoke tests against the real kernel. These don't assert on specific
    //! interface names (CI might not have eth0) — they assert shape: at
    //! least one link, `lo` present, addresses parse, routes parse.

    use super::*;

    #[test]
    fn links_dump_returns_lo() {
        let b = NetlinkBackend::new();
        let links = b.links().expect("RTM_GETLINK");
        assert!(!links.is_empty(), "at least one link");
        let lo = links.iter().find(|l| l.name == "lo").expect("lo present");
        assert!(matches!(lo.kind, LinkKind::Loopback));
        assert!(matches!(lo.state, OperState::Unknown | OperState::Up));
    }

    #[test]
    fn addrs_dump_returns_loopback_127() {
        let b = NetlinkBackend::new();
        let addrs = b.addrs().expect("RTM_GETADDR");
        let has_lo_v4 = addrs
            .iter()
            .any(|(_, a)| matches!(a.ip, IpAddr::V4(v4) if v4 == Ipv4Addr::new(127, 0, 0, 1)));
        assert!(has_lo_v4, "127.0.0.1 present in address dump");
    }

    #[test]
    fn routes_dump_has_entries() {
        let b = NetlinkBackend::new();
        let routes = b.routes().expect("RTM_GETROUTE");
        assert!(!routes.is_empty(), "at least one route");
    }

    #[test]
    fn neighbors_dump_parses() {
        let b = NetlinkBackend::new();
        let _ = b.neighbors().expect("RTM_GETNEIGH");
    }

    #[test]
    fn connections_join_addrs_to_links() {
        let b = NetlinkBackend::new();
        let conns = b.connections().expect("connections");
        assert!(!conns.is_empty(), "at least one connection");
        let lo = conns.iter().find(|c| c.link.name == "lo").expect("lo");
        assert!(
            lo.addresses.iter().any(|a| a.ip.is_loopback()),
            "lo has 127.0.0.1 in addresses"
        );
    }

    #[test]
    fn egress_for_loopback_returns_lo() {
        let b = NetlinkBackend::new();
        let eg = b
            .egress_for(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("egress 127.0.0.1");
        assert_eq!(eg.iface, "lo");
    }

    #[test]
    fn sockets_dump_returns_something() {
        let b = NetlinkBackend::new();
        let socks = b.sockets().expect("sock_diag dump");
        // Any live Linux box has at least one TCP or UDP socket open
        // (systemd-resolved on :53, sshd, a getty, etc.).
        assert!(!socks.is_empty(), "no sockets at all — kernel returning empty dump?");
    }

    #[test]
    fn services_includes_a_listener() {
        use netcore::link::TcpState;
        let b = NetlinkBackend::new();
        let services = b.services().expect("services");
        // Don't hardcode port 53 — CI might not run systemd-resolved.
        // Just confirm the filter produced *some* listener and didn't
        // swallow everything.
        let socks = b.sockets().unwrap();
        let listener_count = socks.iter().filter(|s| matches!(s.state, TcpState::Listen)).count();
        if listener_count > 0 {
            assert!(!services.is_empty(), "had {listener_count} listeners, 0 services");
        }
    }

    #[test]
    fn flows_are_established_only() {
        use netcore::link::TcpState;
        let b = NetlinkBackend::new();
        let flows = b.flows().expect("flows");
        for f in &flows {
            assert!(matches!(f.state, TcpState::Established), "non-Established flow");
            // Established flows must have a remote peer.
            assert!(!f.remote.ip().is_unspecified());
        }
    }
}
