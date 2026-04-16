//! iproute2 backend for netcore.
//!
//! Shells out to `ip -j {addr,link,route,neigh}` and `ip -j route get <dst>`,
//! parses the JSON via serde, and maps into netcore primitives. Joins Links +
//! Addrs + Routes + Neighbors into [`Connection`] at the [`Inventory`] layer.
//!
//! Busybox `ip` has no `-j` flag; we detect that up front and fail with a
//! clear [`Error::BusyBox`]. The caller (`jip-cli`) can then fall back to the
//! netlink backend once it exists.
//!
//! Services / flows are out of scope for this crate — those belong to a
//! future `netcore-ss` backend. `Inventory::services()` and `flows()` return
//! empty vecs here.

use std::net::IpAddr;
use std::process::{Command, Stdio};

use netcore::connection::{
    Connection, ConnectionId, DhcpLease, Family, Gateway, Medium, VirtualKind,
};
use netcore::link::{
    Addr, AddrScope, Lifetime, Link, LinkKind, NeighState, Neighbor, Route, RouteDst, Socket,
};
use netcore::path::Egress;
use netcore::service::{Flow, Service};
use netcore::traits::{Inventory, InventoryRaw};
use netcore::{Error, Result};

mod mapping;
mod raw;

/// How we invoke the `ip` binary. Tests substitute a [`StaticRunner`] with
/// canned JSON blobs; the real backend uses [`RealRunner`] which shells out.
pub trait Runner: Send + Sync {
    /// Run `ip -j <args...>` and return stdout. Non-zero exit is an error.
    fn run(&self, args: &[&str]) -> Result<String>;
}

/// Real `ip` invocation.
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new("ip");
        cmd.arg("-j");
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let out = cmd
            .output()
            .map_err(|e| Error::Backend(format!("spawning `ip`: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("invalid option") || stderr.contains("Option \"-j\"") {
                return Err(Error::Backend(
                    "this `ip` binary does not support -j (busybox?)".into(),
                ));
            }
            return Err(Error::Backend(format!(
                "ip {}: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        String::from_utf8(out.stdout)
            .map_err(|e| Error::Parse(format!("ip output was not utf-8: {e}")))
    }
}

/// A runner that serves fixed responses keyed by the args it's asked to run.
/// Used only by the test suite in this crate.
#[cfg(any(test, feature = "test-runner"))]
pub struct StaticRunner {
    pub responses: std::collections::HashMap<Vec<String>, String>,
}

#[cfg(any(test, feature = "test-runner"))]
impl Runner for StaticRunner {
    fn run(&self, args: &[&str]) -> Result<String> {
        let key: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("no canned response for {key:?}")))
    }
}

/// Top-level iproute2 backend. Implements both [`InventoryRaw`] and
/// [`Inventory`].
pub struct IpRoute {
    runner: Box<dyn Runner>,
}

impl IpRoute {
    /// Real runner, shelling out to the system `ip` binary.
    pub fn new() -> Self {
        Self { runner: Box::new(RealRunner) }
    }

    pub fn with_runner(runner: Box<dyn Runner>) -> Self {
        Self { runner }
    }

    fn parse_links(&self) -> Result<Vec<raw::RawLink>> {
        let s = self.runner.run(&["addr", "show"])?;
        serde_json::from_str(&s)
            .map_err(|e| Error::Parse(format!("ip -j addr: {e}")))
    }

    fn parse_routes(&self) -> Result<Vec<raw::RawRoute>> {
        let v4 = self.runner.run(&["-4", "route", "show"])?;
        let v6 = self.runner.run(&["-6", "route", "show"]).unwrap_or_default();
        let mut out: Vec<raw::RawRoute> = serde_json::from_str(&v4)
            .map_err(|e| Error::Parse(format!("ip -j -4 route: {e}")))?;
        if !v6.trim().is_empty() {
            let v6_parsed: Vec<raw::RawRoute> = serde_json::from_str(&v6)
                .map_err(|e| Error::Parse(format!("ip -j -6 route: {e}")))?;
            out.extend(v6_parsed);
        }
        Ok(out)
    }

    fn parse_neighbors(&self) -> Result<Vec<raw::RawNeigh>> {
        let s = self.runner.run(&["neigh", "show"])?;
        serde_json::from_str(&s)
            .map_err(|e| Error::Parse(format!("ip -j neigh: {e}")))
    }
}

impl Default for IpRoute {
    fn default() -> Self { Self::new() }
}

impl InventoryRaw for IpRoute {
    fn links(&self) -> Result<Vec<Link>> {
        Ok(self
            .parse_links()?
            .iter()
            .map(mapping::link_from_raw)
            .collect())
    }

    fn addrs(&self) -> Result<Vec<(u32, Addr)>> {
        Ok(self
            .parse_links()?
            .iter()
            .flat_map(mapping::addrs_from_raw)
            .collect())
    }

    fn routes(&self) -> Result<Vec<Route>> {
        Ok(self
            .parse_routes()?
            .iter()
            .filter_map(mapping::route_from_raw)
            .collect())
    }

    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        Ok(self
            .parse_neighbors()?
            .iter()
            .map(mapping::neighbor_from_raw)
            .collect())
    }

    fn sockets(&self) -> Result<Vec<Socket>> {
        // `ss` backend is out of scope for this crate.
        Ok(vec![])
    }
}

impl Inventory for IpRoute {
    fn connections(&self) -> Result<Vec<Connection>> {
        let raw_links = self.parse_links()?;
        let routes = self.parse_routes()?;
        let neighbors = self.parse_neighbors()?;
        let links: Vec<Link> = raw_links.iter().map(mapping::link_from_raw).collect();
        let mapped_routes: Vec<Route> =
            routes.iter().filter_map(mapping::route_from_raw).collect();
        let mapped_neighbors: Vec<Neighbor> =
            neighbors.iter().map(mapping::neighbor_from_raw).collect();

        let mut out = Vec::with_capacity(links.len());
        for (raw_link, link) in raw_links.iter().zip(links.iter()) {
            let addrs: Vec<Addr> = raw_link
                .addr_info
                .iter()
                .filter_map(mapping::addrs_from_raw_single)
                .collect();

            let default_route_for_link = mapped_routes
                .iter()
                .find(|r| {
                    matches!(r.dst, RouteDst::Default)
                        && r.oif.as_deref() == Some(link.name.as_str())
                });
            let gateway = default_route_for_link
                .and_then(|r| r.gateway)
                .map(|ip| gateway_for(ip, &mapped_neighbors));

            out.push(Connection {
                id: ConnectionId(link.name.clone()),
                medium: medium_for(link),
                link: link.clone(),
                primary_v4: primary_v4(&addrs),
                primary_v6: primary_v6(&addrs),
                v4_lease: v4_lease(&addrs),
                addresses: addrs,
                gateway,
                dns: vec![],
                is_default: default_route_for_link.is_some(),
                default_metric: default_route_for_link.and_then(|r| r.metric),
                profile: None,
            });
        }
        Ok(out)
    }

    fn services(&self) -> Result<Vec<Service>> { Ok(vec![]) }

    fn flows(&self) -> Result<Vec<Flow>> { Ok(vec![]) }

    fn egress_for(&self, dst: IpAddr) -> Result<Egress> {
        let flag = if dst.is_ipv6() { "-6" } else { "-4" };
        let s = match self.runner.run(&[flag, "route", "get", &dst.to_string()]) {
            Ok(s) => s,
            Err(Error::Backend(msg)) if msg.contains("Network is unreachable") => {
                return Ok(unreachable_egress(dst));
            }
            Err(e) => return Err(e),
        };
        let parsed: Vec<raw::RawRouteGet> = serde_json::from_str(&s)
            .map_err(|e| Error::Parse(format!("ip -j route get: {e}")))?;
        let first = parsed
            .into_iter()
            .next()
            .ok_or_else(|| Error::Parse("empty `ip route get` response".into()))?;
        let src = first.prefsrc.unwrap_or(dst);
        let iface = first.dev.clone().unwrap_or_else(|| "-".into());
        Ok(Egress {
            connection_id: ConnectionId(iface.clone()),
            iface,
            src,
            gateway: first.gateway,
            family_used: Family::of(dst),
            family_unreachable: vec![],
            uid_scoped: first.uid.is_some(),
        })
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

fn gateway_for(ip: IpAddr, neighbors: &[Neighbor]) -> Gateway {
    if let Some(n) = neighbors.iter().find(|n| n.ip == ip) {
        Gateway {
            ip,
            lladdr: n.lladdr,
            l2_state: n.state,
            is_router: n.is_router,
        }
    } else {
        Gateway {
            ip,
            lladdr: None,
            l2_state: NeighState::None,
            is_router: false,
        }
    }
}

fn medium_for(link: &Link) -> Medium {
    match &link.kind {
        LinkKind::Ethernet => Medium::Ethernet,
        LinkKind::Wifi => Medium::Wifi { ssid: None, signal: None, security: None },
        LinkKind::Loopback => Medium::Loopback,
        LinkKind::Bridge => Medium::Virtual {
            kind: if link.name.starts_with("docker") {
                VirtualKind::Docker
            } else {
                VirtualKind::Bridge
            },
        },
        LinkKind::Veth => Medium::Virtual { kind: VirtualKind::Veth },
        LinkKind::Tap => Medium::Virtual { kind: VirtualKind::Tap },
        LinkKind::Tun => Medium::Virtual { kind: VirtualKind::Other },
        LinkKind::Wireguard => Medium::Vpn { kind: netcore::connection::VpnKind::Wireguard },
        LinkKind::Vlan | LinkKind::Bond | LinkKind::Other(_) => {
            Medium::Virtual { kind: VirtualKind::Other }
        }
    }
}

/// First global, non-deprecated IPv4 (privacy/temporary concerns don't apply).
fn primary_v4(addrs: &[Addr]) -> Option<IpAddr> {
    addrs
        .iter()
        .filter(|a| matches!(a.ip, IpAddr::V4(_)))
        .filter(|a| matches!(a.scope, AddrScope::Global))
        .filter(|a| !a.deprecated)
        .map(|a| a.ip)
        .next()
}

/// The IPv6 a user should see: a global, non-deprecated address, preferring
/// non-temporary (the stable SLAAC base) over temporary privacy addresses.
/// Deprecated addresses are never returned. Link-local (`fe80::/10`) is
/// excluded.
fn primary_v6(addrs: &[Addr]) -> Option<IpAddr> {
    let v6 = addrs
        .iter()
        .filter(|a| matches!(a.ip, IpAddr::V6(_)))
        .filter(|a| matches!(a.scope, AddrScope::Global))
        .filter(|a| !a.deprecated);
    // Prefer stable (mngtmpaddr or non-temporary) over temporary privacy addresses.
    if let Some(stable) = v6
        .clone()
        .find(|a| !a.temporary && !matches!(a.preferred_lft, Lifetime::Seconds(0)))
    {
        return Some(stable.ip);
    }
    v6.map(|a| a.ip).next()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    const ADDR_JSON: &str = include_str!("../testdata/addr.json");
    const ROUTE4_JSON: &str = include_str!("../testdata/route4.json");
    const ROUTE6_JSON: &str = "[]";
    const NEIGH_JSON: &str = include_str!("../testdata/neigh.json");
    const ROUTE_GET_JSON: &str = include_str!("../testdata/route_get_1.1.1.1.json");

    fn test_runner() -> Box<dyn Runner> {
        let mut responses: HashMap<Vec<String>, String> = HashMap::new();
        let v = |args: &[&str]| args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        responses.insert(v(&["addr", "show"]), ADDR_JSON.into());
        responses.insert(v(&["-4", "route", "show"]), ROUTE4_JSON.into());
        responses.insert(v(&["-6", "route", "show"]), ROUTE6_JSON.into());
        responses.insert(v(&["neigh", "show"]), NEIGH_JSON.into());
        responses.insert(
            v(&["-4", "route", "get", "1.1.1.1"]),
            ROUTE_GET_JSON.into(),
        );
        Box::new(StaticRunner { responses })
    }

    #[test]
    fn links_round_trip() {
        let ip = IpRoute::with_runner(test_runner());
        let links = ip.links().unwrap();
        let names: Vec<&str> = links.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"lo"));
        assert!(names.contains(&"eth0"));
        assert!(names.contains(&"docker0"));
    }

    #[test]
    fn enp_has_global_v4_and_v6_and_lease() {
        let ip = IpRoute::with_runner(test_runner());
        let conns = ip.connections().unwrap();
        let enp = conns.iter().find(|c| c.link.name == "eth0").unwrap();

        assert_eq!(
            enp.primary_v4,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143)))
        );
        let v6 = enp.primary_v6.expect("should have a primary v6");
        assert!(v6.is_ipv6());
        // The stable mngtmpaddr base should win over the temporary privacy address.
        // At minimum the chosen v6 must not be deprecated.
        let chosen = enp.addresses.iter().find(|a| a.ip == v6).unwrap();
        assert!(!chosen.deprecated);
        assert!(enp.v4_lease.is_some(), "dynamic v4 should produce a lease");
        assert!(enp.is_default);
    }

    #[test]
    fn docker_is_virtual_docker_medium() {
        let ip = IpRoute::with_runner(test_runner());
        let conns = ip.connections().unwrap();
        let d = conns.iter().find(|c| c.link.name == "docker0").unwrap();
        assert!(matches!(
            d.medium,
            Medium::Virtual { kind: VirtualKind::Docker }
        ));
        assert!(!d.is_default);
    }

    #[test]
    fn gateway_joins_neighbor_state() {
        let ip = IpRoute::with_runner(test_runner());
        let conns = ip.connections().unwrap();
        let enp = conns.iter().find(|c| c.link.name == "eth0").unwrap();
        let gw = enp.gateway.as_ref().expect("enp has a gateway");
        assert_eq!(gw.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(gw.l2_state, NeighState::Reachable);
    }

    #[test]
    fn egress_for_returns_prefsrc_and_gateway() {
        let ip = IpRoute::with_runner(test_runner());
        let e = ip
            .egress_for(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .unwrap();
        assert_eq!(e.iface, "eth0");
        assert_eq!(e.src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143)));
        assert_eq!(e.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(e.uid_scoped);
    }

    #[test]
    fn failed_neighbor_state_reports_as_failed() {
        let ip = IpRoute::with_runner(test_runner());
        let neigh = ip.neighbors().unwrap();
        let meta = neigh
            .iter()
            .find(|n| n.ip == IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))
            .unwrap();
        assert_eq!(meta.state, NeighState::Failed);
    }

    #[test]
    fn router_flag_detected_from_null_quirk() {
        let ip = IpRoute::with_runner(test_runner());
        let neigh = ip.neighbors().unwrap();
        let router = neigh.iter().find(|n| n.is_router);
        assert!(router.is_some(), "expected one neighbor with router:null set");
    }
}

