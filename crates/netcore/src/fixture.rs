//! In-memory fixture backend for tests and development.
//!
//! [`Fixture::this_machine`] reproduces the live topology of the development
//! host as of writing (eth0 dual-stack with 10 IPv6 addresses, dormant
//! wifi, linkdown docker0, loopback). [`Fixture::gateway_down`] is the same
//! topology with the gateway's neighbor entry in [`NeighState::Failed`] so
//! the diagnostician can be exercised against a realistic failure case.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::Result;
use crate::connection::{
    Connection, ConnectionId, DhcpLease, Family, Gateway, Medium, Profile, VirtualKind,
};
use crate::diag::{FirewallBackend, FirewallVerdict, PingOpts, ProbeCapabilities, TraceOpts};
use crate::dns::{DnsAnswer, DnsError, DnsResolution, DnsSource};
use crate::link::{
    Addr, AddrScope, L4Proto, Lifetime, Link, LinkFlags, LinkKind, LinkMode, MacAddr, NeighState,
    Neighbor, OperState, Route, RouteDst, RouteScope, Socket, TcpState,
};
use crate::path::{Egress, Hop, HttpProbeResult, PingResult, TcpProbeResult, TlsProbeResult};
use crate::process::{ProcessInfo, ProcessRef};
use crate::service::{BindScope, Exposure, Flow, Service};
use crate::traits::{Firewall, Inventory, InventoryRaw, Reachability, Resolver};

/// Snapshot of a host's network state, matching every capability trait.
///
/// Fields are `pub` so tests can tweak specific pieces (e.g. flip a neighbor
/// state from `Reachable` to `Failed`) without rebuilding the whole topology.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub links: Vec<Link>,
    pub addrs: Vec<(u32, Addr)>,
    pub routes: Vec<Route>,
    pub neighbors: Vec<Neighbor>,
    pub sockets: Vec<Socket>,
    pub connections: Vec<Connection>,
    pub services: Vec<Service>,
    pub flows: Vec<Flow>,
    /// Pre-canned answers keyed by target string form (`"github.com"`,
    /// `"1.1.1.1"`). Backends match on `Target::Ip(..)` / `Target::Host(..)`
    /// via their string form.
    pub dns_answers: HashMap<String, DnsResolution>,
    /// Per-connection DNS servers. Keyed by connection id string.
    pub dns_per_link: HashMap<String, Vec<IpAddr>>,
    pub stub: Option<IpAddr>,
    /// `ip route get` answers by destination.
    pub egress_table: HashMap<IpAddr, Egress>,
    /// Ping results keyed by destination.
    pub ping_results: HashMap<IpAddr, PingResult>,
    /// TCP-connect results keyed by target socket address.
    pub tcp_results: HashMap<SocketAddr, TcpProbeResult>,
    /// Firewall verdicts keyed by (port, proto).
    pub firewall: HashMap<(u16, L4Proto), FirewallVerdict>,
    pub firewall_backend: FirewallBackend,
    pub capabilities: ProbeCapabilities,
}

impl Fixture {
    /// The development machine's topology: eth0 UP dual-stack with the
    /// gateway reachable, wifi dormant, docker0 down.
    pub fn this_machine() -> Self {
        let enp = Link {
            name: "eth0".into(),
            index: 2,
            kind: LinkKind::Ethernet,
            mac: Some(MacAddr([0xd8, 0x43, 0xae, 0xa6, 0x49, 0x23])),
            mtu: 1500,
            state: OperState::Up,
            linkmode: LinkMode::Default,
            flags: LinkFlags(vec![
                "BROADCAST".into(),
                "MULTICAST".into(),
                "UP".into(),
                "LOWER_UP".into(),
            ]),
        };
        let wlp = Link {
            name: "wlan0".into(),
            index: 3,
            kind: LinkKind::Wifi,
            mac: Some(MacAddr([0x58, 0xcd, 0xc9, 0x12, 0x0b, 0x1d])),
            mtu: 1500,
            state: OperState::Down,
            linkmode: LinkMode::Dormant,
            flags: LinkFlags(vec![
                "NO-CARRIER".into(),
                "BROADCAST".into(),
                "MULTICAST".into(),
                "UP".into(),
            ]),
        };
        let docker = Link {
            name: "docker0".into(),
            index: 4,
            kind: LinkKind::Bridge,
            mac: Some(MacAddr([0xd2, 0xdc, 0xba, 0x6b, 0x72, 0xb4])),
            mtu: 1500,
            state: OperState::Down,
            linkmode: LinkMode::Default,
            flags: LinkFlags(vec![
                "NO-CARRIER".into(),
                "BROADCAST".into(),
                "MULTICAST".into(),
                "UP".into(),
            ]),
        };
        let lo = Link {
            name: "lo".into(),
            index: 1,
            kind: LinkKind::Loopback,
            mac: Some(MacAddr([0; 6])),
            mtu: 65536,
            state: OperState::Unknown,
            linkmode: LinkMode::Default,
            flags: LinkFlags(vec!["LOOPBACK".into(), "UP".into(), "LOWER_UP".into()]),
        };

        let enp_v4 = Addr {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143)),
            prefix: 24,
            scope: AddrScope::Global,
            dynamic: true,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: true,
            valid_lft: Lifetime::Seconds(31312),
            preferred_lft: Lifetime::Seconds(31312),
            label: Some("eth0".into()),
        };
        let enp_v6_primary = Addr {
            ip: "2001:db8:1:0:c53a:1abf:eec5:38b3".parse().unwrap(),
            prefix: 64,
            scope: AddrScope::Global,
            dynamic: true,
            temporary: true,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: false,
            valid_lft: Lifetime::Seconds(536576),
            preferred_lft: Lifetime::Seconds(18130),
            label: None,
        };
        let enp_v6_stable = Addr {
            ip: "2001:db8:1::fe3".parse().unwrap(),
            prefix: 128,
            scope: AddrScope::Global,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: true,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: None,
        };
        let enp_v6_mngtmp = Addr {
            ip: "2001:db8:1:0:f1fd:af04:74a2:6dad".parse().unwrap(),
            prefix: 64,
            scope: AddrScope::Global,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: true,
            noprefixroute: true,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: None,
        };
        let enp_v6_ll = Addr {
            ip: "fe80::aaaa:bbbb:cccc:dddd".parse().unwrap(),
            prefix: 64,
            scope: AddrScope::Link,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: true,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: None,
        };
        let enp_v6_deprecated: Vec<Addr> = [
            "2001:db8:1:0:1a49:e256:4568:bb09",
            "2001:db8:1:0:8481:899b:c9a7:f719",
            "2001:db8:1:0:435a:39ea:ba0e:7e3c",
            "2001:db8:1:0:2677:64d0:7dbe:9d99",
            "2001:db8:1:0:6248:6b8e:6430:5297",
            "2001:db8:1:0:244b:7148:40da:f0ce",
        ]
        .iter()
        .map(|s| Addr {
            ip: s.parse().unwrap(),
            prefix: 64,
            scope: AddrScope::Global,
            dynamic: true,
            temporary: true,
            deprecated: true,
            mngtmpaddr: false,
            noprefixroute: false,
            valid_lft: Lifetime::Seconds(450000),
            preferred_lft: Lifetime::Seconds(0),
            label: None,
        })
        .collect();

        let docker_v4 = Addr {
            ip: IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)),
            prefix: 16,
            scope: AddrScope::Global,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: false,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: Some("docker0".into()),
        };
        let lo_v4 = Addr {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            prefix: 8,
            scope: AddrScope::Host,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: false,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: Some("lo".into()),
        };
        let lo_v6 = Addr {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 128,
            scope: AddrScope::Host,
            dynamic: false,
            temporary: false,
            deprecated: false,
            mngtmpaddr: false,
            noprefixroute: false,
            valid_lft: Lifetime::Forever,
            preferred_lft: Lifetime::Forever,
            label: None,
        };

        let mut addrs: Vec<(u32, Addr)> = vec![
            (1, lo_v4.clone()),
            (1, lo_v6.clone()),
            (2, enp_v4.clone()),
            (2, enp_v6_primary.clone()),
        ];
        addrs.extend(enp_v6_deprecated.iter().cloned().map(|a| (2, a)));
        addrs.push((2, enp_v6_stable.clone()));
        addrs.push((2, enp_v6_mngtmp.clone()));
        addrs.push((2, enp_v6_ll.clone()));
        addrs.push((4, docker_v4.clone()));

        let routes = vec![
            Route {
                dst: RouteDst::Default,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                oif: Some("eth0".into()),
                metric: Some(100),
                table: 254,
                protocol: "dhcp".into(),
                scope: RouteScope::Universe,
                prefsrc: None,
                flags: vec![],
            },
            Route {
                dst: RouteDst::Prefix {
                    ip: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
                    prefix: 16,
                },
                gateway: None,
                oif: Some("eth0".into()),
                metric: Some(1000),
                table: 254,
                protocol: "boot".into(),
                scope: RouteScope::Link,
                prefsrc: None,
                flags: vec![],
            },
            Route {
                dst: RouteDst::Prefix {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    prefix: 24,
                },
                gateway: None,
                oif: Some("eth0".into()),
                metric: Some(100),
                table: 254,
                protocol: "kernel".into(),
                scope: RouteScope::Link,
                prefsrc: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143))),
                flags: vec![],
            },
        ];

        let neighbors = vec![
            Neighbor {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                lladdr: Some(MacAddr([0x98, 0xde, 0xd0, 0x24, 0x76, 0xb6])),
                oif: "eth0".into(),
                state: NeighState::Reachable,
                is_router: true,
            },
            Neighbor {
                ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                lladdr: None,
                oif: "eth0".into(),
                state: NeighState::Failed,
                is_router: false,
            },
        ];

        let sshd = Socket {
            proto: L4Proto::Tcp,
            local: SocketAddr::from(([0u8, 0, 0, 0], 22)),
            remote: None,
            state: TcpState::Listen,
            process: ProcessInfo::PermissionDenied,
            bound_iface: None,
        };
        let py8000 = Socket {
            proto: L4Proto::Tcp,
            local: SocketAddr::from(([0u8, 0, 0, 0], 8000)),
            remote: None,
            state: TcpState::Listen,
            process: ProcessInfo::Known(ProcessRef {
                pid: 36095,
                comm: "python3".into(),
            }),
            bound_iface: None,
        };
        let sockets = vec![sshd, py8000];

        let enp_connection = Connection {
            id: ConnectionId("Wired connection 1".into()),
            medium: Medium::Ethernet,
            link: enp.clone(),
            addresses: {
                let mut v = vec![enp_v4.clone(), enp_v6_primary.clone()];
                v.extend(enp_v6_deprecated.iter().cloned());
                v.push(enp_v6_stable.clone());
                v.push(enp_v6_mngtmp.clone());
                v.push(enp_v6_ll.clone());
                v
            },
            primary_v4: Some(enp_v4.ip),
            primary_v6: Some(enp_v6_primary.ip),
            v4_lease: Some(DhcpLease {
                expires_in: Duration::from_secs(31312),
                server: None,
            }),
            gateway: Some(Gateway {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                lladdr: Some(MacAddr([0x98, 0xde, 0xd0, 0x24, 0x76, 0xb6])),
                l2_state: NeighState::Reachable,
                is_router: true,
            }),
            dns: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            is_default: true,
            default_metric: Some(100),
            profile: Some(Profile {
                name: "Wired connection 1".into(),
                uuid: String::new(),
                autoconnect: true,
                kind: "802-3-ethernet".into(),
                iface: Some("eth0".into()),
                active: true,
            }),
        };
        let wlp_connection = Connection {
            id: ConnectionId("wlan0".into()),
            medium: Medium::Wifi {
                ssid: None,
                signal: None,
                security: None,
            },
            link: wlp.clone(),
            addresses: vec![],
            primary_v4: None,
            primary_v6: None,
            v4_lease: None,
            gateway: None,
            dns: vec![],
            is_default: false,
            default_metric: None,
            profile: None,
        };
        let docker_connection = Connection {
            id: ConnectionId("docker0".into()),
            medium: Medium::Virtual {
                kind: VirtualKind::Docker,
            },
            link: docker.clone(),
            addresses: vec![docker_v4.clone()],
            primary_v4: Some(docker_v4.ip),
            primary_v6: None,
            v4_lease: None,
            gateway: None,
            dns: vec![],
            is_default: false,
            default_metric: None,
            profile: Some(Profile {
                name: "docker0".into(),
                uuid: String::new(),
                autoconnect: true,
                kind: "bridge".into(),
                iface: Some("docker0".into()),
                active: false,
            }),
        };
        let lo_connection = Connection {
            id: ConnectionId("lo".into()),
            medium: Medium::Loopback,
            link: lo.clone(),
            addresses: vec![lo_v4.clone(), lo_v6.clone()],
            primary_v4: Some(lo_v4.ip),
            primary_v6: Some(lo_v6.ip),
            v4_lease: None,
            gateway: None,
            dns: vec![],
            is_default: false,
            default_metric: None,
            profile: None,
        };

        let services = vec![
            Service {
                port: 22,
                proto: L4Proto::Tcp,
                bind: BindScope::AnyAddress,
                process: ProcessInfo::PermissionDenied,
                exposure: Exposure::Exposed,
            },
            Service {
                port: 8000,
                proto: L4Proto::Tcp,
                bind: BindScope::AnyAddress,
                process: ProcessInfo::Known(ProcessRef {
                    pid: 36095,
                    comm: "python3".into(),
                }),
                exposure: Exposure::Exposed,
            },
            Service {
                port: 5432,
                proto: L4Proto::Tcp,
                bind: BindScope::Loopback,
                process: ProcessInfo::PermissionDenied,
                exposure: Exposure::LocalOnly,
            },
        ];

        let mut dns_answers: HashMap<String, DnsResolution> = HashMap::new();
        dns_answers.insert(
            "github.com".into(),
            DnsResolution {
                queried: "github.com".into(),
                via: DnsSource::Stub(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))),
                upstream_used: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                answers: vec![DnsAnswer {
                    ip: IpAddr::V4(Ipv4Addr::new(20, 27, 177, 113)),
                    family: Family::V4,
                    ttl: Some(60),
                }],
                took: Duration::from_millis(2),
                cached: true,
                authenticated: false,
                error: None,
            },
        );
        dns_answers.insert(
            "cloudflare.com".into(),
            DnsResolution {
                queried: "cloudflare.com".into(),
                via: DnsSource::Stub(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))),
                upstream_used: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                answers: vec![DnsAnswer {
                    ip: IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)),
                    family: Family::V4,
                    ttl: Some(300),
                }],
                took: Duration::from_millis(3),
                cached: true,
                authenticated: false,
                error: None,
            },
        );
        dns_answers.insert(
            "nxdomain.example".into(),
            DnsResolution {
                queried: "nxdomain.example".into(),
                via: DnsSource::Stub(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))),
                upstream_used: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                answers: vec![],
                took: Duration::from_millis(12),
                cached: false,
                authenticated: false,
                error: Some(DnsError::NxDomain),
            },
        );

        let mut dns_per_link: HashMap<String, Vec<IpAddr>> = HashMap::new();
        dns_per_link.insert(
            "Wired connection 1".into(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        );

        let mut egress_table: HashMap<IpAddr, Egress> = HashMap::new();
        egress_table.insert(
            IpAddr::V4(Ipv4Addr::new(20, 27, 177, 113)),
            Egress {
                connection_id: ConnectionId("Wired connection 1".into()),
                iface: "eth0".into(),
                src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143)),
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                family_used: Family::V4,
                family_unreachable: vec![Family::V6],
                uid_scoped: true,
            },
        );
        egress_table.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 159)),
            Egress {
                connection_id: ConnectionId("Wired connection 1".into()),
                iface: "eth0".into(),
                src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 143)),
                gateway: None,
                family_used: Family::V4,
                family_unreachable: vec![],
                uid_scoped: true,
            },
        );

        let mut ping_results: HashMap<IpAddr, PingResult> = HashMap::new();
        ping_results.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            PingResult {
                sent: 2,
                received: 2,
                rtt_min: Some(Duration::from_micros(143)),
                rtt_avg: Some(Duration::from_micros(197)),
                rtt_max: Some(Duration::from_micros(251)),
            },
        );

        let mut tcp_results: HashMap<SocketAddr, TcpProbeResult> = HashMap::new();
        let github = SocketAddr::from(([20, 27, 177, 113], 443));
        tcp_results.insert(
            github,
            TcpProbeResult {
                addr: github,
                connected: true,
                took: Duration::from_millis(42),
                error: None,
            },
        );
        let canary = SocketAddr::from(([1, 1, 1, 1], 443));
        tcp_results.insert(
            canary,
            TcpProbeResult {
                addr: canary,
                connected: true,
                took: Duration::from_millis(18),
                error: None,
            },
        );

        let mut firewall: HashMap<(u16, L4Proto), FirewallVerdict> = HashMap::new();
        firewall.insert((22, L4Proto::Tcp), FirewallVerdict::Allow);
        firewall.insert((8000, L4Proto::Tcp), FirewallVerdict::Allow);

        Fixture {
            links: vec![lo, enp, wlp, docker],
            addrs,
            routes,
            neighbors,
            sockets,
            connections: vec![
                enp_connection,
                wlp_connection,
                docker_connection,
                lo_connection,
            ],
            services,
            flows: vec![],
            dns_answers,
            dns_per_link,
            stub: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))),
            egress_table,
            ping_results,
            tcp_results,
            firewall,
            firewall_backend: FirewallBackend::Nftables,
            capabilities: ProbeCapabilities {
                has_ping: true,
                has_traceroute: true,
                has_mtr: true,
                has_tracepath: true,
                unprivileged_icmp: true,
            },
        }
    }

    /// Same topology, but the gateway's neighbor entry is `FAILED` and the
    /// gateway ping times out.
    pub fn gateway_down() -> Self {
        let mut f = Self::this_machine();
        for n in &mut f.neighbors {
            if n.ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)) {
                n.state = NeighState::Failed;
                n.lladdr = None;
            }
        }
        for c in &mut f.connections {
            if let Some(g) = c.gateway.as_mut() {
                if g.ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)) {
                    g.l2_state = NeighState::Failed;
                    g.lladdr = None;
                }
            }
        }
        f.ping_results.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            PingResult {
                sent: 2,
                received: 0,
                rtt_min: None,
                rtt_avg: None,
                rtt_max: None,
            },
        );
        f
    }
}

impl InventoryRaw for Fixture {
    fn links(&self) -> Result<Vec<Link>> {
        Ok(self.links.clone())
    }
    fn addrs(&self) -> Result<Vec<(u32, Addr)>> {
        Ok(self.addrs.clone())
    }
    fn routes(&self) -> Result<Vec<Route>> {
        Ok(self.routes.clone())
    }
    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        Ok(self.neighbors.clone())
    }
    fn sockets(&self) -> Result<Vec<Socket>> {
        Ok(self.sockets.clone())
    }
}

impl Inventory for Fixture {
    fn connections(&self) -> Result<Vec<Connection>> {
        Ok(self.connections.clone())
    }
    fn services(&self) -> Result<Vec<Service>> {
        Ok(self.services.clone())
    }
    fn flows(&self) -> Result<Vec<Flow>> {
        Ok(self.flows.clone())
    }
    fn egress_for(&self, dst: IpAddr) -> Result<Egress> {
        self.egress_table
            .get(&dst)
            .cloned()
            .ok_or_else(|| crate::Error::NotFound(format!("no egress for {dst}")))
    }
}

impl Resolver for Fixture {
    fn resolve(&self, name: &str) -> Result<DnsResolution> {
        self.dns_answers
            .get(name)
            .cloned()
            .ok_or_else(|| crate::Error::NotFound(format!("fixture has no answer for {name}")))
    }
    fn servers_for(&self, conn: &ConnectionId) -> Result<Vec<IpAddr>> {
        Ok(self.dns_per_link.get(&conn.0).cloned().unwrap_or_default())
    }
    fn stub_server(&self) -> Result<Option<IpAddr>> {
        Ok(self.stub)
    }
}

impl Reachability for Fixture {
    fn ping(&self, ip: IpAddr, _opts: PingOpts) -> Result<PingResult> {
        self.ping_results
            .get(&ip)
            .cloned()
            .ok_or_else(|| crate::Error::NotFound(format!("no ping fixture for {ip}")))
    }
    fn tcp_connect(&self, sa: SocketAddr, _timeout: Duration) -> Result<TcpProbeResult> {
        self.tcp_results
            .get(&sa)
            .cloned()
            .ok_or_else(|| crate::Error::NotFound(format!("no tcp fixture for {sa}")))
    }
    fn tls_handshake(
        &self,
        sa: SocketAddr,
        sni: &str,
        _timeout: Duration,
    ) -> Result<TlsProbeResult> {
        Ok(TlsProbeResult {
            peer: sa,
            sni: sni.to_owned(),
            negotiated: true,
            took: Duration::from_millis(35),
            error: None,
        })
    }
    fn http_head(&self, url: &Url, _timeout: Duration) -> Result<HttpProbeResult> {
        Ok(HttpProbeResult {
            url: url.to_string(),
            status: Some(200),
            took: Duration::from_millis(60),
            error: None,
        })
    }
    fn trace(&self, _ip: IpAddr, _opts: TraceOpts) -> Result<Vec<Hop>> {
        Ok(vec![])
    }
    fn capabilities(&self) -> ProbeCapabilities {
        self.capabilities.clone()
    }
}

impl Firewall for Fixture {
    fn verdict_for_inbound(&self, port: u16, proto: L4Proto) -> Result<FirewallVerdict> {
        Ok(self
            .firewall
            .get(&(port, proto))
            .copied()
            .unwrap_or(FirewallVerdict::Unknown))
    }
    fn backend(&self) -> FirewallBackend {
        self.firewall_backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_default_connection() {
        let f = Fixture::this_machine();
        let default: Vec<_> = f.connections.iter().filter(|c| c.is_default).collect();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].link.name, "eth0");
    }

    #[test]
    fn gateway_down_fixture_flips_neighbor_state() {
        let ok = Fixture::this_machine();
        let dn = Fixture::gateway_down();
        let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ok_state = ok.neighbors.iter().find(|n| n.ip == gw).unwrap().state;
        let dn_state = dn.neighbors.iter().find(|n| n.ip == gw).unwrap().state;
        assert_eq!(ok_state, NeighState::Reachable);
        assert_eq!(dn_state, NeighState::Failed);
        let p = dn.ping(gw, PingOpts::default()).unwrap();
        assert_eq!(p.received, 0);
    }

    #[test]
    fn resolver_returns_preloaded_answers() {
        let f = Fixture::this_machine();
        let r = f.resolve("github.com").unwrap();
        assert_eq!(r.answers.len(), 1);
        let nx = f.resolve("nxdomain.example").unwrap();
        assert_eq!(nx.error, Some(DnsError::NxDomain));
    }
}
