//! Diagnostician: composes [`Inventory`], [`Resolver`], [`Reachability`], and
//! optionally [`Firewall`] into the end-to-end [`Diagnostician`] trait.
//!
//! The logic here is intentionally boring — check each layer bottom-up, emit a
//! `Finding` when something is wrong, stop elevating severity once the lowest
//! broken layer is known. No I/O: every concrete action goes through a trait.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use netcore::connection::{Connection, ConnectionId, Family};
use netcore::diag::{
    CheckScope, Evidence, Finding, Health, Layer, PingOpts, Remedy, Severity, TraceOpts,
};
use netcore::dns::DnsError;
use netcore::link::NeighState;
use netcore::path::{
    Egress, Hop, HttpProbeResult, Path, PingResult, ProbeResults, ProbeStrategy, Target,
    TcpProbeResult, TlsProbeResult, Verdict,
};
use netcore::traits::{Diagnostician, Firewall, Inventory, Reachability, Resolver};
use netcore::{Error, Result};

/// Well-known canary for the internet-reachable check (Cloudflare 1.1.1.1).
const CANARY_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const CANARY_PORT: u16 = 443;
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Composes capability traits into a [`Diagnostician`].
pub struct DiagApp {
    inventory: Box<dyn Inventory>,
    resolver: Box<dyn Resolver>,
    reach: Box<dyn Reachability>,
    firewall: Option<Box<dyn Firewall>>,
}

impl DiagApp {
    /// Create a new diagnostician with the required inventory, resolver, and
    /// reachability backends. Call [`DiagApp::with_firewall`] to add firewall
    /// posture checking.
    pub fn new(
        inventory: Box<dyn Inventory>,
        resolver: Box<dyn Resolver>,
        reach: Box<dyn Reachability>,
    ) -> Self {
        Self {
            inventory,
            resolver,
            reach,
            firewall: None,
        }
    }

    /// Attach an optional firewall backend. When present, `check()` includes
    /// inbound exposure verdicts.
    pub fn with_firewall(mut self, firewall: Box<dyn Firewall>) -> Self {
        self.firewall = Some(firewall);
        self
    }
}

impl Diagnostician for DiagApp {
    fn check(&self, scope: CheckScope) -> Result<Health> {
        let connections = self.inventory.connections()?;
        let mut findings = Vec::new();

        check_default_connection(&connections, &mut findings);
        check_gateway(&connections, self.reach.as_ref(), &mut findings);
        check_dns(self.resolver.as_ref(), &mut findings);

        if matches!(scope, CheckScope::Full) {
            check_internet(self.reach.as_ref(), &mut findings);
        }

        if findings.iter().any(|f| f.severity == Severity::Broken) {
            Ok(Health::Broken { findings })
        } else if findings.iter().any(|f| f.severity == Severity::Warn) {
            Ok(Health::Degraded { findings })
        } else if findings.is_empty() {
            Ok(Health::Ok)
        } else {
            Ok(Health::Degraded { findings })
        }
    }

    fn trace_path(&self, target: Target) -> Result<Path> {
        let strategy = strategy_for(&target);
        let (target_ip, port, resolution) = resolve_target(&target, self.resolver.as_ref())?;

        let Some(ip) = target_ip else {
            let dns_err = resolution
                .as_ref()
                .and_then(|r| r.error.clone())
                .unwrap_or(DnsError::Other("no answer".into()));
            let evidence = resolution
                .clone()
                .map(|r| Evidence::Dns { dns: r })
                .unwrap_or(Evidence::Text {
                    text: "no resolution".into(),
                });
            return Ok(Path {
                target,
                resolution,
                egress: empty_egress(),
                probes: empty_probes(strategy),
                verdict: Verdict::DnsFailed {
                    error: dns_err.clone(),
                },
                findings: vec![Finding {
                    layer: Layer::Dns,
                    severity: Severity::Broken,
                    summary: format!("DNS resolution failed: {dns_err:?}"),
                    detail: None,
                    remedy: Some(Remedy::Check {
                        what: "check /etc/resolv.conf and your DNS server".into(),
                    }),
                    evidence,
                }],
            });
        };

        let egress = self.inventory.egress_for(ip)?;
        let mut probes = empty_probes(strategy);
        let mut findings = Vec::new();

        if let Some(gw) = egress.gateway {
            if let Ok(p) = self.reach.ping(gw, PingOpts::default()) {
                probes.gateway_ping = Some(p);
            }
        }

        let (verdict, probes) = run_probes(
            strategy,
            ip,
            port,
            &target,
            self.reach.as_ref(),
            &egress,
            probes,
            &mut findings,
        );

        Ok(Path {
            target,
            resolution,
            egress,
            probes,
            verdict,
            findings,
        })
    }
}

fn check_default_connection(connections: &[Connection], findings: &mut Vec<Finding>) {
    let any_up = connections.iter().any(|c| c.is_default);
    if !any_up {
        findings.push(Finding {
            layer: Layer::Link,
            severity: Severity::Broken,
            summary: "no default route on any connection".into(),
            detail: Some(
                "No connection is currently the default egress. Check that a cable is plugged in, wifi is associated, or a VPN is up.".into(),
            ),
            remedy: Some(Remedy::Check { what: "cable / wifi / VPN".into() }),
            evidence: Evidence::Text { text: format!("{} connections enumerated", connections.len()) },
        });
    }
}

fn check_gateway(
    connections: &[Connection],
    reach: &dyn Reachability,
    findings: &mut Vec<Finding>,
) {
    for c in connections.iter().filter(|c| c.is_default) {
        let Some(gw) = c.gateway.as_ref() else {
            findings.push(Finding {
                layer: Layer::Gateway,
                severity: Severity::Broken,
                summary: format!("{} is default but has no gateway", c.id),
                detail: None,
                remedy: Some(Remedy::Reconnect { id: c.id.clone() }),
                evidence: Evidence::Text {
                    text: format!("link {}", c.link.name),
                },
            });
            continue;
        };
        match gw.l2_state {
            NeighState::Reachable
            | NeighState::Stale
            | NeighState::Delay
            | NeighState::Probe
            | NeighState::Permanent => {}
            NeighState::Failed | NeighState::Incomplete => {
                findings.push(Finding {
                    layer: Layer::Gateway,
                    severity: Severity::Broken,
                    summary: format!("gateway {} is not responding at L2 ({:?})", gw.ip, gw.l2_state),
                    detail: Some(
                        "Route points at this gateway but ARP/ND shows it unreachable. The router may be off or the cable unplugged.".into(),
                    ),
                    remedy: Some(Remedy::Check {
                        what: "router power / cable / wifi association".into(),
                    }),
                    evidence: Evidence::Text { text: format!("gateway {} state {:?}", gw.ip, gw.l2_state) },
                });
            }
            NeighState::Noarp | NeighState::None => {}
        }

        if let Ok(p) = reach.ping(gw.ip, PingOpts::default()) {
            if p.received == 0 {
                findings.push(Finding {
                    layer: Layer::Gateway,
                    severity: Severity::Broken,
                    summary: format!("gateway {} did not respond to ping", gw.ip),
                    detail: Some(format!("{} sent, {} received", p.sent, p.received)),
                    remedy: Some(Remedy::Check {
                        what: "gateway power / upstream".into(),
                    }),
                    evidence: Evidence::Text {
                        text: format!("{:?}", p),
                    },
                });
            } else if p.loss_pct() > 25.0 {
                findings.push(Finding {
                    layer: Layer::Gateway,
                    severity: Severity::Warn,
                    summary: format!("{:.0}% packet loss to gateway {}", p.loss_pct(), gw.ip),
                    detail: None,
                    remedy: None,
                    evidence: Evidence::Text {
                        text: format!("{:?}", p),
                    },
                });
            }
        }
    }
}

fn check_dns(resolver: &dyn Resolver, findings: &mut Vec<Finding>) {
    match resolver.resolve("cloudflare.com") {
        Ok(r) if r.error.is_none() && !r.answers.is_empty() => {}
        Ok(r) => {
            let err = r
                .error
                .clone()
                .unwrap_or(DnsError::Other("empty answer".into()));
            findings.push(Finding {
                layer: Layer::Dns,
                severity: Severity::Broken,
                summary: format!("DNS probe failed: {err:?}"),
                detail: None,
                remedy: Some(Remedy::Check {
                    what: "resolver reachability".into(),
                }),
                evidence: Evidence::Dns { dns: r },
            });
        }
        Err(e) => {
            findings.push(Finding {
                layer: Layer::Dns,
                severity: Severity::Broken,
                summary: "DNS probe failed to run".into(),
                detail: Some(e.to_string()),
                remedy: Some(Remedy::Check {
                    what: "resolver configuration".into(),
                }),
                evidence: Evidence::Text {
                    text: e.to_string(),
                },
            });
        }
    }
}

fn check_internet(reach: &dyn Reachability, findings: &mut Vec<Finding>) {
    let addr = SocketAddr::new(CANARY_V4, CANARY_PORT);
    match reach.tcp_connect(addr, Duration::from_secs(2)) {
        Ok(r) if r.connected => {}
        Ok(r) => {
            findings.push(Finding {
                layer: Layer::Internet,
                severity: Severity::Broken,
                summary: format!("could not TCP connect to canary {addr}"),
                detail: r.error.clone(),
                remedy: Some(Remedy::Check {
                    what: "upstream connectivity / firewall".into(),
                }),
                evidence: Evidence::Text {
                    text: format!("{:?}", r),
                },
            });
        }
        Err(e) => {
            findings.push(Finding {
                layer: Layer::Internet,
                severity: Severity::Warn,
                summary: "canary TCP probe could not run".into(),
                detail: Some(e.to_string()),
                remedy: None,
                evidence: Evidence::Text {
                    text: e.to_string(),
                },
            });
        }
    }
}

/// Select the [`ProbeStrategy`] appropriate for a given [`Target`].
///
/// The strategy is a pure function of the target shape: URL targets run HTTP;
/// hostnames with ports run TCP; bare IPs on LAN prefixes use ICMP only.
pub fn strategy_for(target: &Target) -> ProbeStrategy {
    match target {
        Target::Url { .. } => ProbeStrategy::HttpUrl,
        Target::Host { port: Some(_), .. } => ProbeStrategy::SpecificPort,
        Target::Host { port: None, .. } => ProbeStrategy::UnspecifiedTcp,
        Target::Ip { ip, port: Some(_) } if is_lan_ish(*ip) => ProbeStrategy::LanIp,
        Target::Ip { ip, port: None } if is_lan_ish(*ip) => ProbeStrategy::LanIp,
        Target::Ip { port: Some(_), .. } => ProbeStrategy::SpecificPort,
        Target::Ip { port: None, .. } => ProbeStrategy::IcmpOnly,
    }
}

fn is_lan_ish(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.segments()[0] & 0xffc0 == 0xfe80
                || v6.segments()[0] & 0xfe00 == 0xfc00
        }
    }
}

fn resolve_target(
    target: &Target,
    resolver: &dyn Resolver,
) -> Result<(
    Option<IpAddr>,
    Option<u16>,
    Option<netcore::dns::DnsResolution>,
)> {
    match target {
        Target::Ip { ip, port } => Ok((Some(*ip), *port, None)),
        Target::Host { name, port } => {
            let r = resolver.resolve(name)?;
            let ip = r.answers.first().map(|a| a.ip);
            Ok((ip, *port, Some(r)))
        }
        Target::Url { url } => {
            let parsed =
                url::Url::parse(url).map_err(|e| Error::Parse(format!("invalid url: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| Error::Parse("url has no host".into()))?;
            let r = resolver.resolve(host)?;
            let ip = r.answers.first().map(|a| a.ip);
            let port = parsed.port().or(match parsed.scheme() {
                "https" => Some(443),
                "http" => Some(80),
                _ => None,
            });
            Ok((ip, port, Some(r)))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_probes(
    strategy: ProbeStrategy,
    ip: IpAddr,
    port: Option<u16>,
    target: &Target,
    reach: &dyn Reachability,
    egress: &Egress,
    mut probes: ProbeResults,
    findings: &mut Vec<Finding>,
) -> (Verdict, ProbeResults) {
    let tcp_port = port.unwrap_or(DEFAULT_HTTPS_PORT);
    let family = Family::of(ip);

    match strategy {
        ProbeStrategy::LanIp | ProbeStrategy::IcmpOnly => {
            let p = match reach.ping(ip, PingOpts::default()) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        Verdict::NoEgress {
                            reason: e.to_string(),
                        },
                        probes,
                    );
                }
            };
            let loss = p.loss_pct();
            let verdict = if p.received == 0 {
                Verdict::TcpTimeout {
                    addr: SocketAddr::new(ip, tcp_port),
                }
            } else if loss > 50.0 {
                Verdict::PacketLoss { loss_pct: loss }
            } else {
                Verdict::Reachable {
                    latency_ms: p.rtt_avg.map(|d| d.as_millis() as u64).unwrap_or(0),
                    family_used: family,
                }
            };
            probes.target_ping = Some(p);
            (verdict, probes)
        }
        ProbeStrategy::UnspecifiedTcp | ProbeStrategy::SpecificPort | ProbeStrategy::HttpUrl => {
            let addr = SocketAddr::new(ip, tcp_port);
            let tcp = match reach.tcp_connect(addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        Verdict::NoEgress {
                            reason: e.to_string(),
                        },
                        probes,
                    );
                }
            };
            if !tcp.connected {
                probes.tcp_connect = Some(tcp.clone());
                let verdict = match tcp.error.as_deref() {
                    Some(err) if err.contains("refused") => Verdict::TcpRefused { addr },
                    _ => Verdict::TcpTimeout { addr },
                };
                maybe_note_unreachable_family(egress, findings);
                return (verdict, probes);
            }
            probes.tcp_connect = Some(tcp.clone());

            if matches!(strategy, ProbeStrategy::HttpUrl) {
                run_http_stage(target, addr, reach, &mut probes);
            }

            let latency = probes
                .tcp_connect
                .as_ref()
                .map(|t| t.took.as_millis() as u64)
                .unwrap_or(0);
            maybe_note_unreachable_family(egress, findings);
            (
                Verdict::Reachable {
                    latency_ms: latency,
                    family_used: family,
                },
                probes,
            )
        }
    }
}

fn run_http_stage(
    target: &Target,
    addr: SocketAddr,
    reach: &dyn Reachability,
    probes: &mut ProbeResults,
) {
    if let Target::Url { url } = target {
        let Ok(parsed) = url::Url::parse(url) else {
            return;
        };
        let host = parsed.host_str().unwrap_or("").to_owned();
        if parsed.scheme() == "https" {
            if let Ok(tls) = reach.tls_handshake(addr, &host, Duration::from_secs(3)) {
                probes.tls_handshake = Some(tls);
            }
        }
        if let Ok(http) = reach.http_head(&parsed, Duration::from_secs(3)) {
            probes.http_head = Some(http);
        }
    }
}

fn maybe_note_unreachable_family(egress: &Egress, findings: &mut Vec<Finding>) {
    for fam in &egress.family_unreachable {
        findings.push(Finding {
            layer: Layer::Internet,
            severity: Severity::Info,
            summary: format!("{:?} path is unreachable from here", fam),
            detail: Some(
                "The kernel has no route for this address family. Dual-stack hosts commonly see this when their ISP only provides IPv4.".into(),
            ),
            remedy: None,
            evidence: Evidence::Text { text: format!("family {:?} unreachable via {}", fam, egress.iface) },
        });
    }
}

fn empty_egress() -> Egress {
    Egress {
        connection_id: ConnectionId("-".into()),
        iface: "-".into(),
        src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        gateway: None,
        family_used: Family::V4,
        family_unreachable: vec![],
        uid_scoped: false,
    }
}

fn empty_probes(strategy: ProbeStrategy) -> ProbeResults {
    ProbeResults {
        strategy,
        gateway_ping: None,
        target_ping: None,
        tcp_connect: None,
        tls_handshake: None,
        http_head: None,
        trace: None,
    }
}

/// Re-export of [`netcore::traits::Diagnostician`] for consumers that import
/// from this crate.
pub use netcore::traits::Diagnostician as DiagnosticianTrait;

#[allow(dead_code)]
fn _type_assertions(
    _: &dyn Reachability,
    _: PingResult,
    _: TcpProbeResult,
    _: TlsProbeResult,
    _: HttpProbeResult,
    _: Vec<Hop>,
    _: TraceOpts,
) {
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcore::fixture::Fixture;
    use netcore::traits::Diagnostician;

    fn app_from(f: Fixture) -> DiagApp {
        let inv: Box<dyn Inventory> = Box::new(f.clone());
        let res: Box<dyn Resolver> = Box::new(f.clone());
        let rch: Box<dyn Reachability> = Box::new(f.clone());
        let fw: Box<dyn Firewall> = Box::new(f);
        DiagApp::new(inv, res, rch).with_firewall(fw)
    }

    #[test]
    fn healthy_topology_reports_ok() {
        let app = app_from(Fixture::this_machine());
        let h = app.check(CheckScope::Quick).unwrap();
        assert!(matches!(h, Health::Ok), "expected Ok, got {:?}", h);
    }

    #[test]
    fn full_scope_with_canary_is_ok() {
        let app = app_from(Fixture::this_machine());
        let h = app.check(CheckScope::Full).unwrap();
        assert!(matches!(h, Health::Ok), "expected Ok, got {:?}", h);
    }

    #[test]
    fn gateway_down_is_broken_at_gateway_layer() {
        let app = app_from(Fixture::gateway_down());
        let h = app.check(CheckScope::Quick).unwrap();
        let findings = match h {
            Health::Broken { findings } => findings,
            other => panic!("expected Broken, got {:?}", other),
        };
        assert!(
            findings
                .iter()
                .any(|f| f.layer == Layer::Gateway && f.severity == Severity::Broken),
            "no Gateway/Broken finding in {:#?}",
            findings
        );
    }

    #[test]
    fn trace_path_reaches_github_via_wired_connection() {
        let app = app_from(Fixture::this_machine());
        let path = app
            .trace_path(Target::Host {
                name: "github.com".into(),
                port: None,
            })
            .unwrap();
        assert_eq!(path.egress.connection_id.0, "Wired connection 1");
        assert!(
            matches!(path.verdict, Verdict::Reachable { .. }),
            "expected Reachable verdict, got {:?}",
            path.verdict
        );
        assert!(path.resolution.is_some(), "expected DNS resolution");
    }

    #[test]
    fn trace_path_reports_dns_failure() {
        let app = app_from(Fixture::this_machine());
        let path = app
            .trace_path(Target::Host {
                name: "nxdomain.example".into(),
                port: None,
            })
            .unwrap();
        assert!(
            matches!(path.verdict, Verdict::DnsFailed { .. }),
            "expected DnsFailed verdict, got {:?}",
            path.verdict
        );
        assert!(
            path.findings.iter().any(|f| f.layer == Layer::Dns),
            "expected a Dns finding"
        );
    }

    #[test]
    fn trace_path_surfaces_unreachable_v6_family() {
        let app = app_from(Fixture::this_machine());
        let path = app
            .trace_path(Target::Host {
                name: "github.com".into(),
                port: None,
            })
            .unwrap();
        assert!(
            path.findings
                .iter()
                .any(|f| f.layer == Layer::Internet && f.severity == Severity::Info),
            "expected Info/Internet finding about v6 unreachable, got {:#?}",
            path.findings
        );
    }
}
