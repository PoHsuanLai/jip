#[cfg(not(target_os = "linux"))]
compile_error!("jip currently supports Linux only");

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use netcore::connection::{Connection, ConnectionId};
use netcore::diag::CheckScope;
use netcore::path::Target;
use netcore::service::{Exposure, Service};
use netcore::traits::{Actions, Diagnostician, Firewall, Inventory, InventoryRaw};
use netcore_diag::DiagApp;
use netcore_firewall::NftBackend;
use netcore_netlink::NetlinkBackend;
use netcore_nm::NmBackend;
use netcore_probe::ProbeBackend;
use netcore_resolver::ResolverBackend;

mod render;
mod theme;

#[derive(Parser, Debug)]
#[command(
    name = "jip",
    version,
    about = "modern Linux network CLI",
    long_about = "jip shows and diagnoses Linux networking — connections, paths, services. \
                  Run with no args for a quick health snapshot; `jip check` for full diagnosis; \
                  `jip reach <target>` to trace a specific flow."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    /// Disable default filters (shows loopback, docker, APIPA, etc.).
    #[arg(long, global = true)]
    all: bool,

    /// Show IPv4 only.
    #[arg(short = '4', global = true, conflicts_with = "v6_only")]
    v4_only: bool,

    /// Show IPv6 only.
    #[arg(short = '6', global = true)]
    v6_only: bool,
}

/// Family filter selected by `-4` / `-6` / neither.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FamilyFilter {
    All,
    V4Only,
    V6Only,
}

impl FamilyFilter {
    fn from_flags(v4: bool, v6: bool) -> Self {
        match (v4, v6) {
            (true, _) => Self::V4Only,
            (_, true) => Self::V6Only,
            _ => Self::All,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Full diagnosis. Walks each layer and reports the first broken thing.
    Check,
    /// Probe reachability to a target: IP, host, host:port, or URL.
    Reach {
        target: String,
    },
    /// Print kernel primitives directly (equivalent to `ip addr` etc.).
    Raw {
        #[command(subcommand)]
        what: RawKind,
    },
    /// List listening services with exposure (firewall-aware).
    Listen,
    /// Show established flows (which processes are talking to whom).
    Who,
    /// Activate an NM profile (equivalent to `nmcli con up`).
    Use {
        /// Profile name or UUID.
        profile: String,
    },
    /// Bounce an NM profile (deactivate + activate).
    Reconnect {
        profile: String,
    },
    /// Delete an NM profile from disk.
    Forget {
        profile: String,
    },
}

#[derive(Subcommand, Debug)]
enum RawKind {
    Addr,
    Link,
    Route,
    Neigh,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // JSON output is byte-for-byte stable; don't touch terminal state in
    // that mode so `jip --json | jq` is deterministic across envs.
    if !cli.json {
        theme::init();
    }
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("jip: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let json = cli.json;
    let all = cli.all;
    let family = FamilyFilter::from_flags(cli.v4_only, cli.v6_only);
    match cli.cmd {
        None => overview(json, all, family),
        Some(Cmd::Check) => check(json),
        Some(Cmd::Reach { target }) => reach(&target, json),
        Some(Cmd::Raw { what }) => raw(what, json),
        Some(Cmd::Listen) => listen(json),
        Some(Cmd::Who) => who(json),
        Some(Cmd::Use { profile }) => nm_action(ActionKind::Prefer, &profile),
        Some(Cmd::Reconnect { profile }) => nm_action(ActionKind::Reconnect, &profile),
        Some(Cmd::Forget { profile }) => nm_action(ActionKind::Forget, &profile),
    }
}

enum ActionKind { Prefer, Reconnect, Forget }

fn nm_action(kind: ActionKind, profile: &str) -> anyhow::Result<ExitCode> {
    let Some(nm) = NmBackend::new() else {
        anyhow::bail!("NetworkManager isn't running on this system");
    };
    let id = ConnectionId(profile.to_string());
    match kind {
        ActionKind::Prefer => nm.prefer(&id)?,
        ActionKind::Reconnect => nm.reconnect(&id)?,
        ActionKind::Forget => nm.forget(&id)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn overview(json: bool, all: bool, family: FamilyFilter) -> anyhow::Result<ExitCode> {
    let inv = NetlinkBackend::new();
    let mut conns = inv.connections()?;
    enrich_with_nm_profiles(&mut conns);
    let diag = build_diag();
    let health = diag.check(CheckScope::Quick)?;
    if json {
        render::json::overview(&conns, &health)?;
    } else {
        render::connection::overview(&conns, &health, all, family);
    }
    Ok(ExitCode::SUCCESS)
}

/// Attach NM `Profile` to each `Connection` by matching iface name.
/// Silent no-op when NM isn't running or the lookup fails — the netlink
/// view is authoritative for everything else.
fn enrich_with_nm_profiles(conns: &mut [Connection]) {
    let Some(nm) = NmBackend::new() else { return };
    let Ok(by_iface) = nm.profiles_by_iface() else { return };
    for c in conns {
        if let Some(p) = by_iface.get(&c.link.name) {
            c.profile = Some(p.clone());
        }
    }
}

fn listen(json: bool) -> anyhow::Result<ExitCode> {
    let inv = NetlinkBackend::new();
    let mut services = inv.services()?;
    enrich_with_firewall(&mut services);
    if json {
        println!("{}", serde_json::to_string_pretty(&services)?);
    } else {
        render::listen::listen(&services);
    }
    Ok(ExitCode::SUCCESS)
}

fn who(json: bool) -> anyhow::Result<ExitCode> {
    let inv = NetlinkBackend::new();
    let flows = inv.flows()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&flows)?);
    } else {
        render::who::who(&flows);
    }
    Ok(ExitCode::SUCCESS)
}

/// Populate each service's [`Exposure`] from the current nftables ruleset.
/// No-op (leaves `Exposure::Unknown`) when `nft` isn't usable — root-only,
/// and the firewall backend itself decides whether to surface any verdict.
fn enrich_with_firewall(services: &mut [Service]) {
    let fw = NftBackend::new();
    for s in services {
        if !matches!(s.exposure, Exposure::Unknown) { continue; }
        let Ok(verdict) = fw.verdict_for_inbound(s.port, s.proto) else { continue };
        s.exposure = Exposure::from_scope_and_verdict(&s.bind, verdict);
    }
}

fn check(json: bool) -> anyhow::Result<ExitCode> {
    let diag = build_diag();
    let health = diag.check(CheckScope::Full)?;
    if json {
        render::json::health(&health)?;
    } else {
        render::check::print(&health);
    }
    let code = if matches!(&health, netcore::diag::Health::Broken { .. }) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    };
    Ok(code)
}

fn reach(target_str: &str, json: bool) -> anyhow::Result<ExitCode> {
    let target = parse_target(target_str)?;
    let diag = build_diag();
    let path = diag.trace_path(target)?;
    if json {
        render::json::path(&path)?;
    } else {
        render::reach::print(&path);
    }
    let code = match &path.verdict {
        netcore::path::Verdict::Reachable { .. } => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    };
    Ok(code)
}

fn raw(what: RawKind, json: bool) -> anyhow::Result<ExitCode> {
    let inv = NetlinkBackend::new();
    match what {
        RawKind::Addr => {
            let links = inv.links()?;
            let addrs = inv.addrs()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&addrs)?);
            } else {
                render::raw::addrs(&links, &addrs);
            }
        }
        RawKind::Link => {
            let links = inv.links()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&links)?);
            } else {
                render::raw::links(&links);
            }
        }
        RawKind::Route => {
            let routes = inv.routes()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&routes)?);
            } else {
                render::raw::routes(&routes);
            }
        }
        RawKind::Neigh => {
            let neigh = inv.neighbors()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&neigh)?);
            } else {
                render::raw::neighbors(&neigh);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn build_diag() -> DiagApp {
    DiagApp::new(
        Box::new(NetlinkBackend::new()),
        Box::new(ResolverBackend::new()),
        Box::new(ProbeBackend::new()),
    )
}

/// Parse a user-supplied target string into a `Target`. Accepts:
///   - "1.1.1.1", "::1"                       → Ip{port: None}
///   - "1.1.1.1:443", "[::1]:22"              → Ip{port: Some}
///   - "github.com", "github.com:22"          → Host
///   - "https://github.com/", "http://..."    → Url
fn parse_target(s: &str) -> anyhow::Result<Target> {
    if s.starts_with("http://") || s.starts_with("https://") {
        return Ok(Target::Url { url: s.to_string() });
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(Target::Ip { ip: sa.ip(), port: Some(sa.port()) });
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Target::Ip { ip, port: None });
    }
    // host or host:port. Split from the right so IPv6 literals (which we
    // already handled above) don't get confused.
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok(Target::Host { name: host.to_string(), port: Some(port) });
        }
    }
    Ok(Target::Host { name: s.to_string(), port: None })
}
