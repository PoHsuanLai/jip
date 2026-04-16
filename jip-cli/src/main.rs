#[cfg(not(target_os = "linux"))]
compile_error!("jip currently supports Linux only");

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use netcore::diag::CheckScope;
use netcore::path::Target;
use netcore::traits::{Diagnostician, Inventory, InventoryRaw};
use netcore_diag::DiagApp;
use netcore_netlink::NetlinkBackend;
use netcore_probe::ProbeBackend;
use netcore_resolver::ResolverBackend;

mod render;

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
    match cli.cmd {
        None => overview(json, all),
        Some(Cmd::Check) => check(json),
        Some(Cmd::Reach { target }) => reach(&target, json),
        Some(Cmd::Raw { what }) => raw(what, json),
    }
}

fn overview(json: bool, all: bool) -> anyhow::Result<ExitCode> {
    let inv = NetlinkBackend::new();
    let conns = inv.connections()?;
    let diag = build_diag();
    let health = diag.check(CheckScope::Quick)?;
    if json {
        render::json::overview(&conns, &health)?;
    } else {
        render::connection::overview(&conns, &health, all);
    }
    Ok(ExitCode::SUCCESS)
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
