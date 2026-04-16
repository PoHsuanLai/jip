//! `jip` (no args) — one row per connection, plus a health summary.

use std::net::IpAddr;

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Style, object::Rows, themes::Colorization, Color as TabColor},
};

use netcore::connection::{Connection, Medium};
use netcore::diag::Health;
use netcore::link::{AddrScope, LinkKind, NeighState, OperState};

use crate::FamilyFilter;
use crate::theme;

pub fn overview(conns: &[Connection], health: &Health, all: bool, family: FamilyFilter) {
    let visible: Vec<&Connection> = conns.iter().filter(|c| all || keep_default(c)).collect();

    let rows: Vec<[String; 7]> = visible
        .iter()
        .map(|c| {
            [
                c.link.name.clone(),
                kind_cell(c),
                state_cell(c),
                v4_cell(c, family),
                v6_cell(c, family),
                gateway_cell(c),
                profile_cell(c),
            ]
        })
        .collect();

    if theme::is_plain() {
        // Tab-separated, no header — friendly to awk/cut/grep.
        for row in &rows {
            println!("{}", row.join("\t"));
        }
    } else {
        let mut b = Builder::default();
        b.push_record(["NAME", "KIND", "STATE", "IPv4", "IPv6", "GATEWAY", "PROFILE"]);
        for row in &rows {
            b.push_record(row);
        }
        let mut table = b.build();
        table.with(Style::blank());
        let header_color = TabColor::BOLD | TabColor::UNDERLINE;
        table.with(Colorization::exact([header_color], Rows::first()));
        println!("{table}");
        println!();
    }
    print_health_line(health);
}

fn print_health_line(health: &Health) {
    match health {
        Health::Ok => {
            let s = theme::ok();
            println!("Health: {s}OK{s:#}");
        }
        Health::Degraded { findings } => {
            let s = theme::warn();
            println!(
                "Health: {s}DEGRADED{s:#} ({} finding{})",
                findings.len(),
                plural(findings.len())
            );
            for f in findings.iter().take(3) {
                println!("  - {}", f.summary);
            }
        }
        Health::Broken { findings } => {
            let s = theme::bad();
            println!(
                "Health: {s}BROKEN{s:#} ({} finding{})",
                findings.len(),
                plural(findings.len())
            );
            for f in findings.iter().take(3) {
                println!("  - {}", f.summary);
            }
        }
    }
}

fn v4_cell(c: &Connection, family: FamilyFilter) -> String {
    if family == FamilyFilter::V6Only { return theme::dim_placeholder("-"); }
    match c.primary_v4 {
        Some(ip) => ip.to_string(),
        None => theme::dim_placeholder("-"),
    }
}

/// Primary IPv6 + "+N hidden" suffix counting other global IPv6s on this
/// link. `::1`, link-local (scope != Global), and deprecated addresses
/// don't count — users care about "how many real outgoing addresses are
/// there that I'm not seeing?".
fn v6_cell(c: &Connection, family: FamilyFilter) -> String {
    if family == FamilyFilter::V4Only { return theme::dim_placeholder("-"); }
    let primary = match c.primary_v6 {
        Some(ip) => ip,
        None => return theme::dim_placeholder("-"),
    };
    let extra = c
        .addresses
        .iter()
        .filter(|a| matches!(a.ip, IpAddr::V6(_)))
        .filter(|a| matches!(a.scope, AddrScope::Global))
        .filter(|a| !a.deprecated)
        .filter(|a| a.ip != primary)
        .count();
    if extra == 0 || theme::is_plain() {
        // Plain mode: only the primary IP. Pipe consumers get the full
        // address list via `jip --json` or `jip raw addr`.
        primary.to_string()
    } else {
        let d = theme::dim();
        format!("{primary} {d}+{extra} hidden{d:#}")
    }
}

fn profile_cell(c: &Connection) -> String {
    match &c.profile {
        None => theme::dim_placeholder("-"),
        Some(p) => {
            // Append "(manual)" when autoconnect is off so it's visible
            // at a glance why an otherwise-configured link doesn't come
            // up on boot.
            if p.autoconnect {
                p.name.clone()
            } else {
                format!("{} {}", p.name, theme::paint(theme::dim(), "(manual)"))
            }
        }
    }
}

fn gateway_cell(c: &Connection) -> String {
    let Some(g) = c.gateway.as_ref() else { return theme::dim_placeholder("-"); };
    let ip = g.ip.to_string();
    // Color the IP by the gateway's ARP state — that's the whole reason
    // we carry NeighState alongside the route target.
    match g.l2_state {
        NeighState::Reachable | NeighState::Permanent => theme::paint(theme::ok_soft(), ip),
        NeighState::Failed | NeighState::Incomplete => theme::paint(theme::bad(), ip),
        NeighState::Stale | NeighState::Delay | NeighState::Probe => {
            theme::paint(theme::warn(), ip)
        }
        NeighState::Noarp | NeighState::None => ip,
    }
}

fn keep_default(c: &Connection) -> bool {
    match c.link.kind {
        LinkKind::Loopback => false,
        LinkKind::Bridge | LinkKind::Veth | LinkKind::Tun | LinkKind::Tap
            if matches!(c.link.state, OperState::Down | OperState::Dormant) =>
        {
            false
        }
        _ => true,
    }
}

fn kind_label(kind: &LinkKind) -> &'static str {
    match kind {
        LinkKind::Ethernet => "eth",
        LinkKind::Wifi => "wifi",
        LinkKind::Loopback => "lo",
        LinkKind::Bridge => "bridge",
        LinkKind::Veth => "veth",
        LinkKind::Tun => "tun",
        LinkKind::Tap => "tap",
        LinkKind::Wireguard => "wg",
        LinkKind::Vlan => "vlan",
        LinkKind::Bond => "bond",
        LinkKind::Other(_) => "other",
    }
}

/// For wifi links, suffix the associated SSID and signal so the user can
/// tell "connected to 'home', -54 dBm" apart from "wifi, radio up but no
/// association". Non-wifi links fall through to the bare kind label.
fn kind_cell(c: &Connection) -> String {
    let base = kind_label(&c.link.kind);
    match &c.medium {
        Medium::Wifi { ssid: Some(name), signal, .. } => match signal {
            Some(s) => format!("{base} {name} ({} dBm)", s.rssi_dbm),
            None => format!("{base} {name}"),
        },
        _ => base.into(),
    }
}

fn state_cell(c: &Connection) -> String {
    let (label, style) = match c.link.state {
        OperState::Up => {
            let l = match &c.medium {
                Medium::Wifi { .. } => "UP-wifi",
                _ => "UP",
            };
            (l, theme::ok())
        }
        OperState::Down => ("DOWN", theme::bad()),
        OperState::Dormant => ("DORMANT", theme::warn()),
        OperState::Unknown => ("UNKNOWN", theme::dim()),
    };
    theme::paint(style, label)
}

fn plural(n: usize) -> &'static str { if n == 1 { "" } else { "s" } }
