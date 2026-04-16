//! `jip` (no args) — one-line per connection plus a health summary.

use netcore::connection::{Connection, Medium};
use netcore::diag::Health;
use netcore::link::{LinkKind, OperState};

pub fn overview(conns: &[Connection], health: &Health, all: bool) {
    let visible: Vec<&Connection> = conns.iter().filter(|c| all || keep_default(c)).collect();

    println!("{:<14} {:<8} {:<10} {:<22} {:<22} GATEWAY", "NAME", "KIND", "STATE", "IPv4", "IPv6");
    for c in &visible {
        let name = &c.link.name;
        let kind = kind_label(&c.link.kind);
        let state = state_label(c);
        let v4 = c
            .primary_v4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into());
        let v6 = c
            .primary_v6
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into());
        let gw = c
            .gateway
            .as_ref()
            .map(|g| g.ip.to_string())
            .unwrap_or_else(|| "-".into());
        println!("{name:<14} {kind:<8} {state:<10} {v4:<22} {v6:<22} {gw}");
    }
    println!();
    match health {
        Health::Ok => println!("Health: OK"),
        Health::Degraded { findings } => {
            println!("Health: DEGRADED ({} finding{})", findings.len(), plural(findings.len()));
            for f in findings.iter().take(3) {
                println!("  - {}", f.summary);
            }
        }
        Health::Broken { findings } => {
            println!("Health: BROKEN ({} finding{})", findings.len(), plural(findings.len()));
            for f in findings.iter().take(3) {
                println!("  - {}", f.summary);
            }
        }
    }
}

fn keep_default(c: &Connection) -> bool {
    // Hide loopback and bridge/veth noise by default.
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

fn kind_label(kind: &LinkKind) -> String {
    match kind {
        LinkKind::Ethernet => "eth".into(),
        LinkKind::Wifi => "wifi".into(),
        LinkKind::Loopback => "lo".into(),
        LinkKind::Bridge => "bridge".into(),
        LinkKind::Veth => "veth".into(),
        LinkKind::Tun => "tun".into(),
        LinkKind::Tap => "tap".into(),
        LinkKind::Wireguard => "wg".into(),
        LinkKind::Vlan => "vlan".into(),
        LinkKind::Bond => "bond".into(),
        LinkKind::Other(s) => s.clone(),
    }
}

fn state_label(c: &Connection) -> &'static str {
    match c.link.state {
        OperState::Up => match &c.medium {
            Medium::Wifi { .. } => "UP-wifi",
            _ => "UP",
        },
        OperState::Down => "DOWN",
        OperState::Dormant => "DORMANT",
        OperState::Unknown => "UNKNOWN",
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
