//! `jip raw *` — primitives in an ip-compatible-ish form.

use anstream::println;
use netcore::link::{Addr, Link, Neighbor, Route, RouteDst};

/// Print a list of links in a format similar to `ip link show`.
pub fn links(links: &[Link]) {
    for l in links {
        println!(
            "{}: <{}> mtu {} state {:?} mode {:?}",
            l.name,
            l.flags.0.join(","),
            l.mtu,
            l.state,
            l.linkmode,
        );
        if let Some(mac) = &l.mac {
            println!("    link/ether {}", mac);
        }
        println!("    kind: {:?}", l.kind);
    }
}

/// Print a list of addresses grouped by link, similar to `ip addr show`.
pub fn addrs(links: &[Link], addrs: &[(u32, Addr)]) {
    for l in links {
        let mine: Vec<&Addr> = addrs
            .iter()
            .filter(|(i, _)| *i == l.index)
            .map(|(_, a)| a)
            .collect();
        if mine.is_empty() {
            continue;
        }
        println!("{}: (index {})", l.name, l.index);
        for a in mine {
            println!(
                "    {}/{}  scope {:?}  {}{}{}",
                a.ip,
                a.prefix,
                a.scope,
                if a.dynamic { "dynamic " } else { "" },
                if a.temporary { "temporary " } else { "" },
                if a.deprecated { "deprecated " } else { "" },
            );
        }
    }
}

/// Print a list of routes in a format similar to `ip route show`.
pub fn routes(routes: &[Route]) {
    for r in routes {
        let dst = match &r.dst {
            RouteDst::Default => "default".to_string(),
            RouteDst::Prefix { ip, prefix } => format!("{ip}/{prefix}"),
        };
        let via = r.gateway.map(|g| format!(" via {g}")).unwrap_or_default();
        let dev = r
            .oif
            .as_deref()
            .map(|d| format!(" dev {d}"))
            .unwrap_or_default();
        let metric = r.metric.map(|m| format!(" metric {m}")).unwrap_or_default();
        let proto = format!(" proto {}", r.protocol);
        println!("{dst}{via}{dev}{metric}{proto}");
    }
}

/// Print a list of ARP/ND neighbor entries, similar to `ip neigh show`.
pub fn neighbors(neigh: &[Neighbor]) {
    for n in neigh {
        let lladdr = n
            .lladdr
            .as_ref()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{} dev {} lladdr {} {:?}{}",
            n.ip,
            n.oif,
            lladdr,
            n.state,
            if n.is_router { " ROUTER" } else { "" }
        );
    }
}
