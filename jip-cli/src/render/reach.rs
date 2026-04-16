//! `jip reach <target>` — target + path + verdict.

use anstream::println;
use netcore::path::{Path, Verdict};

use crate::theme;

pub fn print(path: &Path) {
    match &path.target {
        netcore::path::Target::Ip { ip, port } => match port {
            Some(p) => println!("target: {ip}:{p}"),
            None => println!("target: {ip}"),
        },
        netcore::path::Target::Host { name, port } => match port {
            Some(p) => println!("target: {name}:{p}"),
            None => println!("target: {name}"),
        },
        netcore::path::Target::Url { url } => println!("target: {url}"),
    }
    if let Some(r) = &path.resolution {
        print!("dns:    {} via {:?}", r.queried, r.via);
        if let Some(u) = &r.upstream_used {
            print!(" (upstream {u})");
        }
        // Both flags come from systemd-resolved; libc fallback leaves them
        // false. Mark them when true so users can tell a cache hit from a
        // live resolution, and see DNSSEC when it's working.
        let mut tags: Vec<&str> = Vec::new();
        if r.cached { tags.push("cached"); }
        if r.authenticated { tags.push("dnssec-ok"); }
        if !tags.is_empty() {
            print!(" [{}]", tags.join(", "));
        }
        println!();
        for a in &r.answers {
            println!("        → {}", a.ip);
        }
        if let Some(e) = &r.error {
            println!("        error: {e:?}");
        }
    }
    println!(
        "egress: {} dev {} src {} gw {}",
        path.egress.connection_id.0,
        path.egress.iface,
        path.egress.src,
        path.egress.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into()),
    );
    if !path.egress.family_unreachable.is_empty() {
        println!("        unreachable families: {:?}", path.egress.family_unreachable);
    }
    print_probes(&path.probes);
    println!();
    // Color the verdict line by outcome — green for success, red for hard
    // failure, yellow for partial. Style is closed (`:#`) before the
    // variable text so the "REACHABLE" word gets styled but the rest stays
    // neutral.
    let (label, detail, style) = match &path.verdict {
        Verdict::Reachable { latency_ms, family_used } => (
            "REACHABLE",
            format!("({latency_ms}ms, {family_used:?})"),
            theme::ok(),
        ),
        Verdict::PartiallyReachable { working, broken } => (
            "PARTIAL",
            format!("(working={working:?}, broken={broken:?})"),
            theme::warn(),
        ),
        Verdict::DnsFailed { error } => ("DNS FAILED", format!("({error:?})"), theme::bad()),
        Verdict::NoEgress { reason } => ("NO EGRESS", format!("({reason})"), theme::bad()),
        Verdict::GatewayDown { gateway } => ("GW DOWN", format!("({gateway})"), theme::bad()),
        Verdict::PacketLoss { loss_pct } => ("PKT LOSS", format!("({loss_pct:.0}%)"), theme::warn()),
        Verdict::TcpRefused { addr } => ("REFUSED", format!("({addr})"), theme::bad()),
        Verdict::TcpTimeout { addr } => ("TIMEOUT", format!("({addr})"), theme::bad()),
        Verdict::TlsFailed { err } => ("TLS FAILED", format!("({err})"), theme::bad()),
        Verdict::HttpFailed { status } => ("HTTP FAIL", format!("({status})"), theme::bad()),
    };
    println!("verdict: {style}{label}{style:#}  {detail}");
    if !path.findings.is_empty() {
        println!();
        for f in &path.findings {
            println!("  • {}", f.summary);
        }
    }
}

fn print_probes(p: &netcore::path::ProbeResults) {
    if let Some(gp) = &p.gateway_ping {
        println!(
            "probes: gateway ping   sent={} recv={} rtt={}",
            gp.sent,
            gp.received,
            gp.rtt_avg.map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0)).unwrap_or_else(|| "-".into())
        );
    }
    if let Some(tp) = &p.target_ping {
        println!(
            "        target ping    sent={} recv={}",
            tp.sent, tp.received
        );
    }
    if let Some(tc) = &p.tcp_connect {
        println!(
            "        tcp {}         {} in {:.1}ms",
            tc.addr,
            if tc.connected { "OK" } else { "FAIL" },
            tc.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(tls) = &p.tls_handshake {
        println!(
            "        tls {}         {} in {:.1}ms",
            tls.peer,
            if tls.negotiated { "OK" } else { "FAIL" },
            tls.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(h) = &p.http_head {
        println!(
            "        http HEAD      {} in {:.1}ms",
            h.status.map(|c| c.to_string()).unwrap_or_else(|| "ERR".into()),
            h.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(trace) = &p.trace {
        println!("        trace:");
        for hop in trace {
            let ip = hop.ip.map(|i| i.to_string()).unwrap_or_else(|| "*".into());
            let rtt = hop
                .rtt
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".into());
            println!("         {:>2} {:<20} {}", hop.ttl, ip, rtt);
        }
    }
}
