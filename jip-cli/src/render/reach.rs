//! `jip reach <target>` — target + path + verdict.

use anstream::println;
use netcore::diag::Severity;
use netcore::path::{Path, Verdict};

use crate::theme;

/// Print a `jip reach` report: target, DNS resolution, egress, probe
/// results, and final verdict.
pub fn print(path: &Path) {
    // The leading stage labels (target:/dns:/egress:/probes:/verdict:) are
    // signposts, not content — dim them so the values stand out.
    let label = theme::dim();
    match &path.target {
        netcore::path::Target::Ip { ip, port } => match port {
            Some(p) => println!("{label}target:{label:#} {ip}:{p}"),
            None => println!("{label}target:{label:#} {ip}"),
        },
        netcore::path::Target::Host { name, port } => match port {
            Some(p) => println!("{label}target:{label:#} {name}:{p}"),
            None => println!("{label}target:{label:#} {name}"),
        },
        netcore::path::Target::Url { url } => println!("{label}target:{label:#} {url}"),
    }
    if let Some(r) = &path.resolution {
        print!("{label}dns:   {label:#} {} via {:?}", r.queried, r.via);
        if let Some(u) = &r.upstream_used {
            print!(" (upstream {u})");
        }
        // Both flags come from systemd-resolved; libc fallback leaves them
        // false. Mark them when true so users can tell a cache hit from a
        // live resolution, and see DNSSEC when it's working.
        let mut tags: Vec<String> = Vec::new();
        if r.cached {
            tags.push(theme::paint(theme::info(), "cached"));
        }
        if r.authenticated {
            tags.push(theme::paint(theme::ok_soft(), "dnssec-ok"));
        }
        if !tags.is_empty() {
            print!(" [{}]", tags.join(", "));
        }
        println!();
        let arrow = theme::paint(theme::dim(), "→");
        for a in &r.answers {
            println!("        {arrow} {}", a.ip);
        }
        if let Some(e) = &r.error {
            println!(
                "        {}",
                theme::paint(theme::bad(), format!("error: {e:?}"))
            );
        }
    }
    let gw = path
        .egress
        .gateway
        .map(|g| g.to_string())
        .unwrap_or_else(|| theme::dim_placeholder("-"));
    println!(
        "{label}egress:{label:#} {} dev {} src {} gw {}",
        path.egress.connection_id.0, path.egress.iface, path.egress.src, gw,
    );
    if !path.egress.family_unreachable.is_empty() {
        println!(
            "        {}",
            theme::paint(
                theme::warn(),
                format!("unreachable families: {:?}", path.egress.family_unreachable)
            )
        );
    }
    print_probes(&path.probes);
    println!();
    // Color the verdict line by outcome — green for success, red for hard
    // failure, yellow for partial. Style is closed (`:#`) before the
    // variable text so the "REACHABLE" word gets styled but the rest stays
    // neutral.
    let (label, detail, style) = match &path.verdict {
        Verdict::Reachable {
            latency_ms,
            family_used,
        } => (
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
        Verdict::PacketLoss { loss_pct } => {
            ("PKT LOSS", format!("({loss_pct:.0}%)"), theme::warn())
        }
        Verdict::TcpRefused { addr } => ("REFUSED", format!("({addr})"), theme::bad()),
        Verdict::TcpTimeout { addr } => ("TIMEOUT", format!("({addr})"), theme::bad()),
        Verdict::TlsFailed { err } => ("TLS FAILED", format!("({err})"), theme::bad()),
        Verdict::HttpFailed { status } => ("HTTP FAIL", format!("({status})"), theme::bad()),
    };
    let vlabel = theme::dim();
    println!("{vlabel}verdict:{vlabel:#} {style}{label}{style:#}  {detail}");
    if !path.findings.is_empty() {
        println!();
        for f in &path.findings {
            let (bullet_style, badge) = match f.severity {
                Severity::Info => (theme::info(), "info"),
                Severity::Warn => (theme::warn(), "warn"),
                Severity::Broken => (theme::bad(), "!!"),
            };
            println!("  {bullet_style}{badge}{bullet_style:#} {}", f.summary);
        }
    }
}

fn print_probes(p: &netcore::path::ProbeResults) {
    let label = theme::dim();
    let head = format!("{label}probes:{label:#}");
    let pad = "       "; // width of "probes:"
    let mut first = true;
    let mut lead = || {
        if first {
            first = false;
            head.clone()
        } else {
            pad.to_string()
        }
    };
    if let Some(gp) = &p.gateway_ping {
        let verdict = ping_verdict(gp.sent, gp.received);
        println!(
            "{} gateway ping   sent={} recv={} rtt={} {}",
            lead(),
            gp.sent,
            gp.received,
            gp.rtt_avg
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| theme::dim_placeholder("-")),
            verdict,
        );
    }
    if let Some(tp) = &p.target_ping {
        let verdict = ping_verdict(tp.sent, tp.received);
        println!(
            "{} target ping    sent={} recv={} {}",
            lead(),
            tp.sent,
            tp.received,
            verdict,
        );
    }
    if let Some(tc) = &p.tcp_connect {
        println!(
            "{} tcp {}         {} in {:.1}ms",
            lead(),
            tc.addr,
            ok_fail(tc.connected),
            tc.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(tls) = &p.tls_handshake {
        println!(
            "{} tls {}         {} in {:.1}ms",
            lead(),
            tls.peer,
            ok_fail(tls.negotiated),
            tls.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(h) = &p.http_head {
        let status = match h.status {
            Some(c) if (200..400).contains(&c) => theme::paint(theme::ok_soft(), c.to_string()),
            Some(c) => theme::paint(theme::bad(), c.to_string()),
            None => theme::paint(theme::bad(), "ERR"),
        };
        println!(
            "{} http HEAD      {} in {:.1}ms",
            lead(),
            status,
            h.took.as_secs_f64() * 1000.0
        );
    }
    if let Some(trace) = &p.trace {
        println!("{} trace:", lead());
        for hop in trace {
            let ip = hop
                .ip
                .map(|i| i.to_string())
                .unwrap_or_else(|| theme::dim_placeholder("*"));
            let rtt = hop
                .rtt
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| theme::dim_placeholder("-"));
            println!("{}  {:>2} {:<20} {}", pad, hop.ttl, ip, rtt);
        }
    }
}

fn ok_fail(ok: bool) -> String {
    if ok {
        theme::paint(theme::ok_soft(), "OK")
    } else {
        theme::paint(theme::bad(), "FAIL")
    }
}

fn ping_verdict(sent: u32, recv: u32) -> String {
    if sent == 0 {
        return String::new();
    }
    if recv == 0 {
        theme::paint(theme::bad(), "FAIL")
    } else if recv < sent {
        theme::paint(theme::warn(), "LOSS")
    } else {
        theme::paint(theme::ok_soft(), "OK")
    }
}
