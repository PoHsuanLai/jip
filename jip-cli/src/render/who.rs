//! `jip who` — established flows: which processes are talking to whom.

use std::net::SocketAddr;

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Color as TabColor, Style, object::Rows, themes::Colorization},
};

use netcore::link::L4Proto;
use netcore::process::{ProcessInfo, ProcessRef};
use netcore::service::Flow;

use crate::theme;

/// Print a `jip who` table: one row per established flow, sorted by remote
/// address.
pub fn who(flows: &[Flow]) {
    let mut sorted: Vec<&Flow> = flows.iter().collect();
    sorted.sort_by(|a, b| {
        a.remote
            .ip()
            .cmp(&b.remote.ip())
            .then(a.remote.port().cmp(&b.remote.port()))
    });

    let rows: Vec<[String; 6]> = sorted
        .iter()
        .map(|f| {
            [
                proto_cell(f.proto),
                addr_cell(f.local),
                addr_cell(f.remote),
                bytes_cell(f.bytes_in, f.bytes_out),
                rtt_cell(f.rtt_us),
                process_label(&f.process),
            ]
        })
        .collect();

    if theme::is_plain() {
        for row in &rows {
            println!("{}", row.join("\t"));
        }
        return;
    }

    let mut b = Builder::default();
    b.push_record([
        "PROTO",
        "LOCAL",
        "REMOTE",
        "BYTES (in/out)",
        "RTT",
        "PROCESS",
    ]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
}

/// "in/out" with the slash dimmed and each half scaled by unit: K default,
/// M yellow (a megabyte here means a real transfer), G red (the heavy
/// hitters that usually explain bandwidth problems).
fn bytes_cell(bin: u64, bout: u64) -> String {
    if bin == 0 && bout == 0 {
        return theme::dim_placeholder("-");
    }
    let sep = theme::paint(theme::dim(), "/");
    format!("{}{sep}{}", bytes_painted(bin), bytes_painted(bout))
}

fn bytes_painted(n: u64) -> String {
    let (value, unit) = human_split(n);
    let text = format!("{value}{unit}");
    // Tier by unit: smaller = calmer. G/T is unusual and interesting.
    match unit {
        "B" => theme::paint(theme::dim(), text),
        "K" => text,
        "M" => theme::paint(theme::warn(), text),
        "G" | "T" => theme::paint(theme::bad(), text),
        _ => text,
    }
}

fn human_split(n: u64) -> (String, &'static str) {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        (n.to_string(), UNITS[u])
    } else {
        (format!("{v:.1}"), UNITS[u])
    }
}

/// tcp_info.rtt is microseconds, already smoothed by the kernel. Tiered:
/// sub-ms is "LAN or loopback" (green), single-digit ms is normal, tens of
/// ms starts to feel like a WAN hop (cyan), over 100ms is warn, over 200ms
/// is bad (and usually means transoceanic or something congested).
fn rtt_cell(us: Option<u32>) -> String {
    let Some(us) = us else {
        return theme::dim_placeholder("-");
    };
    let text = if us < 1_000 {
        format!("{us}µs")
    } else {
        format!("{:.1}ms", us as f64 / 1_000.0)
    };
    let style = match us {
        0..=999 => theme::ok_soft(),
        1_000..=9_999 => return text,
        10_000..=49_999 => return text,
        50_000..=99_999 => theme::info(),
        100_000..=199_999 => theme::warn(),
        _ => theme::bad(),
    };
    theme::paint(style, text)
}

fn proto_cell(p: L4Proto) -> String {
    match p {
        L4Proto::Tcp => theme::paint(theme::accent(), "tcp"),
        L4Proto::Udp => theme::paint(theme::accent2(), "udp"),
    }
}

/// `addr:port` with the port dimmed (usually ephemeral, not interesting).
/// Loopback and link-local addresses themselves get dimmed — those flows
/// are usually ambient IPC, not the ones the user is hunting for.
fn addr_cell(sa: SocketAddr) -> String {
    let ip = sa.ip();
    let ip_text = ip.to_string();
    let ip_painted = if ip.is_loopback() || is_link_local(&ip) {
        // Loopback + link-local are usually ambient IPC, not the flows the
        // user is hunting for — dim them so the remote-peer rows dominate.
        theme::paint(theme::dim(), ip_text)
    } else if ip.is_ipv6() {
        // Distinguish v6 so dual-stack flows are visually obvious at a glance.
        theme::paint(theme::info(), ip_text)
    } else {
        ip_text
    };
    let port = theme::paint(theme::dim(), format!(":{}", sa.port()));
    format!("{ip_painted}{port}")
}

fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn process_label(p: &ProcessInfo) -> String {
    match p {
        // Bold the comm so the name dominates; pid is context. Makes it easy
        // to scan down the column and pick out the process you care about.
        ProcessInfo::Known(ProcessRef { pid, comm }) => format!(
            "{}{}",
            theme::paint(theme::strong(), comm),
            theme::paint(theme::dim(), format!("({pid})"))
        ),
        ProcessInfo::PermissionDenied | ProcessInfo::Anonymous => theme::dim_placeholder("-"),
    }
}
