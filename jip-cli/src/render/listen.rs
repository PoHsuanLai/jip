//! `jip listen` — one row per listening service, grouped by exposure.
//!
//! Exposure is derived from [`BindScope`] joined with the firewall verdict
//! for that (port, proto). When no firewall backend answered, `Unknown` is
//! shown (preferable to guessing `Exposed` and being wrong).

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Color as TabColor, Style, object::Rows, themes::Colorization},
};

use netcore::link::L4Proto;
use netcore::process::{ProcessInfo, ProcessRef};
use netcore::service::{BindScope, Exposure, Service};

use crate::theme;

/// Print a `jip listen` table: one row per listening service, sorted by
/// exposure risk (most exposed first).
pub fn listen(services: &[Service]) {
    let mut sorted: Vec<&Service> = services.iter().collect();
    sorted.sort_by_key(|s| (exposure_rank(s.exposure), s.port, s.proto as u8));

    let rows: Vec<[String; 6]> = sorted
        .iter()
        .map(|s| {
            [
                proto_cell(s.proto),
                port_cell(s.port),
                bind_label(&s.bind),
                exposure_cell(s.exposure),
                process_label(&s.process),
                String::new(),
            ]
        })
        .collect();

    if theme::is_plain() {
        for row in &rows {
            // 5 meaningful columns (drop trailing empty)
            println!("{}\t{}\t{}\t{}\t{}", row[0], row[1], row[2], row[3], row[4]);
        }
        return;
    }

    let mut b = Builder::default();
    b.push_record(["PROTO", "PORT", "BIND", "EXPOSURE", "PROCESS", ""]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
}

fn exposure_rank(e: Exposure) -> u8 {
    match e {
        Exposure::Exposed => 0,
        Exposure::Unknown => 1,
        Exposure::LanOnly => 2,
        Exposure::LocalOnly => 3,
    }
}

fn exposure_cell(e: Exposure) -> String {
    // Color by risk: Exposed draws the eye (bold red), LanOnly is cautionary
    // yellow, LocalOnly is a soft green (it's the "safe" state), Unknown is
    // dim since it just means we couldn't measure the firewall.
    let (label, style) = match e {
        Exposure::Exposed => ("exposed", theme::bad()),
        Exposure::LanOnly => ("lan-only", theme::warn()),
        Exposure::LocalOnly => ("local", theme::ok_soft()),
        Exposure::Unknown => ("unknown", theme::dim()),
    };
    theme::paint(style, label)
}

fn bind_label(b: &BindScope) -> String {
    match b {
        // `*` = bound to 0.0.0.0 / ::. Warn-colored because this is the bind
        // that turns a service into an exposure risk.
        BindScope::AnyAddress => theme::paint(theme::warn(), "*"),
        BindScope::Loopback => theme::paint(theme::dim(), "lo"),
        BindScope::SpecificInterface(iface) => format!("%{iface}"),
        BindScope::SpecificAddress(ip) => ip.to_string(),
    }
}

fn proto_cell(p: L4Proto) -> String {
    match p {
        L4Proto::Tcp => theme::paint(theme::accent(), "tcp"),
        L4Proto::Udp => theme::paint(theme::accent2(), "udp"),
    }
}

fn port_cell(port: u16) -> String {
    port.to_string()
}

fn process_label(p: &ProcessInfo) -> String {
    match p {
        ProcessInfo::Known(ProcessRef { pid, comm }) => format!(
            "{}{}",
            theme::paint(theme::strong(), comm),
            theme::paint(theme::dim(), format!("({pid})"))
        ),
        ProcessInfo::PermissionDenied | ProcessInfo::Anonymous => theme::dim_placeholder("-"),
    }
}
