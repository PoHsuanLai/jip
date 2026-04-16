//! `jip listen` — one row per listening service, grouped by exposure.
//!
//! Exposure is derived from [`BindScope`] joined with the firewall verdict
//! for that (port, proto). When no firewall backend answered, `Unknown` is
//! shown (preferable to guessing `Exposed` and being wrong).

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Style, object::Rows, themes::Colorization, Color as TabColor},
};

use netcore::link::L4Proto;
use netcore::process::{ProcessInfo, ProcessRef};
use netcore::service::{BindScope, Exposure, Service};

use crate::theme;

pub fn listen(services: &[Service]) {
    let mut sorted: Vec<&Service> = services.iter().collect();
    sorted.sort_by_key(|s| (exposure_rank(s.exposure), s.port, proto_label(s.proto)));

    let rows: Vec<[String; 5]> = sorted
        .iter()
        .map(|s| {
            [
                format!("{}/{}", s.port, proto_label(s.proto)),
                bind_label(&s.bind),
                exposure_label(s.exposure).into(),
                process_label(&s.process),
                String::new(),
            ]
        })
        .collect();

    if theme::is_plain() {
        for row in &rows {
            // 4 meaningful columns (drop trailing empty)
            println!("{}\t{}\t{}\t{}", row[0], row[1], row[2], row[3]);
        }
        return;
    }

    let mut b = Builder::default();
    b.push_record(["ADDR", "BIND", "EXPOSURE", "PROCESS", ""]);
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

fn exposure_label(e: Exposure) -> &'static str {
    match e {
        Exposure::Exposed => "exposed",
        Exposure::LanOnly => "lan-only",
        Exposure::LocalOnly => "local",
        Exposure::Unknown => "unknown",
    }
}

fn bind_label(b: &BindScope) -> String {
    match b {
        BindScope::AnyAddress => "*".into(),
        BindScope::Loopback => "lo".into(),
        BindScope::SpecificInterface(iface) => format!("%{iface}"),
        BindScope::SpecificAddress(ip) => ip.to_string(),
    }
}

fn proto_label(p: L4Proto) -> &'static str {
    match p {
        L4Proto::Tcp => "tcp",
        L4Proto::Udp => "udp",
    }
}

fn process_label(p: &ProcessInfo) -> String {
    match p {
        ProcessInfo::Known(ProcessRef { pid, comm }) => format!("{comm}({pid})"),
        ProcessInfo::PermissionDenied => "-".into(),
        ProcessInfo::Anonymous => "-".into(),
    }
}
