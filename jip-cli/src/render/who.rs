//! `jip who` — established flows: which processes are talking to whom.

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Style, object::Rows, themes::Colorization, Color as TabColor},
};

use netcore::link::L4Proto;
use netcore::process::{ProcessInfo, ProcessRef};
use netcore::service::Flow;

use crate::theme;

pub fn who(flows: &[Flow]) {
    let mut sorted: Vec<&Flow> = flows.iter().collect();
    sorted.sort_by(|a, b| a.remote.ip().cmp(&b.remote.ip()).then(a.remote.port().cmp(&b.remote.port())));

    let rows: Vec<[String; 6]> = sorted
        .iter()
        .map(|f| {
            [
                proto_label(f.proto).into(),
                f.local.to_string(),
                f.remote.to_string(),
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
    b.push_record(["PROTO", "LOCAL", "REMOTE", "BYTES (in/out)", "RTT", "PROCESS"]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
}

fn bytes_cell(bin: u64, bout: u64) -> String {
    if bin == 0 && bout == 0 {
        "-".into()
    } else {
        format!("{}/{}", human_bytes(bin), human_bytes(bout))
    }
}

/// tcp_info.rtt is microseconds, already smoothed by the kernel.
fn rtt_cell(us: Option<u32>) -> String {
    match us {
        None => "-".into(),
        Some(us) if us < 1_000 => format!("{us}µs"),
        Some(us) => format!("{:.1}ms", us as f64 / 1_000.0),
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n}") } else { format!("{v:.1}{}", UNITS[u]) }
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
