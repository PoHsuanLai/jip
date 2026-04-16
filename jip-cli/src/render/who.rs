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

    let rows: Vec<[String; 4]> = sorted
        .iter()
        .map(|f| {
            [
                proto_label(f.proto).into(),
                f.local.to_string(),
                f.remote.to_string(),
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
    b.push_record(["PROTO", "LOCAL", "REMOTE", "PROCESS"]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
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
