//! `cargo run -p netcore-probe --example trace -- 1.1.1.1`
use std::net::IpAddr;
use std::time::Duration;

use netcore::diag::{PingOpts, TraceOpts};
use netcore::link::L4Proto;
use netcore::traits::Reachability;
use netcore_probe::ProbeBackend;

fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "1.1.1.1".into());
    let ip: IpAddr = target.parse().expect("pass an IP literal");
    let b = ProbeBackend::new();
    println!("caps = {:?}", b.capabilities());

    println!("--- ping {ip} ---");
    let r = b
        .ping(
            ip,
            PingOpts {
                count: 3,
                timeout: Duration::from_millis(1000),
            },
        )
        .expect("ping");
    println!(
        "sent={} recv={} min={:?} avg={:?} max={:?}",
        r.sent, r.received, r.rtt_min, r.rtt_avg, r.rtt_max
    );

    println!("--- trace {ip} ---");
    let hops = b
        .trace(
            ip,
            TraceOpts {
                max_hops: 15,
                timeout_per_hop: Duration::from_millis(1000),
                proto: L4Proto::Tcp,
            },
        )
        .expect("trace");
    for h in &hops {
        println!(
            "  {:2} {:>20} {:>10}",
            h.ttl,
            h.ip.map(|i| i.to_string()).unwrap_or_else(|| "*".into()),
            h.rtt
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".into())
        );
    }
}
