//! `jip check` — grouped findings by layer.

use netcore::diag::{Finding, Health, Layer, Remedy, Severity};

pub fn print(health: &Health) {
    let (state, findings): (&str, &[Finding]) = match health {
        Health::Ok => ("OK", &[]),
        Health::Degraded { findings } => ("DEGRADED", findings.as_slice()),
        Health::Broken { findings } => ("BROKEN", findings.as_slice()),
    };
    println!("check: {state}");
    if findings.is_empty() {
        return;
    }
    for layer in [
        Layer::Link,
        Layer::Address,
        Layer::Gateway,
        Layer::Dns,
        Layer::Internet,
        Layer::Firewall,
        Layer::Service,
    ] {
        let subset: Vec<&Finding> = findings.iter().filter(|f| f.layer == layer).collect();
        if subset.is_empty() { continue; }
        println!();
        println!("[{:?}]", layer);
        for f in subset {
            let sev = match f.severity {
                Severity::Info => "info ",
                Severity::Warn => "warn ",
                Severity::Broken => "BROKEN",
            };
            println!("  {sev} {}", f.summary);
            if let Some(d) = &f.detail {
                for line in d.lines() {
                    println!("         {line}");
                }
            }
            match &f.remedy {
                Some(Remedy::Run { cmd }) => println!("         → try: {cmd}"),
                Some(Remedy::Check { what }) => println!("         → check: {what}"),
                Some(Remedy::Reconnect { id }) => println!("         → reconnect {}", id.0),
                Some(Remedy::ElevatePrivileges) => println!("         → run as root for more info"),
                Some(Remedy::None) | None => {}
            }
        }
    }
}
