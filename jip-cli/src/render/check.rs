//! `jip check` — findings grouped by Layer with color-coded severity.

use anstream::println;
use netcore::diag::{Finding, Health, Layer, Remedy, Severity};

use crate::theme;

/// Print a `jip check` report: overall status line followed by findings
/// grouped by [`Layer`] in bottom-up order.
pub fn print(health: &Health) {
    let (state_label, state_style, findings): (&str, anstyle::Style, &[Finding]) = match health {
        Health::Ok => ("OK", theme::ok(), &[]),
        Health::Degraded { findings } => ("DEGRADED", theme::warn(), findings.as_slice()),
        Health::Broken { findings } => ("BROKEN", theme::bad(), findings.as_slice()),
    };
    println!("check: {state_style}{state_label}{state_style:#}");
    if findings.is_empty() {
        return;
    }
    // Fixed layer order so users see root causes first (Link → ... → Service).
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
        if subset.is_empty() {
            continue;
        }
        println!();
        let h = theme::header();
        println!("{h}[{layer:?}]{h:#}");
        for f in subset {
            let (badge, style) = match f.severity {
                Severity::Info => ("info  ", theme::info()),
                Severity::Warn => ("warn  ", theme::warn()),
                Severity::Broken => ("BROKEN", theme::bad()),
            };
            println!("  {style}{badge}{style:#} {}", f.summary);
            if let Some(d) = &f.detail {
                let dim = theme::dim();
                for line in d.lines() {
                    println!("         {dim}{line}{dim:#}");
                }
            }
            let arrow = theme::paint(theme::dim(), "→");
            let hint = theme::info();
            match &f.remedy {
                Some(Remedy::Run { cmd }) => {
                    println!("         {arrow} {hint}try{hint:#}: {cmd}")
                }
                Some(Remedy::Check { what }) => {
                    println!("         {arrow} {hint}check{hint:#}: {what}")
                }
                Some(Remedy::Reconnect { id }) => {
                    println!("         {arrow} {hint}reconnect{hint:#} {}", id.0)
                }
                Some(Remedy::ElevatePrivileges) => {
                    println!("         {arrow} {hint}run as root{hint:#} for more info")
                }
                Some(Remedy::None) | None => {}
            }
        }
    }
}
