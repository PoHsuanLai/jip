//! Quick eyeball dump: `cargo run -p netcore-netlink --example dump`.
use netcore::traits::{Inventory, InventoryRaw};
use netcore_netlink::NetlinkBackend;

fn main() {
    let b = NetlinkBackend::new();
    println!("== connections ==");
    for c in b.connections().expect("connections") {
        println!(
            "  {:<14} kind={:?} state={:?} v4={:?} v6={:?} default={} gw={:?}",
            c.link.name,
            c.link.kind,
            c.link.state,
            c.primary_v4,
            c.primary_v6,
            c.is_default,
            c.gateway.as_ref().map(|g| g.ip),
        );
    }
    println!("== routes ==");
    for r in b.routes().expect("routes").iter().take(10) {
        println!("  {:?} via {:?} dev {:?} metric {:?}", r.dst, r.gateway, r.oif, r.metric);
    }
}
