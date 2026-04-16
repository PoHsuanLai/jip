use netcore::traits::{Inventory, InventoryRaw};
use netcore_netlink::NetlinkBackend;

fn main() {
    let b = NetlinkBackend::new();
    let socks = b.sockets().unwrap();
    let services = b.services().unwrap();
    let flows = b.flows().unwrap();
    println!("sockets: {}  services: {}  flows: {}", socks.len(), services.len(), flows.len());
    println!("\n-- first 5 services --");
    for s in services.iter().take(5) {
        println!("  {:?}:{} on {:?} proc={:?}", s.proto, s.port, s.bind, s.process);
    }
    println!("\n-- first 5 flows --");
    for f in flows.iter().take(5) {
        println!("  {:?} {} -> {} proc={:?}", f.proto, f.local, f.remote, f.process);
    }
}
