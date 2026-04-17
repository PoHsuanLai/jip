//! `jip profiles` — one row per NetworkManager profile.

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Style, object::Rows, themes::Colorization, Color as TabColor},
};

use netcore::connection::Profile;

use crate::theme;

/// Print all NM profiles sorted: active first, then alphabetically by name.
pub fn profiles(profiles: &[Profile]) {
    let mut sorted: Vec<&Profile> = profiles.iter().collect();
    sorted.sort_by_key(|p| (!p.active, p.name.to_lowercase()));

    let rows: Vec<[String; 5]> = sorted
        .iter()
        .map(|p| {
            [
                name_cell(p),
                kind_cell(&p.kind),
                iface_cell(p.iface.as_deref()),
                state_cell(p.active),
                auto_cell(p.autoconnect),
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
    b.push_record(["NAME", "KIND", "IFACE", "STATE", "AUTO"]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
}

fn name_cell(p: &Profile) -> String {
    if p.active {
        theme::paint(theme::strong(), &p.name)
    } else {
        p.name.clone()
    }
}

fn kind_cell(kind: &str) -> String {
    let label = match kind {
        "802-3-ethernet" => "ethernet",
        "802-11-wireless" | "wifi" => "wifi",
        "vpn" => "vpn",
        "bridge" => "bridge",
        "bond" => "bond",
        "vlan" => "vlan",
        "wireguard" => "wireguard",
        "gsm" | "cdma" => "cellular",
        other => other,
    };
    theme::paint(theme::dim(), label)
}

fn iface_cell(iface: Option<&str>) -> String {
    match iface {
        Some(i) => i.to_string(),
        None => theme::dim_placeholder("—"),
    }
}

fn state_cell(active: bool) -> String {
    if active {
        theme::paint(theme::ok(), "active")
    } else {
        theme::paint(theme::dim(), "inactive")
    }
}

fn auto_cell(autoconnect: bool) -> String {
    if autoconnect {
        "yes".to_string()
    } else {
        theme::paint(theme::warn(), "no")
    }
}
