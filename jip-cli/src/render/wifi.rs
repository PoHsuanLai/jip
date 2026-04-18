//! `jip wifi` — nearby access points from NM's cached scan.

use anstream::println;
use tabled::{
    builder::Builder,
    settings::{Color as TabColor, Style, object::Rows, themes::Colorization},
};

use netcore::connection::{AccessPoint, WifiSecurity};

use crate::theme;

/// Print all visible access points sorted: in-use first, then by signal.
pub fn wifi(aps: &[AccessPoint]) {
    if aps.is_empty() {
        println!("{}", theme::paint(theme::dim(), "no access points found"));
        return;
    }

    let rows: Vec<[String; 5]> = aps
        .iter()
        .map(|ap| {
            [
                ssid_cell(ap),
                signal_cell(&ap.signal.quality_pct, ap.signal.rssi_dbm),
                band_cell(ap.frequency_mhz),
                security_cell(&ap.security),
                bssid_cell(&ap.bssid),
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
    b.push_record(["SSID", "SIGNAL", "BAND", "SECURITY", "BSSID"]);
    for row in &rows {
        b.push_record(row);
    }
    let mut table = b.build();
    table.with(Style::blank());
    let header_color = TabColor::BOLD | TabColor::UNDERLINE;
    table.with(Colorization::exact([header_color], Rows::first()));
    println!("{table}");
}

fn ssid_cell(ap: &AccessPoint) -> String {
    let name = if ap.ssid.is_empty() {
        theme::paint(theme::dim(), "<hidden>")
    } else if ap.in_use {
        theme::paint(theme::strong(), &ap.ssid)
    } else {
        ap.ssid.clone()
    };
    if ap.in_use {
        format!("{name} {}", theme::paint(theme::ok(), "*"))
    } else {
        name
    }
}

fn signal_cell(quality_pct: &Option<u8>, rssi_dbm: i32) -> String {
    let pct = quality_pct.unwrap_or(0);
    let bar = signal_bar(pct);
    let label = format!("{bar} {pct}%");
    let style = match rssi_dbm {
        i32::MIN..=-80 => theme::bad(),
        -79..=-70 => theme::warn(),
        -69..=-50 => return label,
        _ => theme::ok_soft(),
    };
    theme::paint(style, label)
}

fn signal_bar(pct: u8) -> &'static str {
    match pct {
        0..=20 => "▂___",
        21..=40 => "▂▄__",
        41..=60 => "▂▄▆_",
        _ => "▂▄▆█",
    }
}

fn band_cell(freq_mhz: u32) -> String {
    match freq_mhz {
        2_400..=2_500 => "2.4 GHz".into(),
        5_000..=5_899 => theme::paint(theme::info(), "5 GHz"),
        5_900..=7_200 => theme::paint(theme::accent(), "6 GHz"),
        _ => theme::paint(theme::dim(), "?"),
    }
}

fn security_cell(sec: &WifiSecurity) -> String {
    match sec {
        WifiSecurity::Open => theme::paint(theme::warn(), "open"),
        WifiSecurity::Wep => theme::paint(theme::warn(), "WEP"),
        WifiSecurity::Wpa2Personal => "WPA2".into(),
        WifiSecurity::Wpa2Enterprise => "WPA2-Ent".into(),
        WifiSecurity::Wpa3Personal => theme::paint(theme::ok_soft(), "WPA3"),
        WifiSecurity::Wpa3Enterprise => theme::paint(theme::ok_soft(), "WPA3-Ent"),
        WifiSecurity::Other(s) => theme::paint(theme::dim(), s),
    }
}

fn bssid_cell(bssid: &str) -> String {
    theme::paint(theme::dim(), bssid)
}
