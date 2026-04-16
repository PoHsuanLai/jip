//! Wifi metadata via nl80211.
//!
//! Two dumps per interface:
//!
//! * Interface dump (`NL80211_CMD_GET_INTERFACE`) — when associated, carries
//!   `Ssid`. An unassociated interface comes back with just ifindex/name
//!   and no SSID attribute, which is what we use to detect the "radio on,
//!   not connected" state.
//! * Station dump (`NL80211_CMD_GET_STATION`) — one entry per peer. For a
//!   client interface there's exactly one: the BSS we're associated to.
//!   Carries the RSSI and a TX bitrate.
//!
//! Security isn't directly exposed by nl80211 for the associated BSS —
//! the kernel knows cipher suites but they're only visible through a
//! scan dump (which needs root) or via NetworkManager. We leave
//! `security: None` here and let `netcore-nm` fill it in when available.

use futures::TryStreamExt;
use wl_nl80211::{
    Nl80211Attr, Nl80211Handle, Nl80211RateInfo, Nl80211StationInfo,
};

use netcore::connection::WifiSignal;

/// Everything nl80211 can tell us about a wifi iface's current state.
#[derive(Debug, Clone, Default)]
pub struct WifiSnapshot {
    /// Present when the interface is associated to a BSS.
    pub ssid: Option<String>,
    pub signal: Option<WifiSignal>,
}

/// Gather wifi state for one interface. Returns `None` if nl80211 is
/// unreachable or the interface isn't a wifi device (the caller already
/// checked `LinkKind::Wifi`, but nl80211 won't have a match for, say, a
/// veth, and that's fine — we just return `None`).
pub async fn snapshot(handle: &mut Nl80211Handle, if_index: u32) -> Option<WifiSnapshot> {
    let mut snap = WifiSnapshot::default();

    // --- interface dump (for SSID) ---
    // Filtering by ifindex server-side would be nice; the handle doesn't
    // expose that cleanly, so we dump and match. Cheap: a few ifaces max.
    let mut iface_stream = handle.interface().get(Vec::new()).execute().await;
    while let Ok(Some(msg)) = iface_stream.try_next().await {
        let mut idx_match = false;
        let mut ssid: Option<String> = None;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::IfIndex(i) if *i == if_index => idx_match = true,
                Nl80211Attr::Ssid(s) => ssid = Some(s.clone()),
                _ => {}
            }
        }
        if idx_match {
            snap.ssid = ssid;
            break;
        }
    }

    // --- station dump (for signal/bitrate) ---
    let mut sta_stream = handle.station().dump(if_index).execute().await;
    while let Ok(Some(msg)) = sta_stream.try_next().await {
        for attr in &msg.payload.attributes {
            if let Nl80211Attr::StationInfo(infos) = attr {
                snap.signal = station_signal(infos);
                if snap.signal.is_some() { return Some(snap); }
            }
        }
    }

    Some(snap)
}

fn station_signal(infos: &[Nl80211StationInfo]) -> Option<WifiSignal> {
    let mut rssi: Option<i8> = None;
    let mut rate_mbps: Option<u32> = None;
    for info in infos {
        match info {
            // Prefer instantaneous signal; fall back to average if that's
            // all we got.
            Nl80211StationInfo::Signal(s) => rssi = Some(*s),
            Nl80211StationInfo::SignalAvg(s) if rssi.is_none() => rssi = Some(*s),
            Nl80211StationInfo::TxBitrate(rates) => {
                rate_mbps = rate_mbps.or_else(|| rate_from(rates));
            }
            _ => {}
        }
    }
    rssi.map(|dbm| WifiSignal {
        rssi_dbm: dbm as i32,
        quality_pct: Some(rssi_to_quality(dbm)),
        rate_mbps,
    })
}

/// nl80211's bitrate is reported in units of 100 kbit/s. A modern
/// connection's "bitrate" attribute overflows `u16`, so prefer the 32-bit
/// variant when present.
fn rate_from(rates: &[Nl80211RateInfo]) -> Option<u32> {
    let mut wide: Option<u32> = None;
    let mut narrow: Option<u16> = None;
    for r in rates {
        match r {
            Nl80211RateInfo::Bitrate32(v) => wide = Some(*v),
            Nl80211RateInfo::Bitrate(v) => narrow = Some(*v),
            _ => {}
        }
    }
    wide.map(|v| v / 10)
        .or_else(|| narrow.map(|v| u32::from(v) / 10))
}

/// Map dBm to a rough 0–100 quality percentage using the same linear scale
/// NetworkManager uses: -30 dBm → 100%, -90 dBm → 0%.
fn rssi_to_quality(dbm: i8) -> u8 {
    let clamped = dbm.clamp(-90, -30);
    let pct = ((clamped as i32 + 90) * 100) / 60;
    pct as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_saturates() {
        assert_eq!(rssi_to_quality(-20), 100);
        assert_eq!(rssi_to_quality(-30), 100);
        assert_eq!(rssi_to_quality(-60), 50);
        assert_eq!(rssi_to_quality(-90), 0);
        assert_eq!(rssi_to_quality(-120), 0);
    }
}
