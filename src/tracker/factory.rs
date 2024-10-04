use url::Url;

use crate::torrent_file::TorrentFile;

use super::{http::HttpTracker, udp::UdpTracker, Tracker};

pub fn create_tracker<'a>(announce_url: &'a str, torrent_file: &'a TorrentFile) -> Box<dyn Tracker + 'a> {
    let url = Url::parse(announce_url).expect("Invalid tracker URL");
    match url.scheme() {
        "http" | "https" => Box::new(HttpTracker { announce_url: announce_url.to_string(), torrent_file }),
        "udp" => Box::new(UdpTracker { announce_url: announce_url.to_string(), torrent_file }),
        _ => panic!("Unsupported tracker protocol"),
    }
}