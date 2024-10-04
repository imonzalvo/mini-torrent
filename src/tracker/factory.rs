use url::Url;

use crate::torrent_file::TorrentFile;

use super::{http::HttpTracker, udp::UdpTracker, Tracker};

pub fn create_tracker<'a>(torrent_file: &'a TorrentFile) -> Box<dyn Tracker + 'a> {
    let url = Url::parse(&torrent_file.announce).expect("Invalid tracker URL");
    match url.scheme() {
        "http" | "https" => Box::new(HttpTracker { torrent_file }),
        "udp" => Box::new(UdpTracker { torrent_file }),
        _ => panic!("Unsupported tracker protocol"),
    }
}
