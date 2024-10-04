use url::Url;

use super::{http::HttpTracker, udp::UdpTracker, Tracker};

pub fn create_tracker(announce_url: &str) -> Box<dyn Tracker> {
    let url = Url::parse(announce_url).expect("Invalid tracker URL");
    match url.scheme() {
        "http" | "https" => Box::new(HttpTracker { announce_url: announce_url.to_string() }),
        "udp" => Box::new(UdpTracker { announce_url: announce_url.to_string() }),
        _ => panic!("Unsupported tracker protocol"),
    }
}