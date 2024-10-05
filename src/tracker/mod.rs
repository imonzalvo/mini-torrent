pub mod factory;
mod http;
mod udp;

use async_trait::async_trait;
use rand::Rng;
use std::error::Error;

use crate::torrent_state::peer::Peer;

#[async_trait]
pub trait Tracker {
    async fn get_peers(
        &self
    ) -> Result<TrackerInfo, Box<dyn Error>>;

    fn parse_tracker_response(&self, response: &[u8]) -> Result<TrackerInfo, Box<dyn std::error::Error>>;
}

pub struct TrackerInfo {
    pub peers: Vec<Peer>,
    pub interval: i64,
}

pub fn generate_peer_id() -> [u8; 20] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    bytes
}