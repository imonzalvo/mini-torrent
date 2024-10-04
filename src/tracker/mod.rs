pub mod factory;
mod http;
mod udp;

use crate::{torrent_file::TorrentFile, Peer};
use async_trait::async_trait;
use rand::Rng;
use std::error::Error;

#[async_trait]
pub trait Tracker {
    async fn get_peers(
        &self,
        torrent: &TorrentFile
    ) -> Result<TrackerInfo, Box<dyn Error>>;
}

pub struct TrackerInfo {
    pub peers: Vec<Peer>,
    pub interval: i64,
}

struct TrackerResponse {
    pub peers: Vec<Peer>,
    pub interval: i64,
}

fn generate_peer_id() -> [u8; 20] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    bytes
}