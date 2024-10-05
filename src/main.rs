mod bencode_parser;
mod handshake;
mod message;
mod torrent_file;
mod torrent_state;
mod tracker;

use torrent_state::TorrentState;
use std::env;
use std::fs;
use torrent_file::TorrentFile;
use tracker::{factory, Tracker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <torrent_file> <output_file>", args[0]);
        std::process::exit(1);
    }

    let torrent_path = &args[1];
    let output_path = &args[2];

    let torrent_data = fs::read(torrent_path)?;
    let torrent_file = TorrentFile::from_bencoded(&torrent_data)?;

    println!("{}", torrent_file);

    let piece_count = torrent_file.info.pieces.len() / 20; // Each SHA-1 hash is 20 bytes
    let pieces_hashes = torrent_file
        .info
        .pieces
        .chunks(20)
        .filter_map(|chunk| chunk.try_into().ok())
        .collect();

    let mut torrent_state = TorrentState::new(
        piece_count,
        torrent_file.info.piece_length as usize,
        output_path,
        torrent_file.info.length as u64,
        pieces_hashes,
        torrent_file.info_hash
    )?;
    let tracker: Box<dyn Tracker> = factory::create_tracker(&torrent_file);

    println!("\nContacting tracker...");
    match tracker.get_peers().await {
        Ok(tracker_info) => {
            println!("Received {} peers from tracker:", tracker_info.peers.len());
            if let Err(e) = torrent_state.connect_and_download(tracker_info.peers).await {
                eprintln!("Failed to download: {}", e);
            }
        }
        Err(e) => println!("Failed to get peers: {}", e),
    }

    Ok(())
}
