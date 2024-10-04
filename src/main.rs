mod bencode_parser;
mod handshake;
mod message;
mod torrent_file;
mod torrent_state;
mod tracker;

use handshake::receive_handshake;
use handshake::send_handshake;
use message::read_message;
use message::send_message;
use message::PeerMessage;
use rand::Rng;
use tracker::{Tracker, factory};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use torrent_file::TorrentFile;
use torrent_state::PeerState;
use torrent_state::TorrentState;

#[derive(Debug, Clone, Copy)]
struct Peer {
    ip: Ipv4Addr,
    port: u16,
}

fn generate_peer_id() -> [u8; 20] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    bytes
}

async fn connect_to_peer(
    peer: &Peer,
    timeout: Duration,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", peer.ip, peer.port);
    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            println!("Connected to peer: {}", addr);
            Ok(stream)
        }
        Ok(Err(e)) => Err(format!("Failed to connect to {}: {}", addr, e).into()),
        Err(_) => Err(format!("Connection to {} timed out", addr).into()),
    }
}

async fn download_piece(
    stream: &mut TcpStream,
    torrent_state: &mut TorrentState,
    piece_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let piece_size = if piece_index == torrent_state.total_pieces - 1 {
        // For the last piece, calculate its size based on total length
        (torrent_state.total_length as usize) - (piece_index * torrent_state.piece_size)
    } else {
        torrent_state.piece_size
    };

    let mut piece_data = Vec::with_capacity(piece_size);

    for block_index in 0..((piece_size + 16383) / 16384) {
        // Round up division
        let begin = block_index * 16384;
        let length = std::cmp::min(16384, piece_size - begin);

        request_piece(stream, piece_index, begin as u32, length as u32).await?;

        // Keep reading messages until we receive a valid piece message
        loop {
            match read_message(stream).await? {
                PeerMessage::Piece {
                    index,
                    begin,
                    block,
                } => {
                    // Ensure the received piece is correct
                    if index as usize == piece_index && begin as usize == block_index * 16384 {
                        piece_data.extend_from_slice(&block);
                        break; // Exit the loop once we have the valid piece
                    } else {
                        return Err("Received incorrect piece data".into());
                    }
                }
                PeerMessage::Unchoke => {
                    println!("Received Unchoke message, ignoring during piece download.");
                    // Ignore, as we don't need to act on this while downloading
                    continue; // Wait for the correct Piece message
                }
                m => {
                    // Handle any unexpected messages
                    println!("Unexpected message: {:?}", m);
                    return Err("Unexpected message while downloading piece".into());
                }
            }
        }
    }

    if piece_data.len() != piece_size {
        return Err("Incomplete piece data".into());
    }

    torrent_state.verify_piece(piece_index, &piece_data);
    torrent_state.write_piece(piece_index, &piece_data)?;
    torrent_state.mark_piece_downloaded(piece_index);
    Ok(())
}

async fn download_from_peer(
    mut stream: TcpStream,
    torrent_state: &mut TorrentState,
    peer_id: [u8; 20],
    info_hash: [u8; 20],
) -> Result<(), Box<dyn std::error::Error>> {
    send_handshake(&mut stream, info_hash, peer_id).await?;
    receive_handshake(&mut stream, info_hash).await?;

    // Send "interested" message
    send_message(&mut stream, PeerMessage::Unchoke).await?;
    send_message(&mut stream, PeerMessage::Interested).await?;

    loop {
        match read_message(&mut stream).await? {
            PeerMessage::Unchoke => {
                println!("Peer has unchoked us. We can now request pieces.");
                let peer_state = torrent_state.peers.first_mut().unwrap();
                peer_state.peer_choking = false;
                break;
            }
            PeerMessage::Bitfield(bitfield) => {
                let peer_state = torrent_state.peers.last_mut().unwrap();
                peer_state.update_bitfield(bitfield, torrent_state.total_pieces);
            }
            _ => {} // Ignore other messages for now
        }
    }

    while let Some(missing_piece) = torrent_state.get_missing_piece() {
        println!("Torrent Peers {:?}", torrent_state.peers.len());
        let peer_state = torrent_state
            .find_peer_with_piece(missing_piece)
            .ok_or("No peer has the missing piece")?;

        println!("Got peer {:?}", peer_state.peer_choking);

        if peer_state.peer_choking {
            match read_message(&mut stream).await? {
                PeerMessage::Unchoke => {
                    println!("Peer has unchoked us. We can now request pieces.");
                    let peer_state = torrent_state.peers.first_mut().unwrap();
                    peer_state.peer_choking = false;
                    break;
                }
                PeerMessage::Bitfield(bitfield) => {
                    let peer_state = torrent_state.peers.last_mut().unwrap();
                    peer_state.update_bitfield(bitfield, torrent_state.total_pieces);
                }
                m => {
                    println!("Wtfffff {:?}", m)
                } // Ignore other messages for now
            }
            // println!("Waiting for peer to unchoke us...");
            continue;
        }

        println!("Downloading piece {}", missing_piece);
        let piece_data = download_piece(&mut stream, torrent_state, missing_piece).await?;
        torrent_state.print_downloaded_pieces();
        let have_message = PeerMessage::Have(missing_piece as u32);
        send_message(&mut stream, have_message).await?;
        println!("Successfully downloaded piece {}", missing_piece);

        // Here you would typically write the piece data to a file or buffer
        // For now, we'll just print the length of the downloaded data
        // println!(
        //     "Downloaded {} bytes for piece {}",
        //     piece_data.len(),
        //     missing_piece
        // );
    }

    println!("Leaving");
    Ok(())
}

async fn request_piece(
    stream: &mut TcpStream,
    piece_index: usize,
    begin: u32,
    length: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_message = PeerMessage::Request {
        index: piece_index as u32,
        begin,
        length,
    };

    send_message(stream, request_message).await?;
    println!(
        "Requested piece {} (begin: {}, length: {})",
        piece_index, begin, length
    );
    Ok(())
}

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
    )?;
    let tracker: Box<dyn Tracker> = factory::create_tracker(&torrent_file.announce, &torrent_file);

    println!("\nContacting tracker...");
    match tracker.get_peers().await {
        Ok(tracker_info) => {
            println!("Received {} peers from tracker:", tracker_info.peers.len());
            let peer_id = generate_peer_id(); // Generate a unique peer_id for the handshake

            let mut connected = false;
            for peer in &tracker_info.peers {
                println!("\nAttempting to connect to peer {}: {}", peer.ip, peer.port);
                match connect_to_peer(peer, Duration::from_secs(3)).await {
                    Ok(stream) => {
                        println!("Successfully connected to peer {}:{}", peer.ip, peer.port);
                        let mut peer_state = PeerState::new(peer.clone());
                        peer_state.has_handshake = true; // We've successfully connected, so mark the handshake as complete
                        torrent_state.peers.push(peer_state);

                        if let Err(e) = download_from_peer(
                            stream,
                            &mut torrent_state,
                            peer_id,
                            torrent_file.info_hash,
                        )
                        .await
                        {
                            eprintln!("Error downloading from peer: {}", e);
                            torrent_state.peers.clear();
                        } else {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        println!("Failed to connect to peer {}:{}: {}", peer.ip, peer.port, e)
                    }
                }
            }

            if !connected {
                println!("Failed to connect to any peers.");
            }
        }
        Err(e) => println!("Failed to get peers: {}", e),
    }

    Ok(())
}
