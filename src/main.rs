mod bencode_parser;
mod handshake;

use bencode_parser::{parse_bencode, BencodeValue};
use handshake::receive_handshake;
use handshake::send_handshake;
use rand::Rng;
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug)]
struct TorrentFile {
    info: Info,
    announce: String,
    info_hash: [u8; 20],
}

#[derive(Debug)]
struct Info {
    piece_length: i64,
    pieces: Vec<u8>,
    name: String,
    length: i64,
}

#[derive(Debug)]
struct Peer {
    ip: Ipv4Addr,
    port: u16,
}

#[derive(Debug)]
struct TrackerInfo {
    peers: Vec<Peer>,
    interval: i64,
}

// Update the parse_info function to accommodate the changes
fn parse_info(dict: &HashMap<String, BencodeValue>) -> Result<Info, String> {
    let piece_length = if let Some(BencodeValue::Integer(length)) = dict.get("piece length") {
        *length
    } else {
        return Err("Missing or invalid piece length".to_string());
    };

    let pieces = if let Some(BencodeValue::ByteString(bytes)) = dict.get("pieces") {
        bytes.clone() // Store raw bytes directly
    } else {
        return Err("Missing or invalid pieces".to_string());
    };

    let name = if let Some(BencodeValue::ByteString(bytes)) = dict.get("name") {
        String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?
    } else {
        return Err("Missing or invalid name".to_string());
    };

    let length = if let Some(BencodeValue::Integer(length)) = dict.get("length") {
        *length
    } else {
        return Err("Missing or invalid length".to_string());
    };

    Ok(Info {
        piece_length,
        pieces,
        name,
        length,
    })
}

fn parse_torrent_file(data: &[u8]) -> Result<TorrentFile, String> {
    let (bencode, _) = parse_bencode(data)?;

    if let BencodeValue::Dictionary(dict) = bencode {
        let announce = if let Some(BencodeValue::ByteString(bytes)) = dict.get("announce") {
            String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?
        } else {
            return Err("Missing or invalid announce URL".to_string());
        };

        let info_value = dict.get("info").ok_or("Missing info dictionary")?;

        let info_dict = if let BencodeValue::Dictionary(info_dict) = info_value {
            info_dict
        } else {
            return Err("Invalid info dictionary".to_string());
        };

        let info = parse_info(info_dict)?;

        // Calculate the SHA-1 hash of the bencoded info dictionary
        let info_bencoded = bencode_parser::bencode_encode(info_value);

        let mut hasher = Sha1::new();
        hasher.update(&info_bencoded);
        let info_hash = hasher.finalize().into();

        Ok(TorrentFile {
            info,
            announce,
            info_hash,
        })
    } else {
        Err("Invalid torrent file format".to_string())
    }
}
fn generate_peer_id() -> [u8; 20] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    bytes
}

async fn get_peers(torrent: &TorrentFile) -> Result<TrackerInfo, Box<dyn std::error::Error>> {
    let peer_id = generate_peer_id();
    let port = 6881; // You can randomize this between 6881-6889 if needed
    let info_hash = urlencoding::encode_binary(&torrent.info_hash);
    let binary_peer_id = urlencoding::encode_binary(&peer_id);

    let url = format!(
        "{}?info_hash={}&peer_id={}&port={}&uploaded=0&downloaded=0&left={}&compact=1",
        torrent.announce, info_hash, binary_peer_id, port, torrent.info.length
    );

    println!("Calling URL {}", url);

    let client = Client::new();
    let response = client.get(&url).send().await?;
    let response_bytes = response.bytes().await?;

    let (bencode_response, _) = parse_bencode(&response_bytes)?;

    match bencode_response {
        BencodeValue::Dictionary(response_dict) => {
            let peers = response_dict
                .get("peers")
                .and_then(|v| {
                    if let BencodeValue::ByteString(b) = v {
                        Some(b)
                    } else {
                        None
                    }
                })
                .ok_or("Invalid peers data in tracker response")?
                .chunks(6)
                .map(|chunk| Peer {
                    ip: Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                    port: u16::from_be_bytes([chunk[4], chunk[5]]),
                })
                .collect();

            let interval = response_dict
                .get("interval")
                .and_then(|v| {
                    if let BencodeValue::Integer(i) = v {
                        Some(*i)
                    } else {
                        None
                    }
                })
                .ok_or("Invalid or missing interval in tracker response")?;

            Ok(TrackerInfo { peers, interval })
        }
        _ => Err("Invalid tracker response format".into()),
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <torrent_file>", args[0]);
        std::process::exit(1);
    }

    let torrent_path = &args[1];
    let torrent_data = fs::read(torrent_path)?;
    let torrent_file = parse_torrent_file(&torrent_data)?;

    println!("Torrent File Information:");
    println!("Announce URL: {}", torrent_file.announce);
    println!("File Name: {}", torrent_file.info.name);
    println!("File Length: {} bytes", torrent_file.info.length);
    println!("Piece Length: {} bytes", torrent_file.info.piece_length);
    println!("Number of Pieces: {}", torrent_file.info.pieces.len());
    println!("Info Hash: {}", hex::encode(torrent_file.info_hash));

    println!("\nContacting tracker...");
    match get_peers(&torrent_file).await {
        Ok(tracker_info) => {
            println!("Received {} peers from tracker:", tracker_info.peers.len());
            let peer_id = generate_peer_id(); // Generate a unique peer_id for the handshake

            let mut connected = false;
            for peer in &tracker_info.peers {
                println!("\nAttempting to connect to peer {}: {}", peer.ip, peer.port);
                match connect_to_peer(peer, Duration::from_secs(3)).await {
                    Ok(mut stream) => {
                        println!("Successfully connected to peer {}:{}", peer.ip, peer.port);

                        // Send handshake to the peer
                        send_handshake(&mut stream, torrent_file.info_hash, peer_id).await?;
                        
                        // Receive handshake from the peer and validate
                        match receive_handshake(&mut stream, torrent_file.info_hash).await {
                            Ok(_) => {
                                println!("Handshake completed with peer!");
                                connected = true;
                                // You can now start exchanging messages with the peer using the BitTorrent protocol.
                                break; // Exit the loop on successful handshake
                            }
                            Err(e) => println!("Failed to complete handshake: {}", e),
                        }

                        drop(stream);
                    }
                    Err(e) => println!("Failed to connect to peer {}:{}: {}", peer.ip, peer.port, e),
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
