mod bencode_parser;

use bencode_parser::{parse_bencode, BencodeValue};
use rand::Rng;
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use urlencoding::encode;

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

fn print_first_ten(values: &Vec<u8>) {
    let first_ten = &values[..10]; // Get the first 10 elements

    for value in first_ten {
        print!("{:02x} ", value); // Print each value in hexadecimal format
    }
    println!(); // Newline after printing
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
        println!("infooo1 {:?}", info_value);
        
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
fn generate_peer_id() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..20).map(|_| rng.gen::<u8>()).collect();
    format!("-RS0001-{}", hex::encode(&random_bytes[..12]))
}

async fn get_peers(torrent: &TorrentFile) -> Result<Vec<Peer>, Box<dyn std::error::Error>> {
    let peer_id = generate_peer_id();
    let port = 6881; // You can randomize this between 6881-6889 if needed
    let info_hash = urlencoding::encode_binary(&torrent.info_hash);

    let url = format!(
        "{}?info_hash={}&peer_id={}&port={}&uploaded=0&downloaded=0&left={}&compact=1",
        torrent.announce,
        info_hash,
        encode(&peer_id),
        port,
        torrent.info.length
    );

    println!("Calling URL {}", url);

    let client = Client::new();
    let response = client.get(&url).send().await?;
    let response_bytes = response.bytes().await?;

    let (bencode_response, _) = parse_bencode(&response_bytes)?;

    if let BencodeValue::Dictionary(response_dict) = bencode_response {
        if let Some(BencodeValue::ByteString(peers_bytes)) = response_dict.get("peers") {
            let peers = peers_bytes
                .chunks(6)
                .map(|chunk| {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    Peer { ip, port }
                })
                .collect();
            Ok(peers)
        } else {
            Err("Invalid peers data in tracker response".into())
        }
    } else {
        Err("Invalid tracker response format".into())
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

    println!("Lenght???? {:?}", torrent_file.info_hash);

    println!("\nContacting tracker...");
    match get_peers(&torrent_file).await {
        Ok(peers) => {
            println!("Received {} peers from tracker:", peers.len());
            for (i, peer) in peers.iter().enumerate() {
                println!("Peer {}: {}:{}", i + 1, peer.ip, peer.port);
            }
        }
        Err(e) => println!("Failed to get peers: {}", e),
    }

    Ok(())
}
