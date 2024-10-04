mod bencode_parser;
mod handshake;
mod message;
mod torrent_state;

use bencode_parser::{parse_bencode, BencodeValue};
use handshake::receive_handshake;
use handshake::send_handshake;
use message::read_message;
use message::send_message;
use message::PeerMessage;
use rand::Rng;
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use torrent_state::PeerState;
use torrent_state::TorrentState;
use url::Url;

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

#[derive(Debug, Clone, Copy)]
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
        println!("{:?}", dict.get("name"));
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
    let info_hash = torrent.info_hash.clone();

    let url = Url::parse(&torrent.announce)?;

    match url.scheme() {
        "http" | "https" => get_peers_http(torrent, &peer_id, port).await,
        "udp" => get_peers_udp(torrent, &peer_id, port).await,
        _ => Err("Unsupported protocol in announce URL".into()),
    }
}

async fn get_peers_http(
    torrent: &TorrentFile,
    peer_id: &[u8; 20],
    port: u16,
) -> Result<TrackerInfo, Box<dyn std::error::Error>> {
    let info_hash = urlencoding::encode_binary(&torrent.info_hash);
    let binary_peer_id = urlencoding::encode_binary(peer_id);

    let url = format!(
        "{}?info_hash={}&peer_id={}&port={}&uploaded=0&downloaded=0&left={}&compact=1",
        torrent.announce, info_hash, binary_peer_id, port, torrent.info.length
    );

    println!("Calling HTTP URL {}", url);

    let client = Client::new();
    let response = client.get(&url).send().await?;
    let response_bytes = response.bytes().await?;

    parse_tracker_response(&response_bytes)
}

async fn get_peers_udp(
    torrent: &TorrentFile,
    peer_id: &[u8; 20],
    port: u16,
) -> Result<TrackerInfo, Box<dyn std::error::Error>> {
    let url = Url::parse(&torrent.announce)?;
    let host = url.host_str().ok_or("Invalid host in announce URL")?;
    let port = url.port().unwrap_or(80);

    println!("Connecting to UDP tracker: {}:{}", host, port);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let addr = format!("{}:{}", host, port);
    println!("here");

    socket.connect(&addr).await?;
    println!("here1");

    // Step 1: Connection request
    let connection_id = send_connection_request(&socket).await?;
    println!("here2");

    // Step 2: Announce request
    let transaction_id: u32 = rand::thread_rng().gen();
    let announce_request = create_announce_request(
        connection_id,
        transaction_id,
        &torrent.info_hash,
        peer_id,
        0,                                       // downloaded
        torrent.info.length.try_into().unwrap(), // left
        0,                                       // uploaded
        port,
    );
    println!("here3");

    socket.send(&announce_request).await?;

    let mut response = vec![0u8; 1024];
    let size = socket.recv(&mut response).await?;

    parse_udp_response(&response[..size])
}

async fn send_connection_request(socket: &UdpSocket) -> Result<u64, Box<dyn std::error::Error>> {
    let connection_id: u64 = 0x41727101980;
    let action: u32 = 0; // connect
    let transaction_id: u32 = rand::thread_rng().gen();

    let request = connection_id
        .to_be_bytes()
        .iter()
        .chain(&action.to_be_bytes())
        .chain(&transaction_id.to_be_bytes())
        .copied()
        .collect::<Vec<u8>>();

    socket.send(&request).await?;

    println!("here 21");
    let mut response = vec![0u8; 16];
    socket.recv(&mut response).await?;
    println!("here 22");

    let action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if action != 0 {
        return Err("Invalid action in connection response".into());
    }

    let received_transaction_id =
        u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if received_transaction_id != transaction_id {
        return Err("Transaction ID mismatch in connection response".into());
    }

    Ok(u64::from_be_bytes([
        response[8],
        response[9],
        response[10],
        response[11],
        response[12],
        response[13],
        response[14],
        response[15],
    ]))
}

fn create_announce_request(
    connection_id: u64,
    transaction_id: u32,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    downloaded: u64,
    left: u64,
    uploaded: u64,
    port: u16,
) -> Vec<u8> {
    let mut request = Vec::with_capacity(98);
    request.extend_from_slice(&connection_id.to_be_bytes());
    request.extend_from_slice(&1u32.to_be_bytes()); // action (announce)
    request.extend_from_slice(&transaction_id.to_be_bytes());
    request.extend_from_slice(info_hash);
    request.extend_from_slice(peer_id);
    request.extend_from_slice(&downloaded.to_be_bytes());
    request.extend_from_slice(&left.to_be_bytes());
    request.extend_from_slice(&uploaded.to_be_bytes());
    request.extend_from_slice(&0u32.to_be_bytes()); // event
    request.extend_from_slice(&0u32.to_be_bytes()); // IP address
    request.extend_from_slice(&0u32.to_be_bytes()); // key
    request.extend_from_slice(&(-1i32).to_be_bytes()); // num_want
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn parse_udp_response(response: &[u8]) -> Result<TrackerInfo, Box<dyn std::error::Error>> {
    if response.len() < 20 {
        return Err("UDP response too short".into());
    }

    let action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if action != 1 {
        return Err("Invalid action in announce response".into());
    }

    let interval = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);

    let peers = response[20..]
        .chunks(6)
        .map(|chunk| Peer {
            ip: Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
            port: u16::from_be_bytes([chunk[4], chunk[5]]),
        })
        .collect();

    Ok(TrackerInfo {
        peers,
        interval: interval as i64,
    })
}

fn parse_tracker_response(
    response_bytes: &[u8],
) -> Result<TrackerInfo, Box<dyn std::error::Error>> {
    let (bencode_response, _) = parse_bencode(response_bytes)?;

    match bencode_response {
        BencodeValue::Dictionary(response_dict) => {
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

            let peers = match response_dict.get("peers") {
                Some(BencodeValue::ByteString(b)) => {
                    // Compact response
                    b.chunks(6)
                        .map(|chunk| Peer {
                            ip: Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                            port: u16::from_be_bytes([chunk[4], chunk[5]]),
                        })
                        .collect()
                }
                Some(BencodeValue::List(peer_list)) => {
                    // Non-compact response
                    peer_list
                        .iter()
                        .filter_map(|peer| {
                            if let BencodeValue::Dictionary(peer_dict) = peer {
                                let ip = peer_dict
                                    .get("ip")
                                    .and_then(|v| {
                                        if let BencodeValue::ByteString(s) = v {
                                            std::str::from_utf8(s).ok()
                                        } else {
                                            None
                                        }
                                    })
                                    .and_then(|ip_str| Ipv4Addr::from_str(ip_str).ok());

                                let port = peer_dict.get("port").and_then(|v| {
                                    if let BencodeValue::Integer(p) = v {
                                        Some(*p as u16)
                                    } else {
                                        None
                                    }
                                });

                                match (ip, port) {
                                    (Some(ip), Some(port)) => Some(Peer { ip, port }),
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        })
                        .collect()
                }
                _ => return Err("Invalid peers data in tracker response".into()),
            };

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
    let torrent_file = parse_torrent_file(&torrent_data)?;

    println!("Torrent File Information:");
    println!("Announce URL: {}", torrent_file.announce);
    println!("File Name: {}", torrent_file.info.name);
    println!("File Length: {} bytes", torrent_file.info.length);
    println!("Piece Length: {} bytes", torrent_file.info.piece_length);
    println!("Number of Pieces: {}", torrent_file.info.pieces.len());
    println!("Info Hash: {}", hex::encode(torrent_file.info_hash));

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
    println!("\nContacting tracker...");
    match get_peers(&torrent_file).await {
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
