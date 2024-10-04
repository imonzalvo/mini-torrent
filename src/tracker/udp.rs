use std::{error::Error, net::Ipv4Addr};

use super::{Tracker, TrackerInfo};
use crate::{torrent_file::TorrentFile, tracker::generate_peer_id, Peer};
use async_trait::async_trait;
use rand::Rng;
use tokio::net::UdpSocket;
use url::Url;

pub struct UdpTracker<'a> {
    pub announce_url: String,
    pub torrent_file: &'a TorrentFile,
}

#[async_trait]
impl<'a> Tracker for UdpTracker<'a> {
    async fn get_peers(&self) -> Result<TrackerInfo, Box<dyn Error>> {
        let peer_id = generate_peer_id();

        let url = Url::parse(&self.announce_url)?;
        let host = url.host_str().ok_or("Invalid host in announce URL")?;
        let port = url.port().unwrap_or(80);

        println!("Connecting to UDP tracker: {}:{}", host, port);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", host, port);

        socket.connect(&addr).await?;

        // Step 1: Connection request
        let connection_id = send_connection_request(&socket).await?;

        // Step 2: Announce request
        let transaction_id: u32 = rand::thread_rng().gen();
        let announce_request = create_announce_request(
            connection_id,
            transaction_id,
            &self.torrent_file.info_hash,
            &peer_id,
            0,                                                 // downloaded
            self.torrent_file.info.length.try_into().unwrap(), // left
            0,                                                 // uploaded
            port,
        );

        socket.send(&announce_request).await?;

        let mut response = vec![0u8; 1024];
        let size = socket.recv(&mut response).await?;

        parse_udp_response(&response[..size])
    }
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

    let mut response = vec![0u8; 16];
    socket.recv(&mut response).await?;

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
