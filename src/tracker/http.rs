use std::{error::Error, net::Ipv4Addr, str::FromStr};

use super::{Tracker, TrackerInfo};
use crate::{bencode_parser::{parse_bencode, BencodeValue}, torrent_file::TorrentFile, tracker::generate_peer_id, Peer};
use async_trait::async_trait;
use reqwest::Client;

pub struct HttpTracker<'a> {
    pub announce_url: String,
    pub torrent_file: &'a TorrentFile,
}

#[async_trait]
impl<'a> Tracker for HttpTracker<'a> {
    async fn get_peers(&self) -> Result<TrackerInfo, Box<dyn Error>> {
        let peer_id = generate_peer_id();
        let port = 6881;

        let info_hash = urlencoding::encode_binary(&self.torrent_file.info_hash);
        let binary_peer_id = urlencoding::encode_binary(&peer_id);

        let url = format!(
            "{}?info_hash={}&peer_id={}&port={}&uploaded=0&downloaded=0&left={}&compact=1",
            self.announce_url, info_hash, binary_peer_id, port, self.torrent_file.info.length
        );

        println!("Calling HTTP URL {}", url);

        let client = Client::new();
        let response = client.get(&url).send().await?;
        let response_bytes = response.bytes().await?;

        parse_tracker_response(&response_bytes)
    }
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
