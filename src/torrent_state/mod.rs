mod errors;
pub mod peer;
mod piece;

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::time::Duration;

use errors::TorrentError;
use peer::{Peer, PeerState};
use piece::PieceManager;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::handshake::{receive_handshake, send_handshake};
use crate::message::{read_message, send_message, PeerMessage};
use crate::tracker::generate_peer_id;

pub struct TorrentState {
    peers: Vec<PeerState>,
    piece_manager: PieceManager,
    file: File,
    info_hash: [u8; 20],
}

impl TorrentState {
    pub fn new(
        piece_count: usize,
        piece_size: usize,
        file_path: &str,
        total_length: u64,
        pieces_hashes: Vec<[u8; 20]>,
        info_hash: [u8; 20],
    ) -> io::Result<Self> {
        let file = File::create(file_path)?;
        file.set_len(total_length)?;

        Ok(Self {
            peers: Vec::new(),
            piece_manager: PieceManager::new(piece_count, piece_size, pieces_hashes, total_length),
            file,
            info_hash,
        })
    }

    pub async fn connect_and_download(&mut self, peers: Vec<Peer>) -> Result<(), TorrentError> {
        for peer in peers {
            match self.connect_to_peer(&peer, Duration::from_secs(3)).await {
                Ok(stream) => {
                    println!("Successfully connected to peer {}", peer);
                    let mut peer_state = PeerState::new(peer);
                    peer_state.set_handshaked(true);
                    self.peers.push(peer_state);

                    if let Err(e) = self.download_from_peer(stream).await {
                        eprintln!("Error downloading from peer: {}", e);
                        self.peers.pop(); // Remove the failed peer
                    } else {
                        return Ok(());
                    }
                }
                Err(e) => {
                    println!("Failed to connect to peer {}: {}", peer, e);
                }
            }
        }
        Err(TorrentError::NoPeersAvailable)
    }

    async fn connect_to_peer(
        &self,
        peer: &Peer,
        timeout_duration: Duration,
    ) -> Result<TcpStream, TorrentError> {
        let addr = SocketAddr::new(peer.ip.into(), peer.port);
        match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                println!("Connected to peer: {}", addr);
                Ok(stream)
            }
            Ok(Err(e)) => Err(TorrentError::ConnectionFailed(addr, e.to_string())),
            Err(_) => Err(TorrentError::ConnectionTimeout(addr)),
        }
    }

    async fn download_from_peer(&mut self, mut stream: TcpStream) -> Result<(), TorrentError> {
        let peer_id = generate_peer_id();

        send_handshake(&mut stream, self.info_hash, peer_id).await?;
        receive_handshake(&mut stream, self.info_hash).await?;

        send_message(&mut stream, PeerMessage::Unchoke).await?;
        send_message(&mut stream, PeerMessage::Interested).await?;

        self.handle_initial_messages(&mut stream).await?;

        while let Some(missing_piece) = self.piece_manager.get_missing_piece() {
            self.download_piece(&mut stream, missing_piece).await?;
            self.piece_manager.print_downloaded_pieces();
        }

        println!("Download complete");
        Ok(())
    }

    async fn handle_initial_messages(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), TorrentError> {
        loop {
            match read_message(stream).await? {
                PeerMessage::Unchoke => {
                    println!("Peer has unchoked us. We can now request pieces.");
                    let peer_state = self
                        .peers
                        .first_mut()
                        .ok_or(TorrentError::NoPeersAvailable)?;
                    peer_state.set_peer_choking(false);
                    break;
                }
                PeerMessage::Bitfield(bitfield) => {
                    let peer_state = self
                        .peers
                        .last_mut()
                        .ok_or(TorrentError::NoPeersAvailable)?;
                    peer_state.update_bitfield(bitfield, self.piece_manager.total_pieces());
                }
                _ => {} // Ignore other messages for now
            }
        }
        Ok(())
    }

    async fn download_piece(
        &mut self,
        stream: &mut TcpStream,
        piece_index: usize,
    ) -> Result<(), TorrentError> {
        let (piece_size, num_blocks) = {
            let piece = self.piece_manager.get_piece(piece_index)?;
            (piece.size(), piece.num_blocks())
        };
        let mut piece_data = Vec::with_capacity(piece_size);

        for block_index in 0..num_blocks {
            let (begin, length) = {
                let piece = self.piece_manager.get_piece(piece_index)?;
                piece.block_info(block_index)
            };
            self.request_piece(stream, piece_index, begin, length)
                .await?;

            loop {
                match read_message(stream).await? {
                    PeerMessage::Piece {
                        index,
                        begin: msg_begin,
                        block,
                    } => {
                        if index as usize == piece_index && msg_begin as usize == begin {
                            piece_data.extend_from_slice(&block);
                            break;
                        } else {
                            return Err(TorrentError::IncorrectPieceData);
                        }
                    }
                    PeerMessage::Unchoke => continue, // Ignore during piece download
                    msg => return Err(TorrentError::UnexpectedMessage(format!("{:?}", msg))),
                }
            }
        }

        if !self.piece_manager.verify_piece(piece_index, &piece_data) {
            return Err(TorrentError::PieceVerificationFailed(piece_index));
        }

        self.write_piece(piece_index, &piece_data)?;
        self.piece_manager.mark_piece_downloaded(piece_index);

        let have_message = PeerMessage::Have(piece_index as u32);
        send_message(stream, have_message).await?;

        println!("Successfully downloaded piece {}", piece_index);
        Ok(())
    }

    async fn request_piece(
        &mut self,
        stream: &mut TcpStream,
        piece_index: usize,
        begin: usize,
        length: usize,
    ) -> Result<(), TorrentError> {
        let request_message = PeerMessage::Request {
            index: piece_index as u32,
            begin: begin as u32,
            length: length as u32,
        };

        send_message(stream, request_message).await?;
        println!(
            "Requested piece {} (begin: {}, length: {})",
            piece_index, begin, length
        );
        Ok(())
    }

    fn write_piece(&mut self, piece_index: usize, data: &[u8]) -> io::Result<()> {
        let offset = piece_index * self.piece_manager.piece_size();
        self.file.seek(SeekFrom::Start(offset as u64))?;
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }
}
