mod errors;
pub mod peer;
mod piece;

use futures::future::join_all;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use errors::TorrentError;
use peer::{Peer, PeerState};
use piece::PieceManager;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{self, JoinHandle};
use tokio::time::{interval, timeout};

use crate::handshake::{receive_handshake, send_handshake};
use crate::message::{read_message, send_message, PeerMessage};
use crate::tracker::generate_peer_id;

pub struct TorrentState {
    piece_manager: Arc<Mutex<PieceManager>>,
    file: Arc<Mutex<File>>,
    info_hash: [u8; 20],
    download_complete: Arc<AtomicBool>,
    peer_states: Arc<Mutex<Vec<PeerState>>>,
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
            piece_manager: Arc::new(Mutex::new(PieceManager::new(
                piece_count,
                piece_size,
                pieces_hashes,
                total_length,
            ))),
            file: Arc::new(Mutex::new(file)),
            info_hash,
            download_complete: Arc::new(AtomicBool::new(false)),
            peer_states: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn connect_and_download(&self, peers: Vec<Peer>) -> Result<(), TorrentError> {
        let (tx, mut rx) = mpsc::channel(100);
        let handles = self.spawn_peer_tasks(peers, tx).await;

        self.monitor_download(&mut rx).await;

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
    async fn spawn_peer_tasks(
        &self,
        peers: Vec<Peer>,
        tx: mpsc::Sender<()>,
    ) -> Vec<JoinHandle<Result<(), TorrentError>>> {
        peers
            .into_iter()
            .map(|peer| {
                let piece_manager = Arc::clone(&self.piece_manager);
                let file = Arc::clone(&self.file);
                let info_hash = self.info_hash;
                let download_complete = Arc::clone(&self.download_complete);
                let peer_states = Arc::clone(&self.peer_states);
                let tx = tx.clone();

                task::spawn(async move {
                    println!("new task spawn for {:?}", peer.ip);
                    Self::download_from_peer(
                        peer,
                        piece_manager,
                        file,
                        info_hash,
                        download_complete,
                        peer_states,
                        tx,
                    )
                    .await
                })
            })
            .collect::<Vec<_>>()
    }

    async fn monitor_download(&self, rx: &mut mpsc::Receiver<()>) {
        let mut interval = interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if self.download_complete.load(Ordering::Relaxed) {
                        println!("Download complete. Stopping all connections.");
                        break;
                    }
                }
                Some(_) = rx.recv() => {
                    if self.is_download_complete().await {
                        self.download_complete.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    async fn connect_to_peer(
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

    async fn download_from_peer(
        peer: Peer,
        piece_manager: Arc<Mutex<PieceManager>>,
        file: Arc<Mutex<File>>,
        info_hash: [u8; 20],
        download_complete: Arc<AtomicBool>,
        peer_states: Arc<Mutex<Vec<PeerState>>>,
        tx: mpsc::Sender<()>,
    ) -> Result<(), TorrentError> {
        let mut stream = match Self::connect_to_peer(&peer, Duration::from_secs(3)).await {
            Ok(stream) => stream,
            Err(e) => {
                println!("Failed to connect to peer {}: {}", peer, e);
                return Err(e);
            }
        };

        println!("Successfully connected to peer {}", peer);
        let peer_id = generate_peer_id();

        Self::perform_handshake(&mut stream, info_hash, peer_id).await?;
        let peer_state_index = Self::initialize_peer_state(peer, &peer_states).await;

        send_message(&mut stream, PeerMessage::Unchoke).await?;
        send_message(&mut stream, PeerMessage::Interested).await?;

        let piece_count = {
            let piece_manager = piece_manager.lock().await;
            piece_manager.total_pieces()
        };

        Self::handle_initial_messages(&mut stream, &peer_states, peer_state_index, piece_count).await?;

        Self::download_pieces_loop(
            &mut stream,
            piece_manager,
            file,
            download_complete,
            peer_states,
            peer_state_index,
            tx,
            peer,
        )
        .await
    }

    async fn perform_handshake(
        stream: &mut TcpStream,
        info_hash: [u8; 20],
        peer_id: [u8; 20],
    ) -> Result<(), TorrentError> {
        send_handshake(stream, info_hash, peer_id).await?;
        receive_handshake(stream, info_hash).await?;
        Ok(())
    }

    async fn initialize_peer_state(
        peer: Peer,
        peer_states: &Arc<Mutex<Vec<PeerState>>>,
    ) -> usize {
        let peer_state = PeerState::new(peer);
        let mut peer_states = peer_states.lock().await;
        peer_states.push(peer_state);
        peer_states.len() - 1
    }

    async fn download_pieces_loop(
        stream: &mut TcpStream,
        piece_manager: Arc<Mutex<PieceManager>>,
        file: Arc<Mutex<File>>,
        download_complete: Arc<AtomicBool>,
        peer_states: Arc<Mutex<Vec<PeerState>>>,
        peer_state_index: usize,
        tx: mpsc::Sender<()>,
        peer: Peer,
    ) -> Result<(), TorrentError> {
        loop {
            if download_complete.load(Ordering::Relaxed) {
                println!(
                    "Download complete signal received. Closing connection with peer {}.",
                    peer
                );
                break;
            }

            let missing_piece_index = {
                let piece_manager = piece_manager.lock().await;
                let piece_index = piece_manager.get_missing_piece();

                if piece_index.is_none() {
                    println!("All pieces downloaded");
                    break;
                }
                piece_manager.mark_piece_downloaded(piece_index.unwrap());
                piece_index.unwrap()
            };

            if !Self::peer_has_piece(&peer_states, peer_state_index, missing_piece_index).await {
                let piece_manager = piece_manager.lock().await;
                piece_manager.mark_piece_not_downloaded(missing_piece_index);
                continue;
            }

            match Self::download_piece(
                stream,
                missing_piece_index,
                &piece_manager,
                &file,
                &peer_states,
                peer_state_index,
            )
            .await
            {
                Ok(()) => {
                    let piece_managed_locked = piece_manager.lock().await;
                    tx.send(())
                        .await
                        .expect("Failed to send piece completion signal");
                    println!(
                        "Successfully downloaded piece {} from peer {}",
                        missing_piece_index, peer
                    );
                    piece_managed_locked.print_downloaded_pieces();
                }
                Err(e) => {
                    eprintln!(
                        "Error downloading piece {} from peer {}: {}",
                        missing_piece_index, peer, e
                    );
                    let piece_manager = piece_manager.lock().await;
                    piece_manager.mark_piece_not_downloaded(missing_piece_index);
                }
            }
        }
        Ok(())
    }

    async fn peer_has_piece(
        peer_states: &Arc<Mutex<Vec<PeerState>>>,
        peer_state_index: usize,
        piece_index: usize,
    ) -> bool {
        let peer_states = peer_states.lock().await;
        let peer_state = &peer_states[peer_state_index];
        peer_state.has_piece(piece_index)
    }

    async fn is_download_complete(&self) -> bool {
        let piece_manager = self.piece_manager.lock().await;
        piece_manager.all_pieces_downloaded()
    }

    async fn handle_initial_messages(
        stream: &mut TcpStream,
        peer_states: &Mutex<Vec<PeerState>>,
        peer_state_index: usize,
        piece_count: usize, // Add this parameter
    ) -> Result<(), TorrentError> {
        let mut bitfield_message_received = false;
        let mut unchoke_message_received = false;
        loop {
            match read_message(stream).await? {
                PeerMessage::Unchoke => {
                    println!(
                        "{:?} Peer has unchoked us. We can now request pieces.",
                        peer_state_index
                    );
                    let mut peer_states = peer_states.lock().await;
                    peer_states[peer_state_index].set_peer_choking(false);
                    unchoke_message_received = true;

                    if bitfield_message_received {
                        break;
                    };
                }
                PeerMessage::Bitfield(bitfield) => {
                    println!("{:?} Bitfield received", peer_state_index);
                    let mut peer_states = peer_states.lock().await;
                    peer_states[peer_state_index].update_bitfield(bitfield, piece_count);
                    bitfield_message_received = true;
                    if unchoke_message_received {
                        break;
                    }
                }
                _ => {} // Ignore other messages for now
            }
        }
        Ok(())
    }

    async fn download_piece(
        stream: &mut TcpStream,
        piece_index: usize,
        piece_manager: &Arc<Mutex<PieceManager>>,
        file: &Arc<Mutex<File>>,
        peer_states: &Mutex<Vec<PeerState>>,
        peer_state_index: usize,
    ) -> Result<(), TorrentError> {
        {
            let peer_states = peer_states.lock().await;
            let peer_state = &peer_states[peer_state_index];

            if peer_state.peer_choking {
                return Err(TorrentError::PeerChoking);
            }
        }
        let (piece_size, num_blocks) = {
            let piece_manager = piece_manager.lock().await;
            let piece = piece_manager.get_piece(piece_index)?;
            (piece.size(), piece.num_blocks())
        };

        let mut piece_data = Vec::with_capacity(piece_size);

        for block_index in 0..num_blocks {
            let (begin, length) = {
                let piece_manager = piece_manager.lock().await;
                let piece = piece_manager.get_piece(piece_index)?;
                piece.block_info(block_index)
            };
            Self::request_piece(stream, piece_index, begin, length).await?;

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

        let piece_valid = {
            let piece_manager = piece_manager.lock().await;
            piece_manager.verify_piece(piece_index, &piece_data)
        };

        if !piece_valid {
            return Err(TorrentError::PieceVerificationFailed(piece_index));
        }

        Self::write_piece(file, piece_manager, piece_index, &piece_data).await?;

        let piece_manager = piece_manager.lock().await;
        piece_manager.mark_piece_downloaded(piece_index);

        let have_message = PeerMessage::Have(piece_index as u32);
        send_message(stream, have_message).await?;

        Ok(())
    }

    async fn request_piece(
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

    async fn write_piece(
        file: &Arc<Mutex<File>>,
        piece_manager: &Arc<Mutex<PieceManager>>,
        piece_index: usize,
        data: &[u8],
    ) -> io::Result<()> {
        let mut file = file.lock().await;
        let piece_manager = piece_manager.lock().await;
        let offset = piece_index * piece_manager.piece_size();
        file.seek(SeekFrom::Start(offset as u64))?;
        file.write_all(data)?;
        file.flush()?;
        Ok(())
    }
}