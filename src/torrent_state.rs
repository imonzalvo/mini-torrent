use crate::Peer;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};

#[derive(Debug)]
pub struct TorrentState {
    pub peers: Vec<PeerState>,
    pub downloaded_pieces: Vec<bool>,
    pub piece_size: usize,
    pub total_pieces: usize,
    pub file: File,
    pub total_length: u64,
}

impl TorrentState {
    pub fn new(
        piece_count: usize,
        piece_size: usize,
        file_path: &str,
        total_length: u64,
    ) -> io::Result<Self> {
        let file = File::create(file_path)?;
        file.set_len(total_length)?;

        Ok(Self {
            peers: Vec::new(),
            downloaded_pieces: vec![false; piece_count],
            piece_size,
            total_pieces: piece_count,
            file,
            total_length,
        })
    }

    pub fn mark_piece_downloaded(&mut self, piece_index: usize) {
        if piece_index < self.downloaded_pieces.len() {
            self.downloaded_pieces[piece_index] = true;
        }
    }

    pub fn is_piece_downloaded(&self, piece_index: usize) -> bool {
        self.downloaded_pieces
            .get(piece_index)
            .copied()
            .unwrap_or(false)
    }

    pub fn get_missing_piece(&self) -> Option<usize> {
        self.downloaded_pieces
            .iter()
            .position(|&have_piece| !have_piece)
    }

    pub fn find_peer_with_piece(&self, piece_index: usize) -> Option<&PeerState> {
        self.peers.iter().find(|peer| peer.has_piece(piece_index))
    }

    pub fn print_downloaded_pieces(&self) {
        let pieces: Vec<char> = self
            .downloaded_pieces
            .iter()
            .map(|&downloaded| if downloaded { '1' } else { '0' })
            .collect();
        println!("[{}]", pieces.into_iter().collect::<String>());
    }

    pub fn write_piece(&mut self, piece_index: usize, data: &[u8]) -> io::Result<()> {
        let offset = piece_index * self.piece_size;
        self.file.seek(SeekFrom::Start(offset as u64))?;
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn is_download_complete(&self) -> bool {
        self.downloaded_pieces.iter().all(|&piece| piece)
    }
}
#[derive(Debug)]
pub struct PeerState {
    pub peer: Peer,
    pub has_handshake: bool,
    pub bitfield: Vec<bool>,
    pub am_choking: bool,
    pub am_interested: bool,
    pub peer_choking: bool,
    pub peer_interested: bool,
}

impl PeerState {
    pub fn new(peer: Peer) -> Self {
        Self {
            peer,
            has_handshake: false,
            bitfield: Vec::new(),
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
        }
    }

    pub fn update_bitfield(&mut self, bitfield: Vec<u8>, piece_count: usize) {
        self.bitfield = (0..piece_count)
            .map(|i| {
                let byte = i / 8;
                let bit = 7 - (i % 8);
                (bitfield[byte] >> bit) & 1 == 1
            })
            .collect();
    }

    pub fn has_piece(&self, piece_index: usize) -> bool {
        self.bitfield.get(piece_index).copied().unwrap_or(false)
    }
}
