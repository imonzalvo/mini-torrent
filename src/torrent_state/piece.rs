use std::sync::atomic::{AtomicBool, Ordering};

use sha1::{Digest, Sha1};

use super::errors::TorrentError;

pub struct Piece {
    index: usize,
    size: usize,
    hash: [u8; 20],
}

impl Piece {
    pub fn new(index: usize, size: usize, hash: [u8; 20]) -> Self {
        Self { index, size, hash }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn num_blocks(&self) -> usize {
        (self.size + 16383) / 16384 // Round up division
    }

    pub fn block_info(&self, block_index: usize) -> (usize, usize) {
        let begin = block_index * 16384;
        let length = std::cmp::min(16384, self.size - begin);
        (begin, length)
    }
}

pub struct PieceManager {
    pieces: Vec<Piece>,
    downloaded_pieces: Vec<AtomicBool>,
    piece_size: usize,
}

impl PieceManager {
    pub fn new(
        piece_count: usize,
        piece_size: usize,
        pieces_hashes: Vec<[u8; 20]>,
        total_length: u64,
    ) -> Self {
        let pieces = pieces_hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| {
                let size = if index == piece_count - 1 {
                    (total_length as usize) - (index * piece_size)
                } else {
                    piece_size
                };
                Piece::new(index, size, hash)
            })
            .collect();

        Self {
            pieces,
            downloaded_pieces: (0..piece_count).map(|_| AtomicBool::new(false)).collect(),
            piece_size,
        }
    }

    pub fn piece_size(&self) -> usize {
        self.piece_size
    }

    pub fn total_pieces(&self) -> usize {
        self.pieces.len()
    }

    pub fn get_piece(&self, index: usize) -> Result<&Piece, TorrentError> {
        self.pieces.get(index).ok_or(TorrentError::PieceNotFound)
    }
    pub fn verify_piece(&self, piece_index: usize, piece_data: &[u8]) -> bool {
        let piece = match self.pieces.get(piece_index) {
            Some(p) => p,
            None => return false,
        };

        let mut hasher = Sha1::new();
        hasher.update(piece_data);
        let result = hasher.finalize();

        result.as_slice() == piece.hash
    }

    pub fn mark_piece_downloaded(&self, piece_index: usize) {
        if piece_index < self.downloaded_pieces.len() {
            self.downloaded_pieces[piece_index].store(true, Ordering::Release);
        }
    }

    pub fn all_pieces_downloaded(&self) -> bool {
        self.downloaded_pieces
            .iter()
            .all(|piece| piece.load(Ordering::Acquire))
    }

    pub fn mark_piece_not_downloaded(&self, piece_index: usize) {
        if piece_index < self.downloaded_pieces.len() {
            self.downloaded_pieces[piece_index].store(false, Ordering::Release);
        }
    }

    pub fn is_piece_downloaded(&self, piece_index: usize) -> bool {
        self.downloaded_pieces
            .get(piece_index)
            .map_or(false, |piece| piece.load(Ordering::Acquire))
    }

    pub fn get_missing_piece(&self) -> Option<usize> {
        self.downloaded_pieces
            .iter()
            .enumerate()
            .find(|(_, piece)| !piece.load(Ordering::Acquire))
            .map(|(index, _)| index)
    }

    pub fn print_downloaded_pieces(&self) {
        let pieces: String = self
            .downloaded_pieces
            .iter()
            .map(|piece| {
                if piece.load(Ordering::Acquire) {
                    '1'
                } else {
                    '0'
                }
            })
            .collect();
        println!("[{}]", pieces);
    }
}
