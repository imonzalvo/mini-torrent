use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TorrentError {
    #[error("Failed to connect to {0}: {1}")]
    ConnectionFailed(SocketAddr, String),

    #[error("Connection to {0} timed out")]
    ConnectionTimeout(SocketAddr),

    #[error("No peers available")]
    NoPeersAvailable,

    #[error("Received incorrect piece data")]
    IncorrectPieceData,

    #[error("Unexpected message: {0}")]
    UnexpectedMessage(String),

    #[error("Piece verification failed for piece {0}")]
    PieceVerificationFailed(usize),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Piece not found")]
    PieceNotFound,

    #[error("Message error: {0}")]
    MessageError(String),
}

impl From<String> for TorrentError {
    fn from(error: String) -> Self {
        TorrentError::MessageError(error)
    }
}
