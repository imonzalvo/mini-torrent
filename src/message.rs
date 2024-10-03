use std::convert::TryInto;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Define a PeerMessage enum to represent all possible message types
#[derive(Debug)]
pub enum PeerMessage {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),         // Piece index
    Bitfield(Vec<u8>), // Bitfield of pieces
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
}

impl PeerMessage {
    // Serialize a PeerMessage into a byte vector for sending
    fn serialize(&self) -> Vec<u8> {
        match self {
            PeerMessage::KeepAlive => vec![0, 0, 0, 0], // Keep-alive has no ID or payload
            PeerMessage::Choke => vec![0, 0, 0, 1, 0],  // Length = 1, ID = 0
            PeerMessage::Unchoke => vec![0, 0, 0, 1, 1], // Length = 1, ID = 1
            PeerMessage::Interested => vec![0, 0, 0, 1, 2], // Length = 1, ID = 2
            PeerMessage::NotInterested => vec![0, 0, 0, 1, 3], // Length = 1, ID = 3
            PeerMessage::Have(piece_index) => {
                let mut buf = vec![0, 0, 0, 5, 4]; // Length = 5, ID = 4
                buf.extend(&piece_index.to_be_bytes());
                buf
            }
            PeerMessage::Bitfield(bitfield) => {
                let mut buf = vec![];
                let len = 1 + bitfield.len();
                buf.extend(&(len as u32).to_be_bytes()); // Length prefix
                buf.push(5); // ID = 5
                buf.extend(bitfield);
                buf
            }
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                let mut buf = vec![0, 0, 0, 13, 6]; // Length = 13, ID = 6
                buf.extend(&index.to_be_bytes());
                buf.extend(&begin.to_be_bytes());
                buf.extend(&length.to_be_bytes());
                buf
            }
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                let mut buf = vec![];
                let len = 9 + block.len();
                buf.extend(&(len as u32).to_be_bytes());
                buf.push(7); // ID = 7
                buf.extend(&index.to_be_bytes());
                buf.extend(&begin.to_be_bytes());
                buf.extend(block);
                buf
            }
        }
    }

    // Deserialize a byte buffer into a PeerMessage
    fn deserialize(buf: &[u8]) -> Result<PeerMessage, String> {
        if buf.is_empty() {
            return Err("Message too short".to_string());
        }

        // The first byte of buf is the message ID
        let message_id = buf[0];

        match message_id {
            0 => Ok(PeerMessage::Choke),
            1 => Ok(PeerMessage::Unchoke),
            2 => Ok(PeerMessage::Interested),
            3 => Ok(PeerMessage::NotInterested),
            4 => {
                if buf.len() < 5 {
                    return Err("Invalid HAVE message".to_string());
                }
                let piece_index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                Ok(PeerMessage::Have(piece_index))
            }
            5 => {
                let bitfield = buf[1..].to_vec();
                Ok(PeerMessage::Bitfield(bitfield))
            }
            6 => {
                if buf.len() < 13 {
                    return Err("Invalid REQUEST message".to_string());
                }
                let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
                let length = u32::from_be_bytes(buf[9..13].try_into().unwrap());
                Ok(PeerMessage::Request {
                    index,
                    begin,
                    length,
                })
            }
            7 => {
                if buf.len() < 9 {
                    return Err("Invalid PIECE message".to_string());
                }
                let index = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                let begin = u32::from_be_bytes(buf[5..9].try_into().unwrap());
                let block = buf[9..].to_vec();
                Ok(PeerMessage::Piece {
                    index,
                    begin,
                    block,
                })
            }
            _ => Err("Unknown message ID".to_string()),
        }
    }
}

// Function to send a PeerMessage to a peer
pub async fn send_message(stream: &mut TcpStream, message: PeerMessage) -> io::Result<()> {
    let serialized_message = message.serialize();
    stream.write_all(&serialized_message).await?;
    Ok(())
}

// Function to read a message from a peer
pub async fn read_message(stream: &mut TcpStream) -> Result<PeerMessage, String> {
    // First, read the length prefix (4 bytes)
    let mut length_prefix_buf = [0u8; 4];
    stream
        .read_exact(&mut length_prefix_buf)
        .await
        .map_err(|e| e.to_string())?;

    let length_prefix = u32::from_be_bytes(length_prefix_buf);

    if length_prefix == 0 {
        return Ok(PeerMessage::KeepAlive);
    }

    // Read the message (length_prefix bytes, which includes message_id and payload)
    let mut message_buf = vec![0u8; length_prefix as usize];
    stream
        .read_exact(&mut message_buf)
        .await
        .map_err(|e| e.to_string())?;

    // Deserialize the message buffer into a PeerMessage
    PeerMessage::deserialize(&message_buf)
}
