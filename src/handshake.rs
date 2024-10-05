use sha1::{Digest, Sha1};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Constants for the BitTorrent protocol
const PSTR: &str = "BitTorrent protocol";
const RESERVED: [u8; 8] = [0; 8]; // Reserved bytes (typically set to zero)

// Struct for the BitTorrent handshake
#[derive(Debug)]
pub struct Handshake {
    pstrlen: u8,
    pstr: String,
    reserved: [u8; 8],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
}

impl Handshake {
    // Create a new handshake instance
    fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Handshake {
            pstrlen: PSTR.len() as u8,
            pstr: PSTR.to_string(),
            reserved: RESERVED,
            info_hash,
            peer_id,
        }
    }

    // Serialize the handshake into bytes for sending
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(68);
        buf.push(self.pstrlen);
        buf.extend_from_slice(self.pstr.as_bytes());
        buf.extend_from_slice(&self.reserved);
        buf.extend_from_slice(&self.info_hash);
        buf.extend_from_slice(&self.peer_id);
        buf
    }

    // Deserialize the handshake from bytes (this will be used for receiving the handshake)
    pub fn deserialize(buf: &[u8]) -> Result<Self, String> {
        if buf.len() != 68 {
            return Err("Invalid handshake length".to_string());
        }

        let pstrlen = buf[0];
        if pstrlen as usize != PSTR.len() {
            return Err("Invalid protocol identifier length".to_string());
        }

        let pstr = String::from_utf8(buf[1..20].to_vec())
            .map_err(|_| "Invalid protocol identifier".to_string())?;
        if pstr != PSTR {
            return Err("Invalid protocol identifier".to_string());
        }

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[20..28]);

        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[28..48]);

        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[48..68]);

        Ok(Handshake {
            pstrlen,
            pstr,
            reserved,
            info_hash,
            peer_id,
        })
    }
}

// Function to send the handshake to a peer
pub async fn send_handshake(
    stream: &mut TcpStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
) -> io::Result<()> {
    let handshake = Handshake::new(info_hash, peer_id);
    let serialized_handshake = handshake.serialize();
    stream.write_all(&serialized_handshake).await?;
    println!("Handshake sent: {:?}", handshake.peer_id);
    Ok(())
}

// Function to receive and validate the handshake from a peer
pub async fn receive_handshake(
    stream: &mut TcpStream,
    expected_info_hash: [u8; 20],
) -> Result<Handshake, String> {
    let mut buf = [0u8; 68]; // Handshake is exactly 68 bytes
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    let handshake = Handshake::deserialize(&buf)?;
    println!("Received handshake: {:?}", handshake.peer_id);

    // Validate the info_hash
    if handshake.info_hash != expected_info_hash {
        return Err("Info hash mismatch".to_string());
    }

    Ok(handshake)
}
