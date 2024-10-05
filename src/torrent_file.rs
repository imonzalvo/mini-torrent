use crate::bencode_parser::{self, parse_bencode, BencodeValue};
use sha1::{Digest, Sha1};
use std::{collections::HashMap, fmt, string::FromUtf8Error};

#[derive(Debug)]
pub struct TorrentFile {
    pub info: Info,
    pub announce: String,
    pub info_hash: [u8; 20],
}

#[derive(Debug)]
pub struct Info {
    pub piece_length: i64,
    pub pieces: Vec<u8>,
    pub name: String,
    pub length: i64,
}


impl TorrentFile {
    pub fn from_bencoded(data: &[u8]) -> Result<Self, String> {
        let (bencode, _) = parse_bencode(data)?;
        let dict = match bencode {
            BencodeValue::Dictionary(dict) => dict,
            _ => return Err("Invalid torrent file format".to_string()),
        };

        let announce = Self::extract_string(&dict, "announce")?;
        let info_value = dict.get("info").ok_or("Missing info dictionary")?;
        let info_dict = match info_value {
            BencodeValue::Dictionary(dict) => dict,
            _ => return Err("Invalid info dictionary".to_string()),
        };
        let info = Info::from_bencoded(info_dict)?;

        let info_hash = Self::calculate_info_hash(info_value)?;

        Ok(Self {
            info,
            announce,
            info_hash,
        })
    }

    pub fn get_piece_count(&self) -> usize {
        self.info.pieces.len() / 20
    }

    pub fn get_pieces_hashes(&self) -> Vec<[u8;20]>{
        self.info
        .pieces
        .chunks(20)
        .filter_map(|chunk| chunk.try_into().ok())
        .collect()
    }

    fn extract_string(dict: &HashMap<String, BencodeValue>, key: &str) -> Result<String, String> {
        match dict.get(key) {
            Some(BencodeValue::ByteString(bytes)) => String::from_utf8(bytes.clone())
                .map_err(|e| format!("Invalid UTF-8 in {}: {}", key, e)),
            _ => Err(format!("Missing or invalid {}", key)),
        }
    }

    fn calculate_info_hash(info_value: &BencodeValue) -> Result<[u8; 20], String> {
        let info_bencoded = bencode_parser::bencode_encode(info_value);
        let mut hasher = Sha1::new();
        hasher.update(&info_bencoded);
        Ok(hasher.finalize().into())
    }
}

impl fmt::Display for TorrentFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Torrent File Information:\n\
             Announce URL: {}\n\
             File Name: {}\n\
             File Length: {} bytes\n\
             Piece Length: {} bytes\n\
             Number of Pieces: {}\n\
             Info Hash: {}",
            self.announce,
            self.info.name,
            self.info.length,
            self.info.piece_length,
            self.info.pieces.len() / 20,
            hex::encode(&self.info_hash)
        )
    }
}

impl Info {
    fn from_bencoded(dict: &HashMap<String, BencodeValue>) -> Result<Info, String> {
        Ok(Info {
            piece_length: Self::extract_integer(dict, "piece length")?,
            pieces: Self::extract_bytestring(dict, "pieces")?,
            name: Self::extract_string(dict, "name")?,
            length: Self::extract_integer(dict, "length")?,
        })
    }

    fn extract_integer(dict: &HashMap<String, BencodeValue>, key: &str) -> Result<i64, String> {
        match dict.get(key) {
            Some(BencodeValue::Integer(value)) => Ok(*value),
            _ => Err(format!("Missing or invalid {}", key)),
        }
    }

    fn extract_bytestring(dict: &HashMap<String, BencodeValue>, key: &str) -> Result<Vec<u8>, String> {
        match dict.get(key) {
            Some(BencodeValue::ByteString(bytes)) => Ok(bytes.clone()),
            _ => Err(format!("Missing or invalid {}", key)),
        }
    }

    fn extract_string(dict: &HashMap<String, BencodeValue>, key: &str) -> Result<String, String> {
        Self::extract_bytestring(dict, key)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
    }
}