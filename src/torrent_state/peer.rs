use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Debug)]
pub struct PeerState {
    pub peer: Peer,
    has_handshake: bool,
    pub bitfield: Vec<bool>,
    am_choking: bool,
    am_interested: bool,
    pub peer_choking: bool,
    peer_interested: bool,
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
                bitfield.get(byte).map_or(false, |&b| (b >> bit) & 1 == 1)
            })
            .collect();
        // println!("Updated bitfield: {:?}", self.bitfield);
    }

    pub fn has_piece(&self, piece_index: usize) -> bool {
        // println!("Piece: {:?} - Bitfield {:?}", piece_index, self.bitfield);
        self.bitfield.get(piece_index).copied().unwrap_or(false)
    }

    pub fn set_handshaked(&mut self, value: bool) {
        self.has_handshake = value;
    }

    pub fn set_peer_choking(&mut self, value: bool) {
        self.peer_choking = value;
    }

}