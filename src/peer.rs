use anyhow::anyhow;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::fmt;
use std::net::SocketAddrV4;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

#[derive(Deserialize, Serialize)]
pub struct PeerHandshake {
    version: u8,
    proto: [u8; 19],
    reserved: [u8; 8],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
}

impl PeerHandshake {
    fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        PeerHandshake {
            version: 19,
            proto: *b"BitTorrent protocol",
            reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    fn to_bytes(&self) -> [u8; 68] {
        let mut buf = [0u8; 68];
        buf[0] = self.version;
        buf[1..20].copy_from_slice(&self.proto);
        // skipping reserved bytes, they're already zeroed
        buf[28..48].copy_from_slice(&self.info_hash);
        buf[48..68].copy_from_slice(&self.peer_id);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut proto = [0; 19];
        proto.copy_from_slice(&buf[1..20]);
        let mut reserved = [0; 8];
        reserved.copy_from_slice(&buf[20..28]);
        let mut info_hash = [0; 20];
        info_hash.copy_from_slice(&buf[28..48]);
        let mut peer_id = [0; 20];
        peer_id.copy_from_slice(&buf[48..68]);
        PeerHandshake {
            version: buf[0],
            proto,
            reserved,
            info_hash,
            peer_id,
        }
    }
}

enum PeerMessage {
    Choke {},
    Unchoke {},
    Interested {},
    NotInterested {},
    Have {
        index: u32,
    },
    Bitfield {
        sent_indices: ByteBuf,
    },
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        piece: ByteBuf,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
}

impl fmt::Debug for PeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Choke {} => writeln!(f, "Choke {{  }}"),
            Self::Unchoke {} => writeln!(f, "Unchoke {{  }}"),
            Self::Interested {} => writeln!(f, "Interested {{  }}"),
            Self::NotInterested {} => writeln!(f, "NotInterested {{  }}"),
            Self::Have { index } => writeln!(f, "Have {{ {} }}", index),
            Self::Bitfield { sent_indices } => writeln!(f, "Bitfield {{ {:?} }}", sent_indices),
            Self::Request {
                index,
                begin,
                length,
            } => writeln!(f, "Request {{ {}, {}, {} }}", index, begin, length),
            Self::Piece {
                index,
                begin,
                piece: _,
            } => writeln!(f, "Piece {{ {}, {}, [...data...] }}", index, begin),
            Self::Cancel {
                index,
                begin,
                length,
            } => writeln!(f, "Cancel {{ {}, {}, {} }}", index, begin, length),
        }
    }
}

impl PeerMessage {
    fn from_bytes(buf: &[u8]) -> anyhow::Result<Self> {
        match buf[0] {
            0 => Ok(Self::Choke {}),
            1 => Ok(Self::Unchoke {}),
            2 => Ok(Self::Interested {}),
            3 => Ok(Self::NotInterested {}),
            4 => {
                if buf.len() != 5 {
                    return Err(anyhow!(
                        "got wrong number of bytes for PeerMessage::Have: {}",
                        buf.len()
                    ));
                }
                Ok(Self::Have {
                    index: u32::from_be_bytes(buf[1..5].try_into()?),
                })
            }
            5 => Ok(Self::Bitfield {
                sent_indices: ByteBuf::from(&buf[1..]),
            }),
            6 => Ok(Self::Request {
                index: u32::from_be_bytes(buf[1..5].try_into()?),
                begin: u32::from_be_bytes(buf[5..9].try_into()?),
                length: u32::from_be_bytes(buf[9..13].try_into()?),
            }),
            7 => Ok(Self::Piece {
                index: u32::from_be_bytes(buf[1..5].try_into()?),
                begin: u32::from_be_bytes(buf[5..9].try_into()?),
                piece: ByteBuf::from(&buf[9..]),
            }),
            8 => Ok(Self::Cancel {
                index: u32::from_be_bytes(buf[1..5].try_into()?),
                begin: u32::from_be_bytes(buf[5..9].try_into()?),
                length: u32::from_be_bytes(buf[9..13].try_into()?),
            }),
            _ => Err(anyhow!("got unexpected PeerMessage type: {}", buf[0])),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match &self {
            Self::Choke {} => {
                vec![0]
            }
            Self::Unchoke {} => {
                vec![1]
            }
            Self::Interested {} => {
                vec![2]
            }
            Self::NotInterested {} => {
                vec![3]
            }
            Self::Have { index } => [4]
                .iter()
                .chain(index.to_be_bytes().iter())
                .copied()
                .collect(),
            Self::Bitfield { sent_indices } => {
                [5].iter().chain(sent_indices.iter()).copied().collect()
            }
            Self::Request {
                index,
                begin,
                length,
            } => [6]
                .iter()
                .chain(index.to_be_bytes().iter())
                .chain(begin.to_be_bytes().iter())
                .chain(length.to_be_bytes().iter())
                .copied()
                .collect(),
            Self::Piece {
                index,
                begin,
                piece,
            } => [7]
                .iter()
                .chain(index.to_be_bytes().iter())
                .chain(begin.to_be_bytes().iter())
                .chain(piece.iter())
                .copied()
                .collect(),
            Self::Cancel {
                index,
                begin,
                length,
            } => [8]
                .iter()
                .chain(index.to_be_bytes().iter())
                .chain(begin.to_be_bytes().iter())
                .chain(length.to_be_bytes().iter())
                .copied()
                .collect(),
        }
    }
}

enum PeerSMState {
    Start,
    Alive,
}

#[allow(dead_code)]
pub struct PeerState {
    im_choked: bool,
    theyre_choked: bool,
    im_interested: bool,
    theyre_interested: bool,
    my_bitfield: Vec<u8>,
    their_bitfield: Vec<u8>,
    remote: SocketAddrV4,
    conn: TcpStream,
    metainfo: crate::Metainfo,
    recv_buf: Vec<u8>,
    machine: PeerSMState,
    pub piece_buf: Vec<u8>,
}

// state machine
// start (no handshake yet received)
//   wait for 68+ bytes in the buffer
//   decode handshake
// alive
//   wait for some bytes
//   try to read a message from what was received

impl PeerState {
    pub async fn connect(remote: SocketAddrV4, metainfo: crate::Metainfo) -> anyhow::Result<Self> {
        let mut peerconn = TcpStream::connect(remote)
            .await
            .context("failed to connect to peer")?;
        let my_hand = PeerHandshake::new(metainfo.info.hash()?, *b"00112233445566778899");
        peerconn
            .write_all(&my_hand.to_bytes())
            .await
            .context("failed to send handshake to peer")?;
        let piece_buf = Vec::with_capacity(metainfo.info.piece_length.try_into()?);
        eprintln!(
            "reserved {} bytes for piece data buffer",
            piece_buf.capacity()
        );
        Ok(PeerState {
            im_choked: true,
            theyre_choked: false,
            im_interested: false,
            theyre_interested: false,
            my_bitfield: vec![],
            their_bitfield: vec![],
            remote,
            conn: peerconn,
            metainfo,
            recv_buf: vec![],
            machine: PeerSMState::Start,
            piece_buf,
        })
    }

    pub async fn wait_for_handshake(&mut self) {
        'ultimate: loop {
            'tryread: loop {
                self.conn
                    .readable()
                    .await
                    .expect("failed waiting for data from peer");
                // eprintln!("peer connection should be readable");
                match self.conn.try_read_buf(&mut self.recv_buf) {
                    Ok(0) => {
                        eprintln!("got 0 bytes");
                        time::sleep(time::Duration::from_secs(1)).await;
                    }
                    Ok(n) => {
                        eprintln!("got {} bytes from peer", n);
                        break 'tryread;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        eprintln!("false positive from peercon.readable()");
                    }
                    Err(e) => panic!("some other error from peer: {}", e),
                }
            }

            if self.recv_buf.len() >= 68 {
                let new_buf = self.recv_buf.split_off(68);
                let hs_bytes = &self.recv_buf;
                let their_hand = PeerHandshake::from_bytes(hs_bytes);
                self.recv_buf = new_buf;
                eprintln!("Peer ID: {}", hex::encode(their_hand.peer_id));
                break 'ultimate;
            } else {
                eprintln!("not enough bytes to start");
            }
        }
    }

    pub async fn poll(&mut self, piece_idx: u32) {
        loop {
            'tryread: loop {
                self.conn
                    .readable()
                    .await
                    .expect("failed waiting for data from peer");
                // eprintln!("peer connection should be readable");
                match self.conn.try_read_buf(&mut self.recv_buf) {
                    Ok(0) => {
                        eprintln!("got 0 bytes");
                        time::sleep(time::Duration::from_secs(1)).await;
                    }
                    Ok(n) => {
                        eprintln!("got {} bytes from peer", n);
                        break 'tryread;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        eprintln!("false positive from peercon.readable()");
                    }
                    Err(e) => panic!("some other error from peer: {}", e),
                }
            }

            'drainbuf: loop {
                match self.machine {
                    PeerSMState::Start => {
                        if self.recv_buf.len() >= 68 {
                            let new_buf = self.recv_buf.split_off(68);
                            let hs_bytes = &self.recv_buf;
                            let their_hand = PeerHandshake::from_bytes(hs_bytes);
                            self.recv_buf = new_buf;
                            eprintln!("Peer ID: {}", hex::encode(their_hand.peer_id));
                            self.machine = PeerSMState::Alive;
                        } else {
                            eprintln!("not enough bytes to start");
                            break 'drainbuf;
                        }
                    }
                    PeerSMState::Alive => match self.try_read_msg() {
                        Err(e) => {
                            eprintln!("couldn't read message: {}", e);
                            break 'drainbuf;
                        }
                        Ok(None) => {
                            eprintln!("got keepalive");
                        }
                        Ok(Some(msg)) => {
                            eprintln!("got message from peer: {:?}", msg);
                            self.machine = PeerSMState::Alive;
                            match msg {
                                PeerMessage::Choke {} => self.im_choked = true,
                                PeerMessage::Unchoke {} => {
                                    self.im_choked = false;

                                    let mut to_send = PeerMessage::Request {
                                        index: piece_idx,
                                        begin: 0,
                                        length: (16 * 1024),
                                    }
                                    .to_bytes();
                                    let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                    bytes_out.append(&mut to_send);
                                    self.conn
                                        .write_all(&bytes_out)
                                        .await
                                        .expect("failed to tell peer my request");
                                }
                                PeerMessage::Bitfield { sent_indices } => {
                                    self.their_bitfield = sent_indices.to_vec();

                                    if !self.im_interested {
                                        let mut to_send = PeerMessage::Interested {}.to_bytes();
                                        let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                        bytes_out.append(&mut to_send);
                                        self.conn
                                            .write_all(&bytes_out)
                                            .await
                                            .expect("failed to send interested to peer");
                                        self.im_interested = true;
                                        eprintln!("told peer i'm interested");
                                    }
                                }
                                PeerMessage::Piece {
                                    index: _,
                                    begin,
                                    piece,
                                } => {
                                    let begin = begin as usize;
                                    let next_piece_start = begin + piece.len();
                                    self.piece_buf.resize(self.piece_buf.len() + piece.len(), 0);
                                    self.piece_buf.splice(begin..next_piece_start, piece);

                                    eprintln!("self.piece_buf.len()={}", self.piece_buf.len());
                                    if self.piece_buf.len() as u64
                                        == self.metainfo.info.piece_length.min(
                                            self.metainfo.info.length
                                                - piece_idx as u64
                                                    * self.metainfo.info.piece_length,
                                        )
                                    {
                                        let mut to_send = PeerMessage::NotInterested {}.to_bytes();
                                        let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                        bytes_out.append(&mut to_send);
                                        self.conn
                                            .write_all(&bytes_out)
                                            .await
                                            .expect("failed to send NOTinterested to peer");
                                        self.im_interested = false;
                                        eprintln!("told peer i'm NOTinterested");

                                        return;
                                    }

                                    let standard_piece_len = 16 * 1024;
                                    let plen = standard_piece_len.min(
                                        self.metainfo.info.length
                                            - (next_piece_start as u64
                                                + piece_idx as u64
                                                    * self.metainfo.info.piece_length),
                                    ) as u32;
                                    let mut to_send = PeerMessage::Request {
                                        index: piece_idx,
                                        begin: next_piece_start as u32,
                                        length: plen,
                                    }
                                    .to_bytes();
                                    let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                    bytes_out.append(&mut to_send);
                                    self.conn
                                        .write_all(&bytes_out)
                                        .await
                                        .expect("failed to tell peer my request");
                                }
                                _ => {
                                    eprintln!("non-bitfield message");
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    fn try_read_msg(&mut self) -> anyhow::Result<Option<PeerMessage>> {
        let buf_len = self.recv_buf.len();
        if buf_len >= 4 {
            let need = u32::from_be_bytes(
                self.recv_buf[..4]
                    .try_into()
                    .expect("recv_buf.len() was supposed to be >=4"),
            );
            if need == 0 {
                // a "keepalive"
                return Ok(None);
            }

            if buf_len >= (4 + (need as usize)) {
                let new_buf = self.recv_buf.split_off(4 + need as usize);
                let msg = PeerMessage::from_bytes(&self.recv_buf[4..4 + need as usize])?;
                self.recv_buf = new_buf;
                Ok(Some(msg))
            } else {
                Err(anyhow!("not enough bytes for the full message"))
            }
        } else {
            Err(anyhow!("not enough bytes for a msglen"))
        }
    }
}
