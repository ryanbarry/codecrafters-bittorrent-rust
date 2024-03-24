use anyhow::anyhow;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::arch::x86_64::_rdrand32_step;
use std::fmt;
use std::net::SocketAddrV4;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

const PIECE_CHUNK_SZ: u32 = 16 * 1024; // 16KiB

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

pub enum PeerMessage {
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
            Self::Choke {} => write!(f, "Choke {{  }}"),
            Self::Unchoke {} => write!(f, "Unchoke {{  }}"),
            Self::Interested {} => write!(f, "Interested {{  }}"),
            Self::NotInterested {} => write!(f, "NotInterested {{  }}"),
            Self::Have { index } => write!(f, "Have {{ {} }}", index),
            Self::Bitfield { sent_indices } => write!(f, "Bitfield {{ {:?} }}", sent_indices),
            Self::Request {
                index,
                begin,
                length,
            } => write!(f, "Request {{ {}, {}, {} }}", index, begin, length),
            Self::Piece {
                index,
                begin,
                piece: _,
            } => write!(f, "Piece {{ {}, {}, [...data...] }}", index, begin),
            Self::Cancel {
                index,
                begin,
                length,
            } => write!(f, "Cancel {{ {}, {}, {} }}", index, begin, length),
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

// enum PeerSMState {
//     Start,
//     Alive,
// }

#[derive(Clone)]
struct PieceRequest {
    index: u32,
    begin: u32,
    buf: Vec<u8>, // length will be carried as the capacity of this vec
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
    pub piece_buf: Vec<u8>,
    req_buf: Vec<PieceRequest>,
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
            //machine: PeerSMState::Start,
            piece_buf,
            req_buf: vec![],
        })
    }

    pub fn choking(&self) -> bool {
        self.im_choked
    }

    pub fn bitfield(&self) -> &[u8] {
        &self.their_bitfield
    }

    pub async fn indicate_interest(&mut self) -> anyhow::Result<()> {
        if !self.im_interested {
            self.send_msg(PeerMessage::Interested {}).await?;
            self.im_interested = true;
        }
        Ok(())
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

    // TODO: kinds of error:
    //   * currently choked
    //   * peer disconnected before i finished downloading
    pub async fn get_piece(&mut self, piece_idx: u32) -> anyhow::Result<Vec<u8>> {
        // TODO: check/set interested state, message about the change if needed

        let piece_len = self.metainfo.info.piece_length.min(
            self.metainfo.info.length - self.metainfo.info.piece_length * piece_idx,
        );
        eprintln!("expecting to get {} bytes for this piece", piece_len);

        while self.req_buf.iter().map(|rb| rb.buf.len()).sum::<usize>() < piece_len as usize {
            while self.req_buf.len() < (piece_len.div_ceil(PIECE_CHUNK_SZ)).try_into()?
                && self.req_buf.iter().filter(|rb| rb.buf.is_empty()).count() < 5
            {
                let chunk_to_request = {
                    let chunks_left: Vec<u32> = (0..(piece_len.div_ceil(PIECE_CHUNK_SZ)))
                        .filter(|potential_idx| {
                            !self
                                .req_buf
                                .iter()
                                .any(|rb| rb.begin == (PIECE_CHUNK_SZ * potential_idx))
                        })
                        .collect();
                    // eprintln!("chunks left: {:?}", chunks_left);

                    let mut rand_num: u32 = 0;
                    if unsafe { _rdrand32_step(&mut rand_num) } == 0 {
                        rand_num = 0;
                    } else {
                        rand_num %= chunks_left.len() as u32;
                    }
                    chunks_left[rand_num as usize]
                };
                eprintln!(
                    "chose to request chunk {} of piece {}",
                    chunk_to_request, piece_idx
                );

                let chunk_begin = PIECE_CHUNK_SZ * chunk_to_request;
                let chunk_length =
                    PIECE_CHUNK_SZ.min(piece_len - PIECE_CHUNK_SZ * chunk_to_request);
                // eprintln!("...which corresponds to begin={} and length={}", chunk_begin, chunk_length);

                self.send_msg(PeerMessage::Request {
                    index: piece_idx,
                    begin: chunk_begin,
                    length: chunk_length,
                })
                .await?;

                self.req_buf.push(PieceRequest {
                    index: piece_idx,
                    begin: chunk_begin,
                    buf: Vec::with_capacity(chunk_length.try_into()?),
                });
            }
            let msgs = self.poll().await?;
            for m in msgs {
                eprintln!("waiting for piece, got: {:?}", m);
            }
        }
        eprintln!("got all the chunks of the piece");

        assert_eq!(
            u32::try_from(self.req_buf.iter().map(|pr| pr.buf.len()).sum::<usize>())?,
            piece_len,
            "sum of bufs vs computed len do not match"
        );
        let mut piece_bytes = vec![0; piece_len.try_into()?];
        for pr in self.req_buf.iter_mut() {
            piece_bytes.splice(
                pr.begin as usize..pr.begin as usize + pr.buf.len(),
                pr.buf.clone(),
            );
            pr.buf.clear();
        }
        self.req_buf.clear();
        Ok(piece_bytes)
    }

    pub async fn poll(&mut self) -> anyhow::Result<Vec<PeerMessage>> {
        let mut res = vec![];

        loop {
            match self.try_read_msg() {
                Err(_e) => {
                    // eprintln!("couldn't parse msg from recv buffer on initial attempt: {}", e);
                    break;
                }
                Ok(None) => {
                    eprintln!("got keepalive");
                }
                Ok(Some(msg)) => {
                    let handled = self.handle_msg(msg)?;
                    eprintln!(
                        "got a message that was already waiting in the buffer: {:?}",
                        handled
                    );
                    res.push(handled);
                }
            }
        }

        if !res.is_empty() {
            return Ok(res);
        }

        self.conn.readable().await?;
        match self.conn.try_read_buf(&mut self.recv_buf) {
            Ok(0) => {
                self.conn.shutdown().await?;
                return Err(anyhow!("peer closed the connection"));
            }
            Ok(_n) => {
                // eprintln!("got {} bytes from peer", n);
                'drainbuf: while !self.recv_buf.is_empty() {
                    match self.try_read_msg() {
                        Err(_e) => {
                            // eprintln!("couldn't read message: {}", e);
                            break 'drainbuf;
                        }
                        Ok(None) => {
                            eprintln!("got keepalive");
                        }
                        Ok(Some(msg)) => {
                            let handled = self.handle_msg(msg)?;
                            res.push(handled);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // eprintln!("false positive from peercon.readable()");
            }
            Err(e) => return Err(anyhow!(e).context("failed while polling peer connection")),
        }

        Ok(res)
    }

    // pub async fn poll_piece(&mut self, piece_idx: u32) {
    //     loop {
    //         'tryread: loop {
    //             self.conn
    //                 .readable()
    //                 .await
    //                 .expect("failed waiting for data from peer");
    //             // eprintln!("peer connection should be readable");
    //             match self.conn.try_read_buf(&mut self.recv_buf) {
    //                 Ok(0) => {
    //                     eprintln!("got 0 bytes");
    //                     time::sleep(time::Duration::from_secs(1)).await;
    //                 }

    //                 Ok(n) => {
    //                     eprintln!("got {} bytes from peer", n);
    //                     break 'tryread;
    //                 }
    //                 Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
    //                     eprintln!("false positive from peercon.readable()");
    //                 }
    //                 Err(e) => panic!("some other error from peer: {}", e),
    //             }
    //         }

    //         'drainbuf: loop {
    //             match self.machine {
    //                 PeerSMState::Start => {
    //                     if self.recv_buf.len() >= 68 {
    //                         let new_buf = self.recv_buf.split_off(68);
    //                         let hs_bytes = &self.recv_buf;
    //                         let their_hand = PeerHandshake::from_bytes(hs_bytes);
    //                         self.recv_buf = new_buf;
    //                         eprintln!("Peer ID: {}", hex::encode(their_hand.peer_id));
    //                         self.machine = PeerSMState::Alive;
    //                     } else {
    //                         eprintln!("not enough bytes to start");
    //                         break 'drainbuf;
    //                     }
    //                 }
    //                 PeerSMState::Alive => match self.try_read_msg() {
    //                     Err(e) => {
    //                         eprintln!("couldn't read message: {}", e);
    //                         break 'drainbuf;
    //                     }
    //                     Ok(None) => {
    //                         eprintln!("got keepalive");
    //                     }
    //                     Ok(Some(msg)) => {
    //                         eprintln!("got message from peer: {:?}", msg);
    //                         self.machine = PeerSMState::Alive;
    //                         match msg {
    //                             PeerMessage::Choke {} => self.im_choked = true,
    //                             PeerMessage::Unchoke {} => {
    //                                 self.im_choked = false;

    //                                 let mut to_send = PeerMessage::Request {
    //                                     index: piece_idx,
    //                                     begin: 0,
    //                                     length: (16 * 1024),
    //                                 }
    //                                 .to_bytes();
    //                                 let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
    //                                 bytes_out.append(&mut to_send);
    //                                 self.conn
    //                                     .write_all(&bytes_out)
    //                                     .await
    //                                     .expect("failed to tell peer my request");
    //                             }
    //                             PeerMessage::Bitfield { sent_indices } => {
    //                                 self.their_bitfield = sent_indices.to_vec();

    //                                 if !self.im_interested {
    //                                     let mut to_send = PeerMessage::Interested {}.to_bytes();
    //                                     let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
    //                                     bytes_out.append(&mut to_send);
    //                                     self.conn
    //                                         .write_all(&bytes_out)
    //                                         .await
    //                                         .expect("failed to send interested to peer");
    //                                     self.im_interested = true;
    //                                     eprintln!("told peer i'm interested");
    //                                 }
    //                             }
    //                             PeerMessage::Piece {
    //                                 index: _,
    //                                 begin,
    //                                 piece,
    //                             } => {
    //                                 let next_piece_start: u32 = begin + piece.len() as u32;
    //                                 self.piece_buf.resize(self.piece_buf.len() + piece.len(), 0);
    //                                 self.piece_buf.splice(begin as usize..next_piece_start as usize, piece);

    //                                 eprintln!("self.piece_buf.len()={}", self.piece_buf.len());
    //                                 if self.piece_buf.len() as u32
    //                                     == self.metainfo.info.piece_length.min(
    //                                         self.metainfo.info.length
    //                                             - piece_idx
    //                                                 * self.metainfo.info.piece_length,
    //                                     )
    //                                 {
    //                                     let mut to_send = PeerMessage::NotInterested {}.to_bytes();
    //                                     let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
    //                                     bytes_out.append(&mut to_send);
    //                                     self.conn
    //                                         .write_all(&bytes_out)
    //                                         .await
    //                                         .expect("failed to send NOTinterested to peer");
    //                                     self.im_interested = false;
    //                                     eprintln!("told peer i'm NOTinterested");

    //                                     return;
    //                                 }

    //                                 let standard_piece_len = 16 * 1024;
    //                                 let plen = standard_piece_len.min(
    //                                     self.metainfo.info.length
    //                                         - (next_piece_start
    //                                             + piece_idx
    //                                                 * self.metainfo.info.piece_length),
    //                                 ) as u32;
    //                                 let mut to_send = PeerMessage::Request {
    //                                     index: piece_idx,
    //                                     begin: next_piece_start as u32,
    //                                     length: plen,
    //                                 }
    //                                 .to_bytes();
    //                                 let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
    //                                 bytes_out.append(&mut to_send);
    //                                 self.conn
    //                                     .write_all(&bytes_out)
    //                                     .await
    //                                     .expect("failed to tell peer my request");
    //                             }
    //                             _ => {
    //                                 eprintln!("non-bitfield message");
    //                             }
    //                         }
    //                     }
    //                 },
    //             }
    //         }
    //     }
    // }

    async fn send_msg(&mut self, msg: PeerMessage) -> anyhow::Result<usize> {
        let mut to_send = msg.to_bytes();
        let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
        bytes_out.append(&mut to_send);
        self.conn
            .write_all(&bytes_out)
            .await
            .context("failed writing to peer connection")
            .map(|_| bytes_out.len())
    }

    // TODO: types of error responses
    fn handle_msg(&mut self, msg: PeerMessage) -> anyhow::Result<PeerMessage> {
        match msg {
            PeerMessage::Choke {} => {
                self.im_choked = true;
                Ok(msg)
            }
            PeerMessage::Unchoke {} => {
                self.im_choked = false;
                Ok(msg)
            }
            PeerMessage::Bitfield { ref sent_indices } => {
                self.their_bitfield = sent_indices.to_vec();
                Ok(msg)
            }
            PeerMessage::Piece {
                index,
                begin,
                ref piece,
            } => {
                let pr_idx = {
                    let mut pr_iter = self
                        .req_buf
                        .iter()
                        .enumerate()
                        .filter(|(_, pr)| pr.index == index && pr.begin == begin);
                    if pr_iter.clone().count() < 1 {
                        return Err(anyhow!(
                            "got a Piece message for which i have no outstanding Request"
                        ));
                    }
                    pr_iter.next().unwrap().0
                };
                let pr = &mut self.req_buf[pr_idx];
                if pr.buf.capacity() < piece.len() {
                    return Err(anyhow!("the received Piece data is bigger than requested"));
                }
                if !pr.buf.is_empty() {
                    return Err(anyhow!("got a Piece for which i already have data"));
                }
                pr.buf.resize(piece.len(), 0);
                pr.buf.copy_from_slice(piece);

                Ok(msg)
            }
            _ => {
                eprintln!("non-bitfield message");
                Err(anyhow!("got unexpected PeerMessage kind: {:?}", msg))
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
                self.recv_buf = self.recv_buf.split_off(4);
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
