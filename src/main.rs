use core::fmt;
use std::{
    env, io,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    str::FromStr,
};

use anyhow::{anyhow, Context};
use bytes::BufMut;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use tokio::{fs::{File, OpenOptions}, io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream, time};

#[derive(Serialize, Deserialize)]
struct InfoDict {
    name: String,
    #[serde(rename = "piece length")]
    piece_length: u64,
    pieces: ByteBuf,
    length: u64,
}

impl InfoDict {
    fn hash(&self) -> anyhow::Result<[u8; 20]> {
        let mut hasher = Sha1::new();
        hasher.update(serde_bencode::to_bytes(&self)?);
        Ok(hasher.finalize().into())
    }
}

#[derive(Serialize, Deserialize)]
struct Metainfo {
    announce: String,
    info: InfoDict,
}

impl Metainfo {
    async fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut file = File::open(path).await?;
        let fsz = file.metadata().await?.len();
        let mut contents = Vec::with_capacity(fsz.try_into()?);
        file.read_to_end(&mut contents).await?;
        Ok(serde_bencode::from_bytes(&contents)?)
    }
}

#[derive(Serialize, Deserialize)]
struct TrackerError {
    #[serde(rename = "failure reason")]
    failure_reason: String,
}

#[derive(Serialize, Deserialize)]
struct TrackerPeers {
    interval: u64,
    peers: ByteBuf,
    complete: u64,
    incomplete: u64,
    #[serde(rename = "min interval")]
    min_interval: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum TrackerResponse {
    Error(TrackerError),
    Success(TrackerPeers),
}

fn convert_bencode_to_json(
    value: serde_bencode::value::Value,
) -> anyhow::Result<serde_json::Value> {
    match value {
        serde_bencode::value::Value::Bytes(b) => {
            let stringified = String::from_utf8_lossy(&b);
            Ok(serde_json::Value::String(stringified.to_string()))
        }
        serde_bencode::value::Value::Int(i) => Ok(serde_json::Value::Number(i.into())),
        serde_bencode::value::Value::List(l) => Ok(serde_json::Value::Array(
            l.iter()
                .map(|v| convert_bencode_to_json(v.clone()).expect("failed conversion"))
                .collect(),
        )),
        serde_bencode::value::Value::Dict(d) => {
            Ok(serde_json::map::Map::from_iter(d.iter().map(|(k, v)| {
                let key = String::from_utf8(k.to_vec()).expect("dict keys must be utf-8");
                let val = convert_bencode_to_json(v.clone()).expect("failed converting dict value");
                (key, val)
            }))
            .into())
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PeerHandshake {
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

    fn from_bytes(buf: &[u8]) -> Self {
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
            Self::Choke {  } => writeln!(f, "Choke {{  }}"),
            Self::Unchoke {  } => writeln!(f, "Unchoke {{  }}"),
            Self::Interested {  } => writeln!(f, "Interested {{  }}"),
            Self::NotInterested {  } => writeln!(f, "NotInterested {{  }}"),
            Self::Have { index } => writeln!(f, "Have {{ {} }}", index),
            Self::Bitfield { sent_indices } => writeln!(f, "Bitfield {{ {:?} }}", sent_indices),
            Self::Request { index, begin, length } => writeln!(f, "Request {{ {}, {}, {} }}", index, begin, length),
            Self::Piece { index, begin, piece: _ } => writeln!(f, "Piece {{ {}, {}, [...data...] }}", index, begin),
            Self::Cancel { index, begin, length } => writeln!(f, "Cancel {{ {}, {}, {} }}", index, begin, length),
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
    Waiting(u32),
}

#[allow(dead_code)]
struct PeerState {
    im_choked: bool,
    theyre_choked: bool,
    im_interested: bool,
    theyre_interested: bool,
    my_bitfield: Vec<u8>,
    their_bitfield: Vec<u8>,
    remote: SocketAddrV4,
    conn: TcpStream,
    metainfo: Metainfo,
    recv_buf: Vec<u8>,
    machine: PeerSMState,
    piece_buf: Vec<u8>,
}

// state machine
// start (no handshake yet received)
//   wait for 68+ bytes in the buffer
//   decode handshake
// alive
//   wait for at least 4 bytes (an i32be)
//   move into waiting(i32be)
// waitbytes
//   wait for that many bytes
//   decode message
//     if bitfield -> set im_interested=true
// interested
//

impl PeerState {
    async fn connect(remote: SocketAddrV4, metainfo: Metainfo) -> anyhow::Result<Self> {
        let mut peerconn = TcpStream::connect(remote)
            .await
            .context("failed to connect to peer")?;
        let my_hand = PeerHandshake::new(metainfo.info.hash()?, *b"00112233445566778899");
        peerconn
            .write_all(&my_hand.to_bytes())
            .await
            .context("failed to send handshake to peer")?;
        let piece_buf = Vec::with_capacity(metainfo.info.length.try_into()?);
        eprintln!("reserved {} bytes for piece data buffer", piece_buf.capacity());
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

    async fn poll(&mut self, piece_idx: u32) {
        loop {
            'tryread: loop {
                self.conn
                    .readable()
                    .await
                    .expect("failed waiting for data from peer");
                eprintln!("peer connection should be readable");
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
                            let their_hand = PeerHandshake::from_bytes(&hs_bytes);
                            self.recv_buf = new_buf;
                            eprintln!("Peer ID: {}", hex::encode(their_hand.peer_id));
                            self.machine = PeerSMState::Alive;
                        } else {
                            eprintln!("not enough bytes to start");
                            break 'drainbuf;
                        }
                    }
                    PeerSMState::Alive => {
                        if self.recv_buf.len() >= 4 {
                            let new_buf = self.recv_buf.split_off(4);
                            let mut msglen: [u8; 4] = [0u8; 4];
                            msglen.copy_from_slice(&self.recv_buf[..4]);
                            self.recv_buf = new_buf;
                            let need = u32::from_be_bytes(msglen);
                            if need == 0 {
                                eprintln!("got keepalive");
                            } else {
                                eprintln!("next message will be {} bytes", need);
                                self.machine = PeerSMState::Waiting(need);
                            }
                        } else {
                            eprintln!("not enough bytes to decode msglen, only found {}", self.recv_buf.len());
                            break 'drainbuf;
                        }
                    }
                    PeerSMState::Waiting(need) => {
                        if self.recv_buf.len() == 0 {
                            break 'drainbuf;
                        } else if self.recv_buf.len() >= need.try_into().expect("can't compare buffer size") {
                            let new_buf = self.recv_buf.split_off(need.try_into().expect("can't split buffer at this size"));
                            let maybe_msg = PeerMessage::from_bytes(&self.recv_buf);
                            self.recv_buf = new_buf;

                            if let Err(e) = maybe_msg {
                                panic!("failed to deserialize peer message: {}", e);
                            }

                            let msg = maybe_msg.unwrap();
                            eprintln!("got message from peer: {:?}", msg);
                            self.machine = PeerSMState::Alive;
                            match msg {
                                PeerMessage::Choke {  } => self.im_choked = true,
                                PeerMessage::Unchoke {  } => {
                                    self.im_choked = false;

                                    let mut to_send = PeerMessage::Request { index: piece_idx, begin: 0, length: (16*1024) }.to_bytes();
                                    let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                    bytes_out.append(&mut to_send);
                                    self.conn.write_all(&bytes_out).await.expect("failed to tell peer my request");
                                },
                                PeerMessage::Bitfield { sent_indices } => {
                                    self.their_bitfield = sent_indices.to_vec();

                                    if !self.im_interested {
                                        let mut to_send = PeerMessage::Interested {  }.to_bytes();
                                        let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                        bytes_out.append(&mut to_send);
                                        self.conn.write_all(&bytes_out).await.expect("failed to send interested to peer");
                                        self.im_interested = true;
                                        eprintln!("told peer i'm interested");
                                    }
                                }
                                PeerMessage::Piece { index: _, begin, piece } => {
                                    let begin = begin as usize;
                                    let next_piece_start = begin+piece.len();
                                    self.piece_buf.resize(self.piece_buf.len() + piece.len(), 0);
                                    self.piece_buf.splice(begin..next_piece_start, piece);

                                    eprintln!("self.piece_buf.len()={}", self.piece_buf.len());
                                    if self.piece_buf.len() as u64 == self.metainfo.info.piece_length.min(self.metainfo.info.length - piece_idx as u64*self.metainfo.info.piece_length) {
                                        let mut to_send = PeerMessage::NotInterested {  }.to_bytes();
                                        let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                        bytes_out.append(&mut to_send);
                                        self.conn.write_all(&bytes_out).await.expect("failed to send NOTinterested to peer");
                                        self.im_interested = false;
                                        eprintln!("told peer i'm NOTinterested");

                                        return ;
                                    }

                                    let standard_piece_len = 16*1024;
                                    let plen = standard_piece_len.min(self.metainfo.info.length - (next_piece_start as u64 + piece_idx as u64 *self.metainfo.info.piece_length)) as u32;
                                    let mut to_send = PeerMessage::Request { index: piece_idx, begin: next_piece_start as u32, length: plen }.to_bytes();
                                    let mut bytes_out = Vec::from(to_send.len().to_be_bytes());
                                    bytes_out.append(&mut to_send);
                                    self.conn.write_all(&bytes_out).await.expect("failed to tell peer my request");
                                }
                                _ => {
                                    eprintln!("non-bitfield message");
                                }
                            }
                        } else {
                            eprintln!("not enough bytes for the message, got {} but wanted {}", self.recv_buf.len(), need);
                            break 'drainbuf;
                        }
                    }
                }
            }
        }
    }
}

#[allow(dead_code)]
fn hexedit<T: AsRef<[u8]>>(data: T) -> String {
    data.as_ref()
        .chunks(16)
        .map(|chunk| {
            (
                chunk
                    .chunks(2)
                    .map(|uc| hex::encode(uc) + " ")
                    .collect::<String>(),
                chunk,
            )
        })
        .map(|(hexstr, bytes)| {
            hexstr
                + " "
                + unsafe {
                    &String::from_utf8_unchecked(
                        bytes
                            .iter()
                            .map(|b| {
                                if b.is_ascii() && !b.is_ascii_whitespace() && !b.is_ascii_control()
                                {
                                    *b
                                } else {
                                    b'.'
                                }
                            })
                            .collect(),
                    )
                }
                + "\n"
        })
        .collect()
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    match command.trim() {
        "decode" => {
            let deser: serde_bencode::value::Value =
                serde_bencode::from_str(&args[2]).expect("could not deserialize value");
            let json = convert_bencode_to_json(deser)?;
            println!("{}", json);
            Ok(())
        }
        "peers" => {
            let torrent = Metainfo::from_file(&args[2]).await?;
            let ih_urlenc = torrent
                .info
                .hash()?
                .iter()
                .map(|b| match *b {
                    b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => {
                        format!("{}", *b as char)
                    }
                    _ => format!("%{:02X}", b),
                })
                .collect::<String>();
            //eprintln!("ih_urlenc: {}", ih_urlenc);

            eprintln!("fetching peers from tracker at {}", torrent.announce);
            let tracker_client = reqwest::blocking::Client::new();
            let mut req = tracker_client
                .get(torrent.announce)
                .query(&[
                    ("peer_id", "00112233445566778899"),
                    ("left", &torrent.info.length.to_string()),
                    ("port", "6881"),
                    ("uploaded", "0"),
                    ("downloaded", "0"),
                    ("compact", "1"),
                ])
                .build()?;
            let q = req
                .url()
                .query()
                .expect("query parameters were not created");
            let newq = q.to_owned() + "&info_hash=" + &ih_urlenc;
            req.url_mut().set_query(Some(&newq));

            //eprintln!("request: {:?}", req);
            let mut res = tracker_client
                .execute(req)
                .expect("failed to get from tracker");
            let body = {
                let mut buf = vec![].writer();
                res.copy_to(&mut buf)
                    .expect("could not read response from tracker");
                buf.into_inner()
            };
            //eprintln!("got a response: {}", String::from_utf8_lossy(&body));
            let peers: Vec<SocketAddrV4>;
            match serde_bencode::from_bytes(&body) {
                Ok(TrackerResponse::Error(e)) => {
                    panic!("tracker responded with error: {}", e.failure_reason)
                }
                Ok(TrackerResponse::Success(r)) => {
                    peers = r
                        .peers
                        .chunks(6)
                        .map(|peer| {
                            let mut ipbytes: [u8; 4] = [0; 4];
                            ipbytes.copy_from_slice(&peer[0..4]);
                            let mut skbytes = [0u8; 2];
                            skbytes.copy_from_slice(&peer[4..6]);
                            SocketAddrV4::new(Ipv4Addr::from(ipbytes), u16::from_be_bytes(skbytes))
                        })
                        .collect();
                }
                Err(e) => {
                    eprintln!(
                        "error reading tracker data, data as json:\n{}",
                        convert_bencode_to_json(
                            serde_bencode::from_bytes(&body)
                                .expect("could not deserialize as bencode")
                        )
                        .expect("invalid conversion")
                    );
                    anyhow::bail!("error deserializing tracker response: {}", e)
                }
            }
            for p in peers.iter() {
                println!("{}", p);
            }
            Ok(())
        }
        "info" => {
            let metainf = Metainfo::from_file(&args[2])
                .await
                .context("failed to read metainfo file")?;
            println!("Tracker URL: {}", metainf.announce);
            println!("Length: {}", metainf.info.length);
            println!("Info Hash: {}", hex::encode(metainf.info.hash()?));
            println!("Piece Length: {}", metainf.info.piece_length);
            println!("Piece Hashes:");
            for ph in metainf.info.pieces.chunks(20).map(Vec::from) {
                println!("{}", hex::encode(ph));
            }
            Ok(())
        }
        "handshake" => {
            let metainf = Metainfo::from_file(&args[2])
                .await
                .context("failed to read metainfo file")?;
            let peer_addr =
                SocketAddrV4::from_str(&args[3]).context("failed to parse given peer address")?;

            let peer = PeerState::connect(peer_addr, metainf)
                .await
                .context("failed to connect to peer")?;

            let mut b = Vec::with_capacity(512);
            loop {
                b.clear();
                peer.conn
                    .readable()
                    .await
                    .context("failed waiting for data from peer")?;
                match peer.conn.try_read_buf(&mut b) {
                    Ok(0) => {
                        return Err(anyhow::anyhow!("got nothing from peer"));
                    }
                    Ok(n) => {
                        assert!(n == 68, "got wrong size response: {}", n);
                        let their_hand = PeerHandshake::from_bytes(&b);
                        println!("Peer ID: {}", hex::encode(their_hand.peer_id));
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        eprintln!("false positive from peercon.readable()");
                        continue;
                    }
                    Err(e) => return Err(anyhow!(e).context("some other error from peer")),
                }
            }
            Ok(())
        }
        "download_piece" => {
            assert_eq!(
                args[2],
                "-o".to_string(),
                "output must be specified with -o <filepath> as 2nd & 3rd args"
            );

            let outfile = &args[3];
            let mi_file = &args[4];
            let piece_idx = &args[5];

            let metainf = Metainfo::from_file(mi_file)
                .await
                .context("failed to read metainfo file")?;

            // tracker contact

            let ih_urlenc = metainf
                .info
                .hash()?
                .iter()
                .map(|b| match *b {
                    b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => {
                        format!("{}", *b as char)
                    }
                    _ => format!("%{:02X}", b),
                })
                .collect::<String>();
            //eprintln!("ih_urlenc: {}", ih_urlenc);

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let tracker_client = reqwest::blocking::Client::new();
            let mut req = tracker_client
                .get(&metainf.announce)
                .query(&[
                    ("peer_id", "00112233445566778899"),
                    ("left", &metainf.info.length.to_string()),
                    ("port", "6881"),
                    ("uploaded", "0"),
                    ("downloaded", "0"),
                    ("compact", "1"),
                ])
                .build()?;
            let q = req
                .url()
                .query()
                .expect("query parameters were not created");
            let newq = q.to_owned() + "&info_hash=" + &ih_urlenc;
            req.url_mut().set_query(Some(&newq));

            let mut res = tracker_client
                .execute(req)
                .expect("failed to get from tracker");
            let body = {
                let mut buf = vec![].writer();
                res.copy_to(&mut buf)
                    .expect("could not read response from tracker");
                buf.into_inner()
            };
            let peers: Vec<SocketAddrV4>;
            match serde_bencode::from_bytes(&body) {
                Ok(TrackerResponse::Error(e)) => {
                    panic!("tracker responded with error: {}", e.failure_reason)
                }
                Ok(TrackerResponse::Success(r)) => {
                    peers = r
                        .peers
                        .chunks(6)
                        .map(|peer| {
                            let mut ipbytes: [u8; 4] = [0; 4];
                            ipbytes.copy_from_slice(&peer[0..4]);
                            let mut skbytes = [0u8; 2];
                            skbytes.copy_from_slice(&peer[4..6]);
                            SocketAddrV4::new(Ipv4Addr::from(ipbytes), u16::from_be_bytes(skbytes))
                        })
                        .collect();
                }
                Err(e) => {
                    eprintln!(
                        "error reading tracker data, data as json:\n{}",
                        convert_bencode_to_json(
                            serde_bencode::from_bytes(&body)
                                .expect("could not deserialize as bencode")
                        )
                        .expect("invalid conversion")
                    );
                    anyhow::bail!("error deserializing tracker response: {}", e)
                }
            }

            // handshake begin

            let mut peer = PeerState::connect(peers[0], metainf).await?;
            peer.poll(piece_idx.parse().context("could not parse given piece index")?).await;

            let mut f = OpenOptions::new().write(true).create(true).open(outfile).await?;
            f.write_all(&peer.piece_buf).await?;

            println!("Piece {} downloaded to {}", piece_idx, outfile);

            Ok(())
        }
        _ => {
            anyhow::bail!("unknown command: {}", args[1])
        }
    }
}
