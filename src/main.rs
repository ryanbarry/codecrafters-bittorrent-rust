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
use tokio::{fs::File, io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

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
            let mut peerconn = TcpStream::connect(peer_addr)
                .await
                .context("failed to connect to peer")?;
            let my_hand = PeerHandshake::new(
                metainf.info.hash().context("failed creating infohash")?,
                *b"00112233445566778899",
            );
            peerconn
                .write_all(&my_hand.to_bytes())
                .await
                .context("failed to send handshake to peer")?;

            let mut b = Vec::with_capacity(512);
            loop {
                b.clear();
                peerconn
                    .readable()
                    .await
                    .context("failed waiting for data from peer")?;
                match peerconn.try_read_buf(&mut b) {
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
        _ => {
            anyhow::bail!("unknown command: {}", args[1])
        }
    }
}
