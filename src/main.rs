use std::{
    env,
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

use bytes::BufMut;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};

#[derive(Serialize, Deserialize)]
struct InfoDict {
    name: String,
    #[serde(rename = "piece length")]
    piece_length: u64,
    pieces: ByteBuf,
    length: u64,
}

impl InfoDict {
    fn infohash(&self) -> anyhow::Result<[u8; 20]> {
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

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> anyhow::Result<()> {
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
            let torrent_path = Path::new(&args[2]);
            //eprintln!("looking at torrent file: {}", torrent_path.display());
            let mut file = match File::open(torrent_path) {
                Err(why) => panic!("couldn't open {}: {}", torrent_path.display(), why),
                Ok(file) => file,
            };
            let fsz = file
                .metadata()
                .expect("couldn't read torrent file metadata")
                .len();
            //eprintln!("torrent file is {} bytes", fsz);
            let mut cts = Vec::with_capacity(
                fsz.try_into()
                    .expect("couldn't make a buffer big enough to hold entire torrent file"),
            );
            match file.read_to_end(&mut cts) {
                Ok(0) => panic!("nothing read from torrent file"),
                Ok(_bsz) => {} //eprintln!("read {} bytes into buffer", bsz),
                Err(why) => panic!(
                    "error reading torrent file {}: {}",
                    torrent_path.display(),
                    why
                ),
            }
            let torrent: Metainfo = serde_bencode::from_bytes(&cts)?;
            let ih_urlenc = torrent
                .info
                .infohash()?
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
            let torrent_path = Path::new(&args[2]);
            //eprintln!("looking at torrent file: {}", torrent_path.display());
            let mut file = match File::open(torrent_path) {
                Err(why) => panic!("couldn't open {}: {}", torrent_path.display(), why),
                Ok(file) => file,
            };
            let fsz = file.metadata()?.len();
            //eprintln!("torrent file is {} bytes", fsz);
            let mut cts = Vec::with_capacity(fsz.try_into()?);
            match file.read_to_end(&mut cts) {
                Ok(0) => panic!("nothing read from torrent file"),
                Ok(_bsz) => {} //eprintln!("read {} bytes into buffer", bsz),
                Err(why) => panic!(
                    "error reading torrent file {}: {}",
                    torrent_path.display(),
                    why
                ),
            }
            let metainf: Metainfo = serde_bencode::from_bytes(&cts)?;
            println!("Tracker URL: {}", metainf.announce);
            println!("Length: {}", metainf.info.length);
            println!("Info Hash: {}", hex::encode(metainf.info.infohash()?));
            println!("Piece Length: {}", metainf.info.piece_length);
            println!("Piece Hashes:");
            for ph in metainf.info.pieces.chunks(20).map(Vec::from) {
                println!("{}", hex::encode(ph));
            }
            Ok(())
        }
        _ => {
            anyhow::bail!("unknown command: {}", args[1])
        }
    }
}
