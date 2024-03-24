use std::{
    env,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    str::FromStr,
};

use anyhow::Context;
use bytes::BufMut;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncReadExt,
    io::AsyncWriteExt,
};

mod peer;

#[derive(Serialize, Deserialize)]
struct InfoDict {
    name: String,
    #[serde(rename = "piece length")]
    piece_length: u32,
    pieces: ByteBuf,
    length: u32,
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

            let mut peer = peer::PeerState::connect(peer_addr, metainf)
                .await
                .context("failed to connect to peer")?;

            peer.wait_for_handshake().await;
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

            let mut peer = peer::PeerState::connect(peers[0], metainf).await?;
            // peer.poll_piece(
            //     piece_idx
            //         .parse()
            //         .context("could not parse given piece index")?,
            // )
            // .await;
            eprintln!("waiting for handshake");
            peer.wait_for_handshake().await;

            eprintln!("checking if i have peer's bitfield");
            while peer.bitfield().len() == 0 {
                let msgs = peer.poll().await?;
                if msgs.len() == 0 {
                    eprintln!("got nothing from peer this round");
                } else {
                    for m in msgs {
                        eprintln!("waiting for bitfield, got: {:?}", m);
                    }
                }
            }

            eprintln!("indicating interest");
            peer.indicate_interest().await?;

            eprintln!("checking if peer is choking");
            while peer.choking() {
                let msgs = peer.poll().await?;
                for m in msgs {
                    eprintln!("waiting for unchoke, got: {:?}", m);
                }
            }

            eprintln!("fetching piece");
            let piece_buf = peer
                .get_piece(
                    piece_idx
                        .parse()
                        .context("could not parse given piece index")?,
                )
                .await?;

            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(outfile)
                .await
                .context("error opening file for writing piece")?;
            f.write_all(&piece_buf)
                .await
                .context("error writing out piece buffer to file")?;

            println!("Piece {} downloaded to {}", piece_idx, outfile);

            Ok(())
        }
        _ => {
            anyhow::bail!("unknown command: {}", args[1])
        }
    }
}
