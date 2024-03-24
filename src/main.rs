use std::{
    env,
    net::SocketAddrV4,
    path::Path,
    str::FromStr,
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncReadExt,
    io::AsyncWriteExt,
};

mod peer;
mod tracker;

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
            eprintln!("fetching peers from tracker at {}", torrent.announce);
            let peers = tracker::Tracker::get_peers(torrent.announce, torrent.info.length, torrent.info.hash()?).await?;
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
            println!("Peer ID: {}", hex::encode(peer.remote_peer_id()));
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

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let peers = tracker::Tracker::get_peers(metainf.announce.clone(), metainf.info.length, metainf.info.hash()?).await?;

            // handshake begin

            let mut peer = peer::PeerState::connect(peers[0], metainf).await?;
            eprintln!("waiting for handshake");
            peer.wait_for_handshake().await;

            eprintln!("checking if i have peer's bitfield");
            while peer.bitfield().is_empty() {
                let msgs = peer.poll().await?;
                if msgs.is_empty() {
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
