use std::{env, net::SocketAddrV4, str::FromStr};

use anyhow::Context;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};

mod peer;
mod tracker;
mod types;
mod utils;

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    match command.trim() {
        "decode" => {
            let deser: serde_bencode::value::Value =
                serde_bencode::from_str(&args[2]).expect("could not deserialize value");
            let json = utils::convert_bencode_to_json(deser)?;
            println!("{}", json);
            Ok(())
        }
        "peers" => {
            let torrent = types::Metainfo::from_file(&args[2]).await?;
            eprintln!("fetching peers from tracker at {}", torrent.announce);
            let peers =
                tracker::get_peers(&torrent.announce, torrent.info.length, torrent.info.hash()?)
                    .await?;
            for p in peers.iter() {
                println!("{}", p);
            }
            Ok(())
        }
        "info" => {
            let metainf = types::Metainfo::from_file(&args[2])
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
            let metainf = types::Metainfo::from_file(&args[2])
                .await
                .context("failed to read metainfo file")?;
            let peer_addr =
                SocketAddrV4::from_str(&args[3]).context("failed to parse given peer address")?;

            let mut peer = peer::PeerState::connect(peer_addr, &metainf)
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

            let metainf = types::Metainfo::from_file(mi_file)
                .await
                .context("failed to read metainfo file")?;

            // tracker contact

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let peers =
                tracker::get_peers(&metainf.announce, metainf.info.length, metainf.info.hash()?)
                    .await?;

            // handshake begin

            let mut peer = peer::PeerState::connect(peers[0], &metainf).await?;
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
        "download" => {
            assert_eq!(
                args[2],
                "-o".to_string(),
                "output must be specified with -o <filepath> as 2nd & 3rd args"
            );

            let outfile = &args[3];
            let mi_file = &args[4];

            let metainf = types::Metainfo::from_file(mi_file)
                .await
                .context("failed to read metainfo file")?;

            // tracker contact

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let peers =
                tracker::get_peers(&metainf.announce, metainf.info.length, metainf.info.hash()?)
                    .await?;

            // handshake begin

            let mut peer = peer::PeerState::connect(peers[0], &metainf).await?;
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

            let mut piece_files = vec![];

            for (piece_idx, piece_hash) in metainf.info.pieces.chunks(20).enumerate() {
                let piece_idx = piece_idx as u32;
                eprintln!(
                    "fetching piece {} with hash {}",
                    piece_idx,
                    hex::encode(piece_hash)
                );
                let piece_buf = peer.get_piece(piece_idx).await?;

                let piece_filename = outfile.to_string() + ".part" + &format!("{:03}", piece_idx);
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&piece_filename)
                    .await
                    .context("error opening file for writing piece")?;
                f.write_all(&piece_buf)
                    .await
                    .context("error writing out piece buffer to file")?;

                eprintln!("Piece {} downloaded to {}", piece_idx, &piece_filename);
                piece_files.push(piece_filename);
            }

            let mut output = OpenOptions::new()
                .write(true)
                .create(true)
                .open(outfile)
                .await
                .context("error opening out file")?;
            for pf in piece_files {
                let mut input = OpenOptions::new()
                    .write(false)
                    .read(true)
                    .open(&pf)
                    .await
                    .context("error opening piece file for reading")?;
                tokio::io::copy(&mut input, &mut output).await?;
                drop(input);
                fs::remove_file(&pf).await?;
            }
            eprintln!("copied pieces into outfile {} and removed piece files", outfile);

            Ok(())
        }
        _ => {
            anyhow::bail!("unknown command: {}", args[1])
        }
    }
}
