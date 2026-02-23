use clap::{Parser, Subcommand};
use std::{arch::x86_64::_rdrand32_step, net::SocketAddr, path::PathBuf};
use types::MagnetLink;

use anyhow::Context;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};

mod peer;
mod tracker;
mod types;
mod utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Decode {
        bencoded: String,
    },
    Peers {
        torrent_file_path: PathBuf,
    },
    Peers2 {
        torrent_file_path: PathBuf,
    },
    Info {
        torrent_file_path: PathBuf,
    },
    Info2 {
        torrent_file_path: PathBuf,
    },
    Handshake {
        torrent_file_path: PathBuf,
        peer_address: SocketAddr,
    },
    #[command(name = "download_piece")]
    DownloadPiece {
        #[arg(short = 'o')]
        downloaded_file_path: PathBuf,
        torrent_file_path: PathBuf,
        piece_index: u32,
    },
    Download {
        #[arg(short = 'o')]
        downloaded_file_path: PathBuf,
        torrent_file_path: PathBuf,
    },
    #[command(name = "magnet_parse")]
    MagnetParse {
        magnet_link: String,
    },
    #[command(name = "magnet_handshake")]
    MagnetHandshake {
        magnet_link: String,
    },
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut peer_id = [0u8; 20];
    for idx in 0..5 {
        let mut randval = 0;
        unsafe {
            _rdrand32_step(&mut randval);
        }
        peer_id[idx * 4..idx * 4 + 4].copy_from_slice(&randval.to_le_bytes());
    }

    match cli.command {
        // "decode" => {
        Commands::Decode { bencoded } => {
            let deser: serde_bencode::value::Value =
                serde_bencode::from_str(&bencoded).expect("could not deserialize value");
            let json = utils::convert_bencode_to_json(deser)?;
            println!("{}", json);
            Ok(())
        }
        // "peers" => {
        Commands::Peers { torrent_file_path } => {
            let torrent = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed reading metainfo")?;

            eprintln!("fetching peers from tracker at {}", torrent.announce);
            let peers = tracker::announce(
                &torrent.announce,
                torrent.info.length(),
                torrent.info.hash()?,
                peer_id,
            )
            .await?;
            for p in peers.iter() {
                println!("{}", p);
            }
            Ok(())
        }
        // "peers2" => {
        Commands::Peers2 { torrent_file_path } => {
            let torrent = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed reading metainfo")?;

            let http_trackers = torrent
                .announce_list
                .iter()
                .flat_map(|al| {
                    al.iter()
                        .filter(|a| a.starts_with("http://"))
                        .cloned()
                        .collect::<Vec<String>>()
                })
                .collect::<Vec<String>>();

            eprintln!("found {} http trackers", http_trackers.len());

            eprintln!("fetching peers from tracker at {}", http_trackers[0]);
            let peers = &mut tracker::announce(
                &http_trackers[0],
                torrent.info.length(),
                torrent.info.hash()?,
                peer_id,
            )
            .await?;
            for p in peers.iter() {
                println!("{}", p);
            }
            Ok(())
        }
        // "info" => {
        Commands::Info { torrent_file_path } => {
            let metainf = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed to read metainfo file")?;
            println!("Tracker URL: {}", metainf.announce);
            println!("Length: {}", metainf.info.length());
            println!("Info Hash: {}", hex::encode(metainf.info.hash()?));
            println!("Piece Length: {}", metainf.info.piece_length());
            println!("Piece Hashes:");
            for ph in metainf.info.pieces().chunks(20).map(Vec::from) {
                println!("{}", hex::encode(ph));
            }
            Ok(())
        }
        // "info2" => {
        Commands::Info2 { torrent_file_path } => {
            let metainf = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed to read metainfo file")?;
            println!("Tracker URL: {}", metainf.announce);
            println!("Tracker URLs:\n{:?}", metainf.announce_list);
            println!("Length: {}", metainf.info.length());
            println!("Info Hash: {}", hex::encode(metainf.info.hash()?));
            println!("Piece Length: {}", metainf.info.piece_length());
            println!("Piece Hashes:");
            for ph in metainf.info.pieces().chunks(20).map(Vec::from) {
                println!("{}", hex::encode(ph));
            }
            Ok(())
        }
        // "handshake" => {
        Commands::Handshake {
            torrent_file_path,
            peer_address,
        } => {
            let metainf = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed to read metainfo file")?;

            eprintln!("starting connection to peer {}", peer_address);
            let mut peer = peer::PeerState::connect(peer_address, &peer_id, &metainf)
                .await
                .context("failed to connect to peer")?;

            peer.wait_for_handshake().await?;
            println!("Peer ID: {}", hex::encode(peer.remote_peer_id()));
            Ok(())
        }
        // "download_piece" => {
        Commands::DownloadPiece {
            downloaded_file_path,
            torrent_file_path,
            piece_index,
        } => {
            let metainf = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed to read metainfo file")?;

            // tracker contact

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let peers = tracker::announce(
                &metainf.announce,
                metainf.info.length(),
                metainf.info.hash()?,
                peer_id,
            )
            .await?;
            eprintln!("got peers: {:?}", peers);

            // handshake begin
            let rand_peer_idx = {
                let mut rand = 7u32;
                unsafe {
                    _rdrand32_step(&mut rand);
                }
                rand as usize % peers.len()
            };
            let selected_peer = peers[rand_peer_idx];
            eprintln!("chose peers[{}]: {}", rand_peer_idx, selected_peer);
            let mut peer = peer::PeerState::connect(selected_peer, &peer_id, &metainf).await?;
            eprintln!("waiting for handshake");
            peer.wait_for_handshake().await?;

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
            let piece_buf = peer.get_piece(piece_index).await?;

            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&downloaded_file_path)
                .await
                .context("error opening file for writing piece")?;
            f.write_all(&piece_buf)
                .await
                .context("error writing out piece buffer to file")?;

            println!(
                "Piece {} downloaded to {}",
                piece_index,
                downloaded_file_path.display()
            );

            Ok(())
        }
        // "download" => {
        Commands::Download {
            downloaded_file_path,
            torrent_file_path,
        } => {
            let metainf = types::Metainfo::from_file(torrent_file_path)
                .await
                .context("failed to read metainfo file")?;

            // tracker contact

            eprintln!("fetching peers from tracker at {}", metainf.announce);
            let peers = tracker::announce(
                &metainf.announce,
                metainf.info.length(),
                metainf.info.hash()?,
                peer_id,
            )
            .await?;

            // handshake begin

            let mut peer = peer::PeerState::connect(peers[0], &peer_id, &metainf).await?;
            eprintln!("waiting for handshake");
            peer.wait_for_handshake().await?;

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

            for (piece_index, piece_hash) in metainf.info.pieces().chunks(20).enumerate() {
                let piece_index = piece_index as u32;
                eprintln!(
                    "fetching piece {} with hash {}",
                    piece_index,
                    hex::encode(piece_hash)
                );
                let piece_buf = peer.get_piece(piece_index).await?;

                let piece_filename = downloaded_file_path
                    .to_str()
                    .expect("need download path")
                    .to_owned()
                    + ".part"
                    + &format!("{:03}", piece_index);
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&piece_filename)
                    .await
                    .context("error opening file for writing piece")?;
                f.write_all(&piece_buf)
                    .await
                    .context("error writing out piece buffer to file")?;

                eprintln!("Piece {} downloaded to {}", piece_index, &piece_filename);
                piece_files.push(piece_filename);
            }

            let mut output = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&downloaded_file_path)
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
            eprintln!(
                "copied pieces into outfile {} and removed piece files",
                downloaded_file_path.display()
            );

            Ok(())
        }
        // "magent_parse" => {
        Commands::MagnetParse { magnet_link } => {
            let maglink = MagnetLink::parse(magnet_link).context("parsing magnet link")?;

            println!(
                "Tracker URL: {}",
                maglink
                    .tracker_url(0)
                    .context("tracker URL required but not found")?
            );
            println!("Info Hash: {}", maglink.info_hash_hex());

            Ok(())
        }
        // "magnet_handshake" => {
        Commands::MagnetHandshake { magnet_link } => {
            let maglink = MagnetLink::parse(magnet_link).context("parsing magnet link")?;
            let tracker_url = match maglink.tr {
                None => return Err(anyhow::anyhow!("no tracker URL in given magnet link")),
                Some(tv) => {
                    eprintln!("found {} trackers", tv.len());
                    tv[0].clone()
                }
            };
            let torrent = crate::types::Metainfo {
                announce: String::from(""),
                info: crate::types::InfoDict::SingleFile {
                    name: String::from(""),
                    piece_length: 0,
                    length: 0,
                    pieces: serde_bytes::ByteBuf::new(),
                },
                announce_list: vec![],
                url_list: vec![],
                created_by: String::from(""),
                creation_date: 0,
            };

            eprintln!("fetching peers from tracker[0] at {}", tracker_url);
            let peers = tracker::announce(&tracker_url, 1, maglink.info_hash, peer_id).await?;
            eprintln!("got peers: {:?}", peers);

            if peers.len() < 1 {
                return Err(anyhow::anyhow!("no peers given in tracker's response"));
            }

            let rand_peer_idx = {
                let mut rand = 7u32;
                unsafe {
                    _rdrand32_step(&mut rand);
                }
                rand as usize % peers.len()
            };
            let selected_peer = peers[rand_peer_idx];
            eprintln!("chose peers[{}]: {}", rand_peer_idx, selected_peer);

            let mut peer =
                peer::PeerState::connect_ext(selected_peer, &maglink.info_hash, &peer_id, &torrent)
                    .await
                    .context("failed to connect to peer")?;

            eprintln!("waiting for handshake...");
            peer.wait_for_handshake().await?;
            println!("Peer ID: {}", hex::encode(peer.remote_peer_id()));

            Ok(())
        }
    }
}
