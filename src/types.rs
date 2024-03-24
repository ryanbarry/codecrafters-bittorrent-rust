use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Serialize, Deserialize, Clone)]
pub struct InfoDictFile {
    pub length: u32,
    pub path: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum InfoDict {
    SingleFile {
        name: String,
        #[serde(rename = "piece length")]
        piece_length: u32,
        pieces: ByteBuf,
        length: u32,
    },
    MultiFile {
        name: String,
        #[serde(rename = "piece length")]
        piece_length: u32,
        pieces: ByteBuf,
        files: Vec<InfoDictFile>,
    },
}

impl InfoDict {
    pub fn hash(&self) -> anyhow::Result<[u8; 20]> {
        let mut hasher = Sha1::new();
        hasher.update(serde_bencode::to_bytes(&self)?);
        Ok(hasher.finalize().into())
    }

    pub fn piece_length(&self) -> u32 {
        match &self {
            InfoDict::SingleFile { piece_length, .. } => *piece_length,
            InfoDict::MultiFile { piece_length, .. } => *piece_length,
        }
    }

    pub fn pieces(&self) -> &ByteBuf {
        match &self {
            InfoDict::SingleFile { pieces, .. } => pieces,
            InfoDict::MultiFile { pieces, .. } => pieces,
        }
    }

    pub fn length(&self) -> u32 {
        match &self {
            InfoDict::SingleFile { length, .. } => *length,
            InfoDict::MultiFile { files, .. } => files.iter().map(|f| f.length).sum(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Metainfo {
    pub announce: String,
    pub info: InfoDict,
    #[serde(rename = "announce-list")]
    #[serde(default)]
    pub announce_list: Vec<Vec<String>>,
}

impl Metainfo {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut file = File::open(path).await?;
        let fsz = file.metadata().await?.len();
        let mut contents = Vec::with_capacity(fsz.try_into()?);
        file.read_to_end(&mut contents).await?;
        Ok(serde_bencode::from_bytes(&contents)?)
    }
}
