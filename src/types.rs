use std::{collections::HashMap, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Serialize, Deserialize, Clone)]
pub struct InfoDictFile {
    pub length: u64,
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
        length: u64,
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

    pub fn length(&self) -> u64 {
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
    #[serde(rename = "url-list")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub url_list: Vec<String>,
    #[serde(default)]
    #[serde(rename = "created by")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    #[serde(rename = "creation date")]
    #[serde(default)]
    pub creation_date: u64,
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

#[allow(unused)]
pub struct MagnetLink {
    pub info_hash: [u8; 20],
    // display name
    pub dn: Option<String>,
    // tracker(s)
    pub tr: Option<Vec<String>>,
    // peer address(es)
    pub xpe: Option<Vec<String>>,
}

impl MagnetLink {
    pub fn parse<S: AsRef<str>>(link_text: S) -> anyhow::Result<Self> {
        let link = reqwest::Url::parse(link_text.as_ref()).context("parsing magnet link as URL")?;

        let link_query: HashMap<String, String> = link
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let tracker = link_query.get("tr");

        let info_hash_hex = link_query
            .get("xt")
            .expect("xt query param not found, but is required")
            .strip_prefix("urn:btih:")
            .context("xt query param value must begin with urn:btih: prefix")?;

        let mut info_hash: [u8; 20] = [0u8; 20];
        hex::decode_to_slice(info_hash_hex, &mut info_hash)?;

        Ok(Self {
            dn: None,
            tr: tracker.map(|ts| vec![ts.clone()]),
            info_hash,
            xpe: None,
        })
    }

    pub fn info_hash_hex(&self) -> String {
        hex::encode(self.info_hash)
    }

    pub fn tracker_url(&self, index: usize) -> Option<String> {
        match &self.tr {
            None => None,
            Some(tr) => tr.get(index).cloned(),
        }
    }
}
