use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

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

fn urlenc<B: AsRef<[u8]>>(bytes: B) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| match *b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~' => {
                format!("{}", *b as char)
            }
            _ => format!("%{:02X}", b),
        })
        .collect::<String>()
}

pub async fn announce(
    tracker_addr: &str,
    left: u32,
    infohash: [u8; 20],
    my_peer_id: [u8; 20],
) -> anyhow::Result<Vec<SocketAddrV4>> {
    let ih_urlenc = urlenc(&infohash);
    let id_urlenc = urlenc(&my_peer_id);

    eprintln!("fetching peers from tracker at {}", tracker_addr);
    let tracker_client = reqwest::Client::new();
    let mut req = tracker_client
        .get(tracker_addr)
        .query(&[
            ("compact", "1"),
            ("left", &left.to_string()),
            ("port", "6881"),
            ("uploaded", "0"),
            ("downloaded", "0"),
        ])
        .build()?;
    let q = req
        .url()
        .query()
        .expect("query parameters were not created");
    let newq = q.to_owned() + "&info_hash=" + &ih_urlenc + "&peer_id=" + &id_urlenc;
    req.url_mut().set_query(Some(&newq));

    //eprintln!("request: {:?}", req);
    let res = tracker_client
        .execute(req)
        .await
        .expect("failed to get from tracker");
    let body = res
        .bytes()
        .await
        .expect("could not read response from tracker")
        .to_vec();
    //eprintln!("got a response: {}", String::from_utf8_lossy(&body));
    match serde_bencode::from_bytes(&body) {
        Ok(TrackerResponse::Error(e)) => Err(anyhow!(
            "tracker responded with error: {}",
            e.failure_reason
        )),
        Ok(TrackerResponse::Success(r)) => Ok(r
            .peers
            .chunks(6)
            .map(|peer| {
                let mut ipbytes: [u8; 4] = [0; 4];
                ipbytes.copy_from_slice(&peer[0..4]);
                let mut skbytes = [0u8; 2];
                skbytes.copy_from_slice(&peer[4..6]);
                SocketAddrV4::new(Ipv4Addr::from(ipbytes), u16::from_be_bytes(skbytes))
            })
            .collect()),
        Err(e) => {
            eprintln!(
                "error reading tracker data, data as json:\n{}",
                crate::utils::convert_bencode_to_json(
                    serde_bencode::from_bytes(&body).expect("could not deserialize as bencode")
                )
                .expect("invalid conversion")
            );
            Err(anyhow!("error deserializing tracker response: {}", e))
        }
    }
}
