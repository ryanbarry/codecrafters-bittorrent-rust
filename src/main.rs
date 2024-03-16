use std::{collections::BTreeMap, env, fs::File, io::Read, path::Path};

use bytes::BytesMut;

// Available if you need it!
// use serde_bencode

enum Bencoded {
    String(Vec<u8>),
    Integer(i64),
    List(Vec<Bencoded>),
    Dict(BTreeMap<String, Bencoded>),
}

impl Bencoded {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::String(v) => serde_json::Value::String(
                String::from_utf8(v.to_vec())
                    .expect("bencoded string can only convert to json if utf-8"),
            ),
            Self::Integer(i) => serde_json::Value::Number((*i).into()),
            Self::List(l) => serde_json::Value::Array(l.iter().map(|e| e.to_json()).collect()),
            Self::Dict(d) => serde_json::Value::Object(serde_json::Map::from_iter(
                d.iter().map(|(k, v)| (k.clone(), v.to_json())),
            )),
        }
    }
}

fn decode_bencoded_value(encoded_value: &[u8]) -> (Bencoded, &[u8]) {
    // If encoded_value starts with a digit, it's a string
    let mut chars = encoded_value.iter().peekable();
    match chars.next() {
        Some(b'd') => {
            let mut dict = BTreeMap::new();
            let mut rest: Vec<u8>;
            while chars.peek() != Some(&&b'e') {
                rest = chars.copied().collect::<Vec<u8>>();
                let (key, r) = decode_bencoded_value(&rest);
                match key {
                    Bencoded::String(key) => {
                        let (val, r) = decode_bencoded_value(r);
                        dict.insert(String::from_utf8(key).expect("key is valid utf-8"), val);
                        chars = r.iter().peekable();
                    }
                    _ => panic!("bencoded dictionary keys must be strings"),
                }
            }
            chars.next();
            (
                Bencoded::Dict(dict),
                &encoded_value[encoded_value.len() - chars.count()..],
            )
        }
        Some(b'l') => {
            let mut vals = vec![];
            let mut rest: Vec<u8>;
            while chars.peek() != Some(&&b'e') {
                rest = chars.copied().collect::<Vec<u8>>();
                let (v, r) = decode_bencoded_value(&rest);
                vals.push(v);
                chars = r.iter().peekable();
            }
            chars.next();
            (
                Bencoded::List(vals),
                &encoded_value[encoded_value.len() - chars.count()..],
            )
        }
        Some(b'i') => {
            let numerals: Vec<u8> = chars
                .map_while(|c| if *c != b'e' { Some(*c) } else { None })
                .collect();
            let integer: i64 = String::from_utf8(numerals.clone())
                .expect("number must be valid utf-8")
                .parse()
                .expect("failed to parse numerals into integer");
            (
                Bencoded::Integer(integer),
                &encoded_value[numerals.len() + 2..],
            )
        }
        Some(c) if c.is_ascii_digit() => {
            // Example: "5:hello" -> "hello"
            let colon_index = {
                let mut i = 0;
                while encoded_value[i] != b':' {
                    i += 1;
                }
                i
            };
            let number_string = String::from_utf8(encoded_value[..colon_index].to_vec())
                .expect("number string must be valid utf-8");
            let number = number_string.parse::<usize>().unwrap();
            let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
            (
                Bencoded::String(string.to_vec()),
                &encoded_value[number + colon_index + 1..],
            )
        }
        Some(_) | None => {
            panic!(
                "Unhandled encoded value: {}",
                String::from_utf8_lossy(encoded_value)
            )
        }
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    match command.trim() {
        "decode" => {
            let encoded_value = &args[2]
                .chars()
                .map(|c| c.try_into().expect("utf-8"))
                .collect::<Vec<u8>>();
            let (decoded_value, rest) = decode_bencoded_value(encoded_value);
            println!("{}", decoded_value.to_json());
            eprintln!("rest: {}", String::from_utf8_lossy(rest));
        }
        "info" => {
            let torrent_path = Path::new(&args[2]);
            println!("looking at torrent file: {}", torrent_path.display());
            let mut file = match File::open(torrent_path) {
                Err(why) => panic!("couldn't open {}: {}", torrent_path.display(), why),
                Ok(file) => file,
            };
            let fsz = file
                .metadata()
                .expect("couldn't read torrent file metadata")
                .len();
            eprintln!("torrent file is {} bytes", fsz);
            let mut cts = BytesMut::with_capacity(
                fsz.try_into()
                    .expect("torrent file too big to fit into memory"),
            );
            cts.resize(
                fsz.try_into()
                    .expect("entire torrent file cannot fit in buffer"),
                0,
            );
            match file.read(&mut cts) {
                Ok(0) => panic!("nothing read from torrent file"),
                Ok(bsz) => eprintln!("read {} bytes into buffer", bsz),
                Err(why) => panic!(
                    "error reading torrent file {}: {}",
                    torrent_path.display(),
                    why
                ),
            }
            let (decoded_value, _rest) = decode_bencoded_value(&cts);
            let tracker: String;
            match decoded_value {
                Bencoded::Dict(d) => {
                    assert!(
                        d.contains_key("announce"),
                        "torrent file dict must contain announce key"
                    );
                    assert!(
                        d.contains_key("info"),
                        "torrent file dict must contain info key"
                    );
                    match d.get("announce") {
                        Some(Bencoded::String(s)) => {
                            tracker = String::from_utf8(s.to_vec())
                                .expect("announce value must be valid utf-8")
                        }
                        _ => panic!("torrent file announce key's value is not a string"),
                    }
                }
                _ => panic!("torrent file should be a bencoded dict"),
            }
            println!("Tracker URL: {}", tracker);
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
