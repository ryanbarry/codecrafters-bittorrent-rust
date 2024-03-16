use std::{collections::BTreeMap, env};

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
            println!("looking at torrent file: {}", &args[2]);
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
