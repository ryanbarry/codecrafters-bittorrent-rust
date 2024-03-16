use std::env;

// Available if you need it!
// use serde_bencode

fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    // If encoded_value starts with a digit, it's a string
    let mut chars = encoded_value.chars().peekable();
    match chars.next() {
        Some('l') => {
            let mut vals = vec![];
            let mut rest: String;
            while chars.peek() != Some(&'e') {
                rest = chars.collect::<String>();
                let (v, r) = decode_bencoded_value(&rest);
                vals.push(v);
                chars = r.chars().peekable();
            }
            chars.next();
            (
                serde_json::Value::Array(vals),
                &encoded_value[encoded_value.len() - chars.count()..],
            )
        }
        Some('i') => {
            let numerals: String = chars.take_while(|c| *c != 'e').collect();
            let integer: isize = numerals
                .parse()
                .expect("failed to parse numerals into integer");
            (
                serde_json::Value::Number(integer.into()),
                &encoded_value[numerals.len() + 2..],
            )
        }
        Some(c) if c.is_ascii_digit() => {
            // Example: "5:hello" -> "hello"
            let colon_index = encoded_value.find(':').unwrap();
            let number_string = &encoded_value[..colon_index];
            let number = number_string.parse::<usize>().unwrap();
            let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
            (
                serde_json::Value::String(string.to_string()),
                &encoded_value[number + colon_index + 1..],
            )
        }
        Some(_) | None => {
            panic!("Unhandled encoded value: {}", encoded_value)
        }
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let (decoded_value, rest) = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value);
        eprintln!("rest: {}", rest);
    } else {
        println!("unknown command: {}", args[1])
    }
}
