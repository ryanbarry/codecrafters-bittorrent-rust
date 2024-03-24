pub fn convert_bencode_to_json(
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
pub fn hexedit<T: AsRef<[u8]>>(data: T) -> String {
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
