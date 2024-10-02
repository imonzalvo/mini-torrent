use std::collections::HashMap;
use std::str;

#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub enum BencodeValue {
    Integer(i64),
    ByteString(Vec<u8>),
    List(Vec<BencodeValue>),
    Dictionary(HashMap<String, BencodeValue>),
}

pub fn parse_bencode(data: &[u8]) -> Result<(BencodeValue, &[u8]), String> {
    match data[0] as char {
        'i' => {
            let end = data.iter().position(|&x| x == b'e').ok_or("Invalid integer")?;
            let num = str::from_utf8(&data[1..end])
                .map_err(|e| e.to_string())?
                .parse::<i64>()
                .map_err(|e| e.to_string())?;
            Ok((BencodeValue::Integer(num), &data[end + 1..]))
        }
        '0'..='9' => {
            let colon = data.iter().position(|&x| x == b':').ok_or("Invalid byte string")?;
            let length = str::from_utf8(&data[..colon])
                .map_err(|e| e.to_string())?
                .parse::<usize>()
                .map_err(|e| e.to_string())?;
            let content = data[colon + 1..colon + 1 + length].to_vec();
            Ok((BencodeValue::ByteString(content), &data[colon + 1 + length..]))
        }
        'l' => {
            let mut list = Vec::new();
            let mut rest = &data[1..];
            while rest[0] != b'e' {
                let (value, new_rest) = parse_bencode(rest)?;
                list.push(value);
                rest = new_rest;
            }
            Ok((BencodeValue::List(list), &rest[1..]))
        }
        'd' => {
            let mut dict = HashMap::new();
            let mut rest = &data[1..];
            while rest[0] != b'e' {
                let (key, new_rest) = parse_bencode(rest)?;
                let key = if let BencodeValue::ByteString(bytes) = key {
                    String::from_utf8(bytes).map_err(|e| e.to_string())?
                } else {
                    return Err("Dictionary key must be a byte string".to_string());
                };
                let (value, new_rest) = parse_bencode(new_rest)?;
                dict.insert(key, value);
                rest = new_rest;
            }
            Ok((BencodeValue::Dictionary(dict), &rest[1..]))
        }
        _ => Err("Invalid bencode".to_string()),
    }
}

pub fn bencode_encode(value: &BencodeValue) -> Vec<u8> {
    match value {
        BencodeValue::Integer(i) => format!("i{}e", i).into_bytes(),
        BencodeValue::ByteString(s) => {
            let mut result = format!("{}:", s.len()).into_bytes();
            result.extend_from_slice(s);
            result
        }
        BencodeValue::List(l) => {
            let mut result = b"l".to_vec();
            for item in l {
                result.extend(bencode_encode(item));
            }
            result.push(b'e');
            result
        }
        BencodeValue::Dictionary(d) => {
            let mut result = b"d".to_vec();
            let mut keys: Vec<_> = d.keys().collect();
            keys.sort(); // Sort keys for consistent encoding
            for key in keys {
                result.extend(bencode_encode(&BencodeValue::ByteString(key.as_bytes().to_vec())));
                result.extend(bencode_encode(&d[key]));
            }
            result.push(b'e');
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_integer() {
        let data = b"i12345e";
        let (parsed, rest) = parse_bencode(data).unwrap();
        assert_eq!(parsed, BencodeValue::Integer(12345));
        assert_eq!(rest, &b""[..]);

        let data = b"i-6789e";
        let (parsed, rest) = parse_bencode(data).unwrap();
        assert_eq!(parsed, BencodeValue::Integer(-6789));
        assert_eq!(rest, &b""[..]);
    }

    #[test]
    fn test_parse_byte_string() {
        let data = b"5:hello";
        let (parsed, rest) = parse_bencode(data).unwrap();
        assert_eq!(parsed, BencodeValue::ByteString(b"hello".to_vec()));
        assert_eq!(rest, &b""[..]);

        let data = b"0:";
        let (parsed, rest) = parse_bencode(data).unwrap();
        assert_eq!(parsed, BencodeValue::ByteString(b"".to_vec()));
        assert_eq!(rest, &b""[..]);
    }

    #[test]
    fn test_parse_list() {
        let data = b"li123e4:spam4:eggse";
        let (parsed, rest) = parse_bencode(data).unwrap();
        assert_eq!(
            parsed,
            BencodeValue::List(vec![
                BencodeValue::Integer(123),
                BencodeValue::ByteString(b"spam".to_vec()),
                BencodeValue::ByteString(b"eggs".to_vec())
            ])
        );
        assert_eq!(rest, &b""[..]);
    }

    #[test]
    fn test_parse_dictionary() {
        let data = b"d3:bar4:spam3:fooi42ee";
        let (parsed, rest) = parse_bencode(data).unwrap();
        let mut expected_dict = HashMap::new();
        expected_dict.insert("bar".to_string(), BencodeValue::ByteString(b"spam".to_vec()));
        expected_dict.insert("foo".to_string(), BencodeValue::Integer(42));
        assert_eq!(parsed, BencodeValue::Dictionary(expected_dict));
        assert_eq!(rest, &b""[..]);
    }

    #[test]
    fn test_bencode_encode_integer() {
        let value = BencodeValue::Integer(12345);
        let encoded = bencode_encode(&value);
        assert_eq!(encoded, b"i12345e");
    }

    #[test]
    fn test_bencode_encode_byte_string() {
        let value = BencodeValue::ByteString(b"hello".to_vec());
        let encoded = bencode_encode(&value);
        assert_eq!(encoded, b"5:hello");

        let value = BencodeValue::ByteString(b"".to_vec());
        let encoded = bencode_encode(&value);
        assert_eq!(encoded, b"0:");
    }

    #[test]
    fn test_bencode_encode_list() {
        let value = BencodeValue::List(vec![
            BencodeValue::Integer(123),
            BencodeValue::ByteString(b"spam".to_vec()),
            BencodeValue::ByteString(b"eggs".to_vec()),
        ]);
        let encoded = bencode_encode(&value);
        assert_eq!(encoded, b"li123e4:spam4:eggse");
    }

    #[test]
    fn test_bencode_encode_dictionary() {
        let mut dict = HashMap::new();
        dict.insert("foo".to_string(), BencodeValue::Integer(42));
        dict.insert("bar".to_string(), BencodeValue::ByteString(b"spam".to_vec()));
        let value = BencodeValue::Dictionary(dict);
        let encoded = bencode_encode(&value);
        assert_eq!(encoded, b"d3:bar4:spam3:fooi42ee");
    }

    #[test]
    fn test_parse_invalid_data() {
        let data = b"i12345";
        assert!(parse_bencode(data).is_err());
    }

    #[test]
    fn test_round_trip_encoding_decoding() {
        let value = BencodeValue::List(vec![
            BencodeValue::Integer(123),
            BencodeValue::ByteString(b"spam".to_vec()),
            BencodeValue::ByteString(b"eggs".to_vec()),
        ]);
        let encoded = bencode_encode(&value);
        let (decoded, _) = parse_bencode(&encoded).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_round_trip_encoding_encoding() {
        let value = b"1-5%3~]+=\\| []>.,`??";
        let (decoded, _) = parse_bencode(value).unwrap();
        let encoded = bencode_encode(&decoded);
        
        println!("Value: {:?}", value);
        println!("Encoded: {:?}", encoded);
        assert_eq!(encoded, value);
    }
}
