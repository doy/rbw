use base64::Engine as _;

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}

pub fn encode_url_safe_no_pad<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn decode<T: AsRef<[u8]>>(
    input: T,
) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

pub fn decode_url_safe_no_pad<T: AsRef<[u8]>>(
    input: T,
) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode_url_safe_no_pad() {
        assert_eq!(
            super::decode_url_safe_no_pad("eyJzdWIiOiJhYmMifQ").unwrap(),
            br#"{"sub":"abc"}"#
        );
        assert!(super::decode_url_safe_no_pad("!!!").is_err());
    }
}
