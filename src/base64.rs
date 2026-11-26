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

pub fn decode_url_safe<T: AsRef<[u8]>>(
    input: T,
) -> Result<Vec<u8>, base64::DecodeError> {
    let bytes = input.as_ref();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(bytes)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(bytes))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(bytes))
}

#[test]
fn test_decode_url_safe_variants() {
    let raw = [0xfb_u8, 0xff, 0xfe, 0x01];
    let url_no_pad = encode_url_safe_no_pad(raw);
    let url_pad = base64::engine::general_purpose::URL_SAFE.encode(raw);
    let std = encode(raw);

    assert_eq!(decode_url_safe(&url_no_pad).unwrap(), raw);
    assert_eq!(decode_url_safe(&url_pad).unwrap(), raw);
    assert_eq!(decode_url_safe(&std).unwrap(), raw);
}
