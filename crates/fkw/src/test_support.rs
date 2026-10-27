pub(crate) fn vector(source: &str, name: &str) -> Vec<u8> {
    let hex = source
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then_some(value)
        })
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
