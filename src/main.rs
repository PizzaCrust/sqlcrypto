fn main() -> sqlcrypto::Result<()> {
    let bytes = std::fs::read("test.db").unwrap();
    let mut output: Vec<u8> = Vec::new();
    sqlcrypto::decrypt(bytes.as_slice(), b"test", &mut output).unwrap();
    std::fs::write("test-dec.db", output).unwrap();
    Ok(())
}