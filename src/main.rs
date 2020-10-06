fn main() -> sqlcrypto::Result<()> {
    let bytes = std::fs::read("test.db").unwrap();
    //println!("{:#?}", &bytes[..16] == b"SQLite format 3\0");
    let mut output: Vec<u8> = Vec::new();
    sqlcrypto::decrypt(bytes.as_slice(), b"test", &mut output).unwrap();
    //println!("{:#?}", output);
    std::fs::write("test-dec.db", output).unwrap();
    Ok(())
}