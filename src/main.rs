use std::time::Instant;

fn main() -> sqlcrypto::Result<()> {
    let bytes = std::fs::read("encrypted.db").unwrap();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let instant = Instant::now();
    sqlcrypto::decrypt(bytes.as_slice(), b"9bf9c6ed9d537c399a6c4513e92ab24717e1a488381e3338593abd923fc8a13b", &mut output).unwrap();
    println!("took {} ms", instant.elapsed().as_millis());
    std::fs::write("decrypted.db", output).unwrap();
    Ok(())
}