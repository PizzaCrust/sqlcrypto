use std::time::Instant;
use std::fs::File;

fn main() -> lsqlcrypto::Result<()> {
    let bytes = std::fs::read("encrypted.db").unwrap(); // 115 sec rust crypto hmac check
    //let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let instant = Instant::now();
    let mut file = File::create("decrypted.db")?;
    lsqlcrypto::decrypt(bytes, b"9bf9c6ed9d537c399a6c4513e92ab24717e1a488381e3338593abd923fc8a13b", &mut file).unwrap();
    //lsqlcrypto::encrypt(bytes.as_slice(), b"test", &mut file)?;
    println!("took {} ms", instant.elapsed().as_millis());
    Ok(())
}