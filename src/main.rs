use sqlcrypto::Error;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

fn main() -> sqlcrypto::Result<()> {
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(0);
    if args.len() != 4 {
        println!("sqlcrypto-cli.exe encrypt/decrypt encrypted.db password decrypted.db");
        return Ok(());
    }
    let mut victim = std::fs::read(&args[1])?;
    let password = &args[2];
    let mut result = File::create(&args[3])?;
    let instant = Instant::now();
    match &*args[0] {
        "decrypt" => {
            println!("decrypting");
            sqlcrypto::decrypt(&mut victim, password.as_bytes())?;
            Ok(())
        }
        "encrypt" => {
            println!("encrypting");
            sqlcrypto::encrypt(&mut victim, password.as_bytes())?;
            Ok(())
        }
        _ => Err(Error::Message("Invalid mode")),
    }?;
    println!("took {} milliseconds", instant.elapsed().as_millis());
    result.write_all(victim.as_slice())?;
    Ok(())
}
