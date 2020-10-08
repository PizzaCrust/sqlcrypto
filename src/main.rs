use std::time::Instant;
use std::fs::File;
use sqlcrypto::Error;

fn main() -> sqlcrypto::Result<()> {
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(0);
    if args.len() != 4 {
        println!("sqlcrypto-cli.exe encrypt/decrypt encrypted.db password decrypted.db");
        return Ok(())
    }
    let victim = std::fs::read(&args[1])?;
    let password = &args[2];
    let mut result = File::create(&args[3])?;
    let instant = Instant::now();
    match &*args[0] {
        "decrypt" => {
            println!("decrypting");
            sqlcrypto::decrypt(victim, password.as_bytes(), &mut result)?;
            Ok(())
        }
        "encrypt" => {
            println!("encrypting");
            sqlcrypto::encrypt(victim, password.as_bytes(), &mut result)?;
            Ok(())
        }
        _ => {
            Err(Error::Message("Invalid mode"))
        }
    }?;
    println!("took {} seconds", instant.elapsed().as_secs_f32());
    Ok(())
}