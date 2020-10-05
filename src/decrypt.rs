use crate::*;
use std::io::{Write};
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::pbkdf2::pbkdf2;
use crypto::aes::cbc_decryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

pub fn decrypt<W: Write>(mut bytes: &[u8], key: &[u8], output: &mut W) -> Result<()> {
    let salt = &bytes[..16];
    let mut mac = Hmac::new(Sha1::new(), key);
    let mut key_derive = vec![0u8; 32];
    pbkdf2(&mut mac, &salt[..], 64000, &mut key_derive[..]);
    let mut iv = &bytes[976..992];
    let mut page = vec![1u8; 1024];
    page.write(b"SQLite format 3\0")?;
    cbc_decryptor(KeySize256, key_derive.as_slice(), iv, NoPadding).decrypt(&mut RefReadBuffer::new(&bytes[16..976]), &mut RefWriteBuffer::new(page.as_mut_slice()), false)?;
    output.write(page.as_slice())?;
    //let mut index = 1024;
    //while index < bytes.len() {
    //    iv = &bytes[index + 976..index + 992];
    //    let mut page = vec![1u8; 1024];
    //    cbc_decryptor(KeySize256, key_derive.as_slice(), iv, NoPadding).decrypt(&mut RefReadBuffer::new(&bytes[index..index+992]), &mut RefWriteBuffer::new(page.as_mut_slice()), false)?;
    //    output.write(page.as_slice())?;
    //    index += 1024;
    //}
    Ok(())
}

