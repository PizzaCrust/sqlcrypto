use crate::*;
use crate::is_valid_decrypted_header;
use std::io::Write;
use ring::hmac::{Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY, sign};

fn read_db_header(header: &[u8]) -> Result<(usize, usize)> {
    if !(&header[..16] == b"SQLite format 3\0" && is_valid_decrypted_header(&header[16..])) {
        return Err(Error::Message("invalid db header"))
    }
    let page = get_page_size_from_database_header(header)?;
    if !(is_valid_page_size(page)) {
        return Err(Error::Message("Invalid page size"))
    }
    let reserve = get_reserved_size_from_database_header(header);
    if reserve == 0 {
        return Err(Error::Message("needs reserved space at the end of each page"))
    }
    Ok((page, reserve))
}

/// Encrypts a decrypted SQLite database, provided a key and an output stream. THIS IS NOT SECURE!
pub fn encrypt<R: AsRef<[u8]>, W: Write>(data: R, key: &[u8], output: &mut W) -> Result<()> {
    //let bytes = data.as_ref();
    //let (page, reserve) = read_db_header(&bytes[..100])?;
    //let (key, hmac_key) = key_derive(&[1u8; 16], key, true); // not particularly secure salt
    //let hmac_key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, hmac_key.as_slice());
    //let mut scheduled_key = vec![0u32; 60];
    //setkey_enc_k256(key.as_slice(), scheduled_key.as_mut_slice());
    //output.write(&[1u8; 16])?;
    //for i in 0..bytes.len()/page {
    //    let mut page = get_page(bytes, page, i + 1);
    //    if i == 0 {
    //        page = &page[16..];
    //    }
    //    let page_content = &page[..page.len()-reserve];
    //    let mut page_encrypted = vec![0u8; page_content.len()];
    //    cbc_enc(page_content, page_encrypted.as_mut_slice(), scheduled_key.as_slice(), &[1u8; 16]);
    //    let mut hmac_data: Vec<u8> = page_encrypted.iter().cloned().chain([1u8; 16].iter().cloned()).collect();
    //    hmac_data.write(&((i + 1) as i32).to_le_bytes())?;
    //    // TODO SIGN HMAC
    //    output.write(page_encrypted.as_slice())?;
    //    output.write(&[1u8; 16])?;
    //    output.write(sign(&hmac_key, hmac_data.as_slice()).as_ref())?;
    //    output.write(vec![1u8; reserve - 36].as_slice())?;
    //} todo finish this
    Ok(())
}