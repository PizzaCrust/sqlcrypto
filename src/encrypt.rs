use crate::*;
use crate::is_valid_decrypted_header;
use std::io::Write;
use crypto::aes::cbc_encryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

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

pub fn encrypt<W: Write>(bytes: &[u8], key: &[u8], output: &mut W) -> Result<()> {
    let (page, reserve) = read_db_header(&bytes[..100])?;
    let (key, hmac_key) = key_derive(&[1u8; 16], key); // not particularly secure salt
    output.write(&[1u8; 16])?;
    for i in 0..bytes.len()/1024 {
        let mut page = get_page(bytes, page, i + 1);
        if i == 0 {
            page = &page[16..];
        }
        let page_content = &page[..page.len()-reserve];
        let mut page_encrypted = vec![0u8; page_content.len()];
        cbc_encryptor(KeySize256, &key[..], &[1u8; 16], NoPadding)
            .encrypt(&mut RefReadBuffer::new(page_content),
                     &mut RefWriteBuffer::new(page_encrypted.as_mut_slice()),
                     true)?;
        let hmac_data: Vec<u8> = page_encrypted.iter().cloned().chain([1u8; 16].iter().cloned()).collect();
        let hmac = generate_hmac(&hmac_key[..], hmac_data, i)?;
        output.write(page_encrypted.as_slice())?;
        output.write(&[1u8; 16])?;
        output.write(hmac.code())?;
        output.write(vec![1u8; reserve - 36].as_slice())?;
    }
    Ok(())
}