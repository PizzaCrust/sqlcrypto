use crate::*;
use crate::is_valid_decrypted_header;
use hmac::{NewMac, Mac};
use block_modes::BlockMode;

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

/// Encrypts a decrypted SQLite database, provided a key. Encrypts in place. THIS IS NOT SECURE!
pub fn encrypt(bytes: &mut [u8], key: &[u8]) -> Result<()> {
    let (page, reserve) = read_db_header(&bytes[..100])?;
    let (key, hmac_key) = key_derive(&[1u8; 16], key, true); // not particularly secure salt
    for x in 0..16 {
        bytes[x as usize] = 1;
    }
    let len = bytes.len();
    for i in 0..len/page {
        let mut page = &mut bytes[page * i..page*(i+1)];
        if i == 0 {
            page = &mut page[16..];
        }
        let page_content = &mut page[..page.len()-reserve];
        Aes::new_var(&key[..], &[1u8; 16])?.encrypt(page_content, page_content.len())?;
        let mut hmac: Hmac = Hmac::new_varkey(hmac_key.as_slice())?;
        hmac.update(page_content);
        hmac.update(&[1u8; 16]);
        hmac.update(&((i + 1) as i32).to_le_bytes());
        let hmac_bytes = hmac.finalize().into_bytes();
        let reserve = &mut page[page.len()-reserve..];
        // iv, hmac data and remaining reserve data
        let iv = &mut reserve[..16];
        for x in 0..16 {
            iv[x as usize] = 1;
        }
        let remaining_reserve = &mut reserve[16..];
        let hmac_len = hmac_bytes.len();
        println!("{}", hmac_len);
        hmac_bytes.into_iter().zip(0..hmac_len).for_each(|(byte, index)| {
            remaining_reserve[index] = byte;
        });
    }
    Ok(())
}