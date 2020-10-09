use crate::*;
use crate::is_valid_decrypted_header;
use hmac::{NewMac, Mac};
use block_modes::BlockMode;
use rayon::prelude::{ParallelSliceMut, IndexedParallelIterator, ParallelIterator};

fn read_db_header(header: &[u8]) -> Result<(usize, usize)> {
    if !(&header[..16] == b"SQLite format 3\0" && is_valid_decrypted_header(&header[16..])) {
        return Err(Error::Message("invalid db header"))
    }
    let page = get_page_size_from_database_header(&header[16..])?;
    if !(is_valid_page_size(page)) {
        return Err(Error::Message("Invalid page size"))
    }
    let reserve = get_reserved_size_from_database_header(&header[16..]);
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
    bytes.par_chunks_mut(page).enumerate().try_for_each::<_, Result<()>>(|(i,mut page)|{
        if i == 0 {
            page = &mut page[16..];
        }
        let page_len = page.len();
        let page_content = &mut page[..page_len-reserve];
        Aes::new_var(&key[..], &[1u8; 16])?.encrypt(page_content, page_content.len())?;
        let mut hmac: Hmac = Hmac::new_varkey(hmac_key.as_slice())?;
        hmac.update(page_content);
        hmac.update(&[1u8; 16]);
        hmac.update(&((i + 1) as i32).to_le_bytes());
        let hmac_bytes = hmac.finalize().into_bytes();
        let reserve = &mut page[page_len-reserve..];
        // iv, hmac data and remaining reserve data
        let iv = &mut reserve[..16];
        for x in 0..16 { // 16
            iv[x as usize] = 1;
        }
        let mut remaining_reserve = &mut reserve[16..];
        let hmac_len = hmac_bytes.len();
        hmac_bytes.into_iter().zip(0..hmac_len).for_each(|(byte, index)| {
            remaining_reserve[index] = byte; // 20
        });
        let reserve_len = reserve.len();
        remaining_reserve = &mut reserve[16 + hmac_len..];
        for x in 0..reserve_len-36 {
            remaining_reserve[x] = 1;
        }
        Ok(())
    })?;
    Ok(())
}