use crate::*;
use std::convert::TryInto;
use block_modes::BlockMode;
use hmac::{NewMac, Mac};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
pub(crate) fn is_valid_decrypted_header(header: &[u8]) -> bool {
    header[5] == 64 && header[6] == 32 && header[7] == 32
}

#[inline]
pub(crate) fn get_page_size_from_database_header(header: &[u8]) -> usize {
    let page_sz = u16::from_be_bytes(header[..2].try_into().unwrap());
    (if page_sz == 1 {
        65536 as usize
    } else {
        page_sz as usize
    }) as usize
}

#[inline]
pub(crate) fn is_valid_page_size(page: usize) -> bool {
    page >= 512 && page == 2i32.pow((page as f32).log(2f32).floor() as u32) as usize
}

#[inline]
pub(crate) fn get_reserved_size_from_database_header(header: &[u8]) -> usize {
    header[4] as usize
}

#[inline]
fn read_db_header(header: &[u8]) -> Result<(usize, usize)> {
    if !(&header[..16] == b"SQLite format 3\0" && is_valid_decrypted_header(&header[16..])) {
        return Err(Error::Message("Invalid db header"))
    }
    let page = get_page_size_from_database_header(&header[16..]);
    if !(is_valid_page_size(page)) {
        return Err(Error::Message("Invalid page size"))
    }
    let reserve = get_reserved_size_from_database_header(&header[16..]);
    if reserve == 0 {
        return Err(Error::Message("Needs reserved space at the end of each page"))
    }
    Ok((page, reserve))
}

#[inline]
fn encrypt_page((index, mut page): (usize, &mut [u8]),
                key: &[u8],
                iv: &[u8],
                hmac_key: &[u8],
                reserve: usize) -> Result<()> {
    if index == 0 {
        page = &mut page[16..];
    }
    let page_len = page.len();
    let page_content = &mut page[..page_len - reserve];
    Aes::new_var(key, iv)?.encrypt(page_content, page_content.len())?;
    let mut hmac: Hmac = Hmac::new_varkey(hmac_key)?;
    hmac.update(page_content);
    hmac.update(iv);
    hmac.update(&((index + 1) as i32).to_le_bytes());
    let hmac_bytes = hmac.finalize().into_bytes();
    let reserve_slice = &mut page[page_len - reserve..];
    let iv_slice =  &mut reserve_slice[..16];
    iv.iter().zip(iv_slice.iter_mut()).for_each(|(byte, slot)| {
        *slot = *byte;
    });
    let reserve_slice = &mut reserve_slice[16..];
    let hmac_len = hmac_bytes.len();
    hmac_bytes.into_iter().zip(reserve_slice.iter_mut()).for_each(|(byte, slot)| {
         *slot = byte;
    });
    let reserve_slice = &mut reserve_slice[hmac_len..];
    for x in 0..reserve - (hmac_len + 16) {
        reserve_slice[x] = 1;
    }
    Ok(())
}

#[cfg(not(feature = "parallel"))]
#[inline]
fn encrypt_pages(bytes: &mut [u8],
                 key: &[u8],
                 iv: &[u8],
                 hmac_key: &[u8],
                 page: usize,
                 reserve: usize) -> Result<()> {
    bytes.chunks_exact_mut(page)
        .enumerate()
        .try_for_each(|x| encrypt_page(x, key, iv, hmac_key, reserve))?;
    Ok(())
}

#[cfg(feature = "parallel")]
fn encrypt_pages(bytes: &mut [u8],
                 key: &[u8],
                 iv: &[u8],
                 hmac_key: &[u8],
                 page: usize,
                 reserve: usize) -> Result<()> {
    bytes.par_chunks_exact_mut(page)
        .enumerate()
        .try_for_each(|x| encrypt_page(x, key, iv, hmac_key, reserve))?;
    Ok(())
}

/// Encrypts a decrypted SQLite database in place. This will use the database's set page size and reserve size.
pub fn encrypt(bytes: &mut [u8], key: &[u8], salt: &[u8; 16], iv: &[u8; 16]) -> Result<()> {
    let (page, reserve) = read_db_header(&bytes[..100])?;
    let (key, hmac_key) = key_derive(key, salt, true);
    salt.iter().zip(bytes.iter_mut()).for_each(|(byte, slot)| {
        *slot = *byte;
    });
    encrypt_pages(bytes, &key, iv, &hmac_key, page, reserve)?;
    Ok(())
}