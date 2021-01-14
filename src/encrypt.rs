use crate::*;
use std::convert::TryInto;
use block_modes::BlockMode;
use hmac::{NewMac, Mac};
use getrandom::getrandom;
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

/// Reads a database's header for the page size and reserve size.
/// Will error if it's an invalid header or a invalid page size.
#[inline]
pub fn read_db_header(header: &[u8]) -> Result<(usize, usize)> {
    if !(&header[..16] == b"SQLite format 3\0" && is_valid_decrypted_header(&header[16..])) {
        return Err(Error::Header)
    }
    let page = get_page_size_from_database_header(&header[16..]);
    if !(is_valid_page_size(page)) {
        return Err(Error::PageSize)
    }
    let reserve = get_reserved_size_from_database_header(&header[16..]);
    Ok((page, reserve))
}

#[inline]
fn encrypt_page((index, mut page): (usize, &mut [u8]),
                key: &[u8],
                hmac_key: &[u8],
                reserve: usize) -> Result<()> {
    if index == 0 {
        page = &mut page[16..];
    }
    let page_len = page.len();
    let page_content = &mut page[..page_len - reserve];
    let mut iv = [0u8; 16];
    getrandom(&mut iv)?;
    Aes::new_var(key, &iv)?.encrypt(page_content, page_content.len())?;
    let mut hmac: Hmac = Hmac::new_varkey(hmac_key)?;
    hmac.update(page_content);
    hmac.update(&iv);
    hmac.update(&((index + 1) as i32).to_le_bytes());
    let hmac_bytes = hmac.finalize().into_bytes();
    let reserve_slice = &mut page[page_len - reserve..];
    let iv_slice =  &mut reserve_slice[..16];
    iv_slice.copy_from_slice(&iv);
    let reserve_slice = &mut reserve_slice[16..];
    let hmac_len = hmac_bytes.len();
    reserve_slice[..hmac_len].copy_from_slice(hmac_bytes.as_slice());
    let reserve_slice = &mut reserve_slice[hmac_len..];
    let mut noise = [0u8; 12];
    getrandom(&mut noise)?;
    reserve_slice.copy_from_slice(&noise);
    Ok(())
}

#[cfg(not(feature = "parallel"))]
#[inline]
fn encrypt_pages(bytes: &mut [u8],
                 key: &[u8],
                 hmac_key: &[u8],
                 page: usize,
                 reserve: usize) -> Result<()> {
    bytes.chunks_exact_mut(page)
        .enumerate()
        .try_for_each(|x| encrypt_page(x, key, hmac_key, reserve))?;
    Ok(())
}

#[cfg(feature = "parallel")]
fn encrypt_pages(bytes: &mut [u8],
                 key: &[u8],
                 hmac_key: &[u8],
                 page: usize,
                 reserve: usize) -> Result<()> {
    bytes.par_chunks_exact_mut(page)
        .enumerate()
        .try_for_each(|x| encrypt_page(x, key, hmac_key, reserve))?;
    Ok(())
}

/// Encrypts a decrypted SQLite database in place.
/// It incurs no allocations and can be parallelized, however the database must have a reserve.
pub fn encrypt(bytes: &mut [u8],
               key: &[u8],
               (page, reserve): (usize, usize)) -> Result<()> {
    if reserve == 0 {
        return Err(Error::Reserve);
    }
    let mut salt = [0u8; 16];
    getrandom(&mut salt)?;
    bytes[..16].copy_from_slice(&salt);
    let (key, hmac_key) = key_derive(key, &salt, true);
    encrypt_pages(bytes, &key, &hmac_key, page, reserve)?;
    Ok(())
}