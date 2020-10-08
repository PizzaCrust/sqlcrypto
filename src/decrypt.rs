use crate::*;
use std::io::{Write};
use std::convert::TryInto;
use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA1};
use std::num::NonZeroU32;
use ring::hmac::{Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY, verify};
use aes_frast::aes_core::setkey_dec_k256;
use aes_frast::aes_with_operation_mode::cbc_dec;

#[inline]
pub(crate) fn key_derive(salt: &[u8], key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut derived_key = vec![0u8; 32];
    unsafe {
        derive(PBKDF2_HMAC_SHA1, NonZeroU32::new_unchecked(64000), salt, key, &mut derived_key[..]);
    }
    let hmac_salt: Vec<u8> = salt.iter().map(|x| x ^ (0x3a)).collect();
    let mut hmac_key = vec![0u8; 32];
    unsafe {
        derive(PBKDF2_HMAC_SHA1, NonZeroU32::new_unchecked(2), hmac_salt.as_slice(), derived_key.as_slice(), hmac_key.as_mut_slice());
    }
    (derived_key, hmac_key)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn verify_hmac(hmac_key: &Key, mut content: Vec<u8>, page_num: usize, hmac_old: &[u8]) -> Result<()> {
    content.write(&((page_num + 1) as i32).to_le_bytes())?;
    verify(hmac_key, content.as_slice(), hmac_old)?;
    Ok(())
}

/// Decrypts an encrypted SQLite database, provided a key and an output stream.
pub fn decrypt<R: AsRef<[u8]>, W: Write>(data: R, key: &[u8], output: &mut W) -> Result<()> {
    let bytes = data.as_ref();
    output.write(b"SQLite format 3\0")?; // lol
    let salt = &bytes[..16];
    let (key, hmac_key) = key_derive(salt, key);
    let mut scheduled_keys = vec![0u32; 60];
    setkey_dec_k256(key.as_slice(), scheduled_keys.as_mut_slice());
    let hmac_key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, hmac_key.as_slice());
    let mut page: usize = 1024;
    let mut reserve: usize = 48;
    reserve = decrypt_page_header(bytes, scheduled_keys.as_slice(), 16, &mut page, 16, reserve)?;
    for i in 0..bytes.len()/page {
        let mut page = get_page(bytes, page, i + 1);
        if i == 0 {
            page = &page[16..];
        }
        let page_content = &page[..page.len()-reserve];
        let reserve = &page[page.len()-reserve..];
        let iv = &reserve[..16];
        let hmac_old = &reserve[16..16+20];
        let hmac_data: Vec<u8> = page_content.iter().cloned().chain(iv.iter().cloned()).collect();
        #[cfg(not(target_arch = "wasm32"))] verify_hmac(&hmac_key, hmac_data, i, hmac_old)?;
        let mut page_decrypted = vec![1u8; page_content.len() + reserve.len()];
        cbc_dec(page_content, page_decrypted.as_mut_slice(), scheduled_keys.as_slice(), iv);
        output.write(&page_decrypted[..])?;
    }
    Ok(())
}

#[inline]
pub(crate) fn is_valid_page_size(page: usize) -> bool {
    page >= 512 && page == 2i32.pow((page as f32).log(2f32).floor() as u32) as usize
}

fn decrypt_page_header(bytes: &[u8], scheduled_key: &[u32], salt: usize, page: &mut usize, iv: usize, reserve: usize) -> Result<usize> {
    if !(is_valid_page_size(*page)) {
        *page = 512;
    }
    let new_reserve = try_get_reserve_size_for_specified_page_size(bytes, scheduled_key, salt, *page, iv, reserve)?;
    if new_reserve > 0 {
        return Ok(new_reserve as usize)
    }
    *page = 512;
    while *page <= 65536 {
        let new_reserve = try_get_reserve_size_for_specified_page_size(bytes, scheduled_key, salt, *page, iv, reserve)?;
        if new_reserve > 0 {
            return Ok(new_reserve as usize)
        }
        *page <<= 1;
    }
    Err(Error::Message("Failed to decrypt page header"))
}

#[inline]
pub(crate) fn get_page(bytes: &[u8], page: usize, page_number: usize) -> &[u8] {
    &bytes[page*(page_number-1)..page*page_number]
}

#[inline]
pub(crate) fn is_valid_decrypted_header(header: &[u8]) -> bool {
    header[5] == 64 && header[6] == 32 && header[7] == 32
}

#[inline]
pub(crate) fn get_page_size_from_database_header(header: &[u8]) -> Result<usize> {
    let page_sz = u16::from_be_bytes(header[16..18].try_into().unwrap());
    Ok(if page_sz == 1 {
        65536 as usize
    } else {
        page_sz as usize
    } as usize)
}

#[inline]
pub(crate) fn get_reserved_size_from_database_header(header: &[u8]) -> usize {
    header[20] as usize
}

fn try_get_reserve_size_for_specified_page_size(bytes: &[u8], scheduled_key: &[u32], salt: usize, page: usize, iv: usize, reserve: usize) -> Result<isize> {
    let first_page_content = &get_page(bytes, page, 1)[salt..];
    if reserve >= iv {
        let page_content = decrypt_by_reserve_size(first_page_content, scheduled_key, iv, reserve)?;
        if is_valid_decrypted_header(page_content.as_slice()) {
            let mut with_salt = Vec::with_capacity(salt + page_content.len());
            with_salt.extend_from_slice(&bytes[..salt]);
            with_salt.extend(page_content);
            if page == get_page_size_from_database_header(with_salt.as_slice())? && reserve == get_reserved_size_from_database_header(with_salt.as_slice()) {
                return Ok(reserve as isize)
            }
        }
    }
    for other_reserve in iv..page - 480 {
        let page_content = decrypt_by_reserve_size(first_page_content, scheduled_key, iv, other_reserve)?;
        if is_valid_decrypted_header(page_content.as_slice()) {
            let mut with_salt = Vec::with_capacity(salt + page_content.len());
            with_salt.extend_from_slice(&bytes[..salt]);
            with_salt.extend(page_content);
            if page == get_page_size_from_database_header(with_salt.as_slice())? && other_reserve == get_reserved_size_from_database_header(with_salt.as_slice()) {
                return Ok(other_reserve as isize)
            }
        }
    }
    Ok(-1)
}

fn decrypt_by_reserve_size(first_page_without_salt: &[u8], scheduled_key: &[u32], iv: usize, reserve: usize) -> Result<Vec<u8>> {
    let reserve = &first_page_without_salt[first_page_without_salt.len() - reserve..];
    let iv = &reserve[..iv];
    let mut decrypted_page_without_salt = vec![1u8; first_page_without_salt.len()];
    cbc_dec(first_page_without_salt, decrypted_page_without_salt.as_mut_slice(), scheduled_key, iv);
    Ok(decrypted_page_without_salt)
}