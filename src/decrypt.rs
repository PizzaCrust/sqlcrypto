use crate::*;
use std::io::{Write};
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::pbkdf2::pbkdf2;
use crypto::aes::cbc_decryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use std::convert::TryInto;
use crypto::mac::{Mac, MacResult};

pub(crate) fn key_derive(salt: &[u8], key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut mac = Hmac::new(Sha1::new(), key);
    let mut key = vec![0u8; 32];
    pbkdf2(&mut mac, &salt[..], 64000, &mut key[..]);
    let hmac_salt: Vec<u8> = salt.iter().map(|x| x ^ (0x3a)).collect();
    let mut hmac_key = vec![0u8; 32];
    pbkdf2(&mut Hmac::new(Sha1::new(), &key[..]), hmac_salt.as_slice(), 2, &mut hmac_key[..]);
    (key, hmac_key)
}

pub(crate) fn generate_hmac(hmac_key: &[u8], mut content: Vec<u8>, page_num: usize) -> Result<MacResult> {
    let mut hmac = Hmac::new(Sha1::new(), hmac_key);
    content.write(&((page_num + 1) as i32).to_le_bytes())?;
    hmac.input(content.as_slice());
    Ok(hmac.result())
}

pub fn decrypt<R: AsRef<[u8]>, W: Write>(data: R, key: &[u8], output: &mut W) -> Result<()> {
    let bytes = data.as_ref();
    output.write(b"SQLite format 3\0")?; // lol
    let salt = &bytes[..16];
    let (key, hmac_key) = key_derive(salt, key);
    let mut page: usize = 1024;
    let mut reserve: usize = 48;
    reserve = decrypt_page_header(bytes, key.as_slice(), 16, &mut page, 16, reserve)?;
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
        if hmac_old != generate_hmac(&hmac_key[..], hmac_data, i)?.code() {
            return Err(Error::Message("hmac check failed in page"))
        }
        let mut page_decrypted = vec![1u8; page_content.len() + reserve.len()];
        cbc_decryptor(KeySize256, &key[..], iv, NoPadding)
            .decrypt(&mut RefReadBuffer::new(page_content),
                     &mut RefWriteBuffer::new(page_decrypted.as_mut_slice()),
                     true)?; //fml btw
        output.write(&page_decrypted[..])?;
    }
    Ok(())
}

#[inline]
pub(crate) fn is_valid_page_size(page: usize) -> bool {
    page >= 512 && page == 2i32.pow((page as f32).log(2f32).floor() as u32) as usize
}

fn decrypt_page_header(bytes: &[u8], key: &[u8], salt: usize, page: &mut usize, iv: usize, reserve: usize) -> Result<usize> {
    if !(is_valid_page_size(*page)) {
        *page = 512;
    }
    let new_reserve = try_get_reserve_size_for_specified_page_size(bytes, key, salt, *page, iv, reserve)?;
    if new_reserve > 0 {
        return Ok(new_reserve as usize)
    }
    *page = 512;
    while *page <= 65536 {
        let new_reserve = try_get_reserve_size_for_specified_page_size(bytes, key, salt, *page, iv, reserve)?;
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

fn try_get_reserve_size_for_specified_page_size(bytes: &[u8], key: &[u8], salt: usize, page: usize, iv: usize, reserve: usize) -> Result<isize> {
    let first_page_content = &get_page(bytes, page, 1)[salt..];
    if reserve >= iv {
        let page_content = decrypt_by_reserve_size(first_page_content, key, iv, reserve)?;
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
        let page_content = decrypt_by_reserve_size(first_page_content, key, iv, other_reserve)?;
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

fn decrypt_by_reserve_size(first_page_without_salt: &[u8], key: &[u8], iv: usize, reserve: usize) -> Result<Vec<u8>> {
    let reserve = &first_page_without_salt[first_page_without_salt.len() - reserve..];
    let iv = &reserve[..iv];
    let mut decrypted_page_without_salt = vec![1u8; first_page_without_salt.len()];
    cbc_decryptor(KeySize256, key, iv, NoPadding)
        .decrypt(&mut RefReadBuffer::new(first_page_without_salt),
                 &mut RefWriteBuffer::new(decrypted_page_without_salt.as_mut_slice()),
                 false)?;
    Ok(decrypted_page_without_salt)
}