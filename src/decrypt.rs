use crate::*;
use block_modes::BlockMode;

#[inline]
fn decrypt_page((index, mut page): (usize, &mut [u8]), key: &[u8]) -> Result<()> {
    if index == 0 {
        page = &mut page[16..];
    }
    let page_len = page.len();
    let reserve_bytes = &page[page_len - 48..];
    let iv = &reserve_bytes[..16];
    let aes = Aes::new_var(&key, iv)?;
    let page_content = &mut page[..page_len - 48];
    aes.decrypt(page_content)?;
    Ok(())
}

#[inline]
fn decrypt_pages(data: &mut [u8], key: &[u8], page: usize) -> Result<()> {
    data.chunks_exact_mut(page)
        .enumerate()
        .try_for_each::<_, Result<()>>(|x| {
            decrypt_page(x, key)
        })?;
    Ok(())
}

/// Decrypts an encrypted SQLite database in place.
/// Note: most encrypted databases have the default page size of 1024
pub fn decrypt(data: &mut [u8], key: &[u8], page: usize) -> Result<()> {
    let salt = &data[..16];
    let (key, _) = key_derive(key, salt, false);
    b"SQLite format 3\0".iter().zip(data.iter_mut()).for_each(|(byte, slot)| {
        *slot = *byte;
    });
    decrypt_pages(data, &key, page)?;
    Ok(())
}