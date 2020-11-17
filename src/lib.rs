//! SQLCrypto is a port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher), which is a utility to decrypt and encrypt SQLite databases.
#![deny(missing_docs)]
#![feature(test)]
mod decrypt;
mod error;
mod encrypt;

pub use error::*;
pub use decrypt::*;
pub use encrypt::*;
use aes::Aes256;
use block_modes::block_padding::NoPadding;
use block_modes::Cbc;
use sha1::Sha1;

pub(crate) type Aes = Cbc<Aes256, NoPadding>;
pub(crate) type Hmac = hmac::Hmac<Sha1>;

pub(crate) fn key_derive(key: &[u8], salt: &[u8], hmac: bool) -> ([u8; 32], [u8; 32]) {
    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac>(key, salt, 64000, &mut derived_key);
    let mut hmac_salt = [0u8; 16];
    salt.iter().zip(hmac_salt.iter_mut()).for_each(|(byte, slot)| {
        *slot = byte ^ 0x3a;
    });
    let mut hmac_key = [0u8; 32];
    if hmac {
        pbkdf2::pbkdf2::<Hmac>(&derived_key, &hmac_salt, 2, &mut hmac_key);
    }
    (derived_key, hmac_key)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;
    use wasm_bindgen_test::*;

    #[bench]
    fn decrypt(b: &mut Bencher) {
        let test = std::fs::read("decrypted-sqlcrypto.db").unwrap(); // 100 ms
        b.iter(|| {
            super::decrypt(&mut test.clone(), b"test", 1024).unwrap()
        });
    }

    #[bench]
    fn encrypt(b: &mut Bencher) {
        let test = std::fs::read("bomb-dec.db").unwrap();
        b.iter(|| {
            super::encrypt(&mut test.clone(), b"test", &[1; 16], &[1; 16]).unwrap()
        })
    }

    #[wasm_bindgen_test]
    fn wasm_comp_dec() {
        let mut test = include_bytes!("../decrypted-sqlcrypto.db").to_vec();
        super::decrypt(&mut test[..], b"test", 1024).unwrap();
        assert_eq!(&test[..], include_bytes!("../bomb-dec.db"))
    }

    #[wasm_bindgen_test]
    fn wasm_comp_enc() {
        let mut test = include_bytes!("../bomb-dec.db").to_vec();
        super::encrypt(&mut test[..], b"test", &[1; 16], &[1; 16]).unwrap();
        assert_eq!(&test[..], include_bytes!("../decrypted-sqlcrypto.db"))
    }

}
