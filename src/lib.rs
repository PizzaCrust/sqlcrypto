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
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[bench]
    fn decrypt_bench(b: &mut Bencher) {
        let test = std::fs::read("sqlcrypto.db").unwrap();
        b.iter(|| {
            super::decrypt(&mut test.clone(), b"test", 1024).unwrap()
        });
    }

    #[bench]
    fn encrypt_bench(b: &mut Bencher) {
        let test = std::fs::read("sqlcrypto_dec.db").unwrap();
        b.iter(|| {
            super::encrypt(&mut test.clone(), b"test").unwrap()
        })
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn comp_dec() {
        let mut test = include_bytes!("../sqlcrypto.db").to_vec();
        super::decrypt(&mut test[..], b"test", 1024).unwrap();
        assert!(&test[..] == include_bytes!("../sqlcrypto_dec.db"))
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn comp_enc() {
        let mut test = include_bytes!("../sqlcrypto_dec.db").to_vec();
        super::encrypt(&mut test[..], b"test").unwrap();
    }

}
