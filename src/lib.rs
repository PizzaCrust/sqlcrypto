//! SQLCrypto is a port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust, which is a utility to decrypt and encrypt SQLite databases.
#![deny(missing_docs)]
#![feature(test)]
mod decrypt;
mod encrypt;
mod error;

use aesni::Aes256;
use block_modes::block_padding::NoPadding;
use block_modes::Cbc;
pub use decrypt::*;
pub use encrypt::*;
pub use error::*;
use sha1::Sha1;

pub(crate) type Aes = Cbc<Aes256, NoPadding>;
pub(crate) type Hmac = hmac::Hmac<Sha1>;

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;

    #[bench]
    fn decrypt(b: &mut Bencher) {
        let test = std::fs::read("decrypted-sqlcrypto.db").unwrap(); // 100 ms
        b.iter(|| super::decrypt(&mut test.clone(), b"test").unwrap());
    }
}
