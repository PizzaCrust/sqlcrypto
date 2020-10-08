//! SQLCrypto is a port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust, which is a utility to decrypt and encrypt SQLite databases.
#![deny(missing_docs)]
#![feature(test)]
mod decrypt;
mod error;
mod encrypt;

pub use error::*;
pub use decrypt::*;
pub use encrypt::*;
use block_modes::Cbc;
use aesni::Aes256;
use block_modes::block_padding::NoPadding;

pub(crate) type Aes = Cbc<Aes256, NoPadding>;

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;

    #[bench]
    fn decrypt(b: &mut Bencher) {
        let test = std::fs::read("decrypted-sqlcrypto.db").unwrap(); // 100 ms
        b.iter(|| {
            super::decrypt(test.as_slice(), b"test", &mut Vec::with_capacity(test.len())).unwrap()
        });
    }

}
