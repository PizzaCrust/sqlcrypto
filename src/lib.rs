//! SQLCrypto is a port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust, which is a utility to decrypt and encrypt SQLite databases.
#![deny(missing_docs)]
#![feature(test)]
mod decrypt;
mod error;
mod encrypt;

pub use error::*;
pub use decrypt::*;
pub use encrypt::*;

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;
    use wasm_bindgen_test::*;

    #[bench]
    fn decrypt(b: &mut Bencher) {
        let test = std::fs::read("test.db").unwrap(); // 100 ms
        b.iter(|| {
            super::decrypt(test.as_slice(), b"test", &mut Vec::with_capacity(test.len())).unwrap()
        });
    }

    #[wasm_bindgen_test]
    fn wasm_comp_dec() {
        let test: &[u8] = include_bytes!("../test.db");
        let mut output = Vec::with_capacity(test.len());
        super::decrypt(test, b"test", &mut output).unwrap();
        assert_eq!(output, include_bytes!("../test-dec.db"))
    }

    #[wasm_bindgen_test]
    fn wasm_comp_enc() {
        let test: &[u8] = include_bytes!("../test-dec.db");
        let mut output = Vec::with_capacity(test.len());
        super::encrypt(test, b"test", &mut output).unwrap();
        assert_eq!(output, include_bytes!("../test-enc.db"))
    }

}
