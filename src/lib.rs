#![feature(test)]
mod decrypt;
mod error;

pub use error::*;
pub use decrypt::*;

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;

    #[bench]
    fn decrypt(b: &mut Bencher) {
        let test = std::fs::read("test.db").unwrap(); // 100 ms
        b.iter(|| {
            super::decrypt(test.as_slice(), b"test", &mut Vec::with_capacity(test.len()))
        });
    }

}
