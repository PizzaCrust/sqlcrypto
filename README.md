# SQLCrypto
[![Latest Version](https://img.shields.io/crates/v/sqlcrypto.svg)](https://crates.io/crates/sqlcrypto)
[![Rust Documentation](https://docs.rs/sqlcrypto/badge.svg)](https://docs.rs/sqlcrypto)

SQLCrypto (0.2.0+) is a hardware accelerated port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust. It is 18x (0.2.1+) faster in decryption and 12.5x (0.2.1+) faster than it's pure Rust implementation.

## Performance
This library and especially this branch outperforms pysqlsimplecipher by in order of magnitudes, the Dokkan Battle database took up to 300+ seconds on my machine, down to <40 ms in decryption and less than <80 ms in encryption, and consumes significantly less memory. In my benchmarks with that database with regard to decryption with this library compared to SQLCipher [in decrypting Dokkan Battle's database], it is about 3x faster (0.2.1+). 
Other than that, I don't have benchmarks in place.

## WASM support
WASM is not supported on this branch! Please use the pure Rust implementation branch or versions lower than 0.2.0.

## Security
Please note that this is not production ready, and in its current state; this library has some compromises with regard to security.