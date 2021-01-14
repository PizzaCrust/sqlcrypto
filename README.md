# SQLCrypto
[![Latest Version](https://img.shields.io/crates/v/sqlcrypto.svg)](https://crates.io/crates/sqlcrypto)
[![Rust Documentation](https://docs.rs/sqlcrypto/badge.svg)](https://docs.rs/sqlcrypto)

SQLCrypto is a pure Rust port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher), a utility to decrypt and encrypt SQLite databases.

## ⚠ DO NOT USE ️⚠️
It is currently broken.

## Performance
SQLCrypto, by default, does not parallelize. You can enable parallelization support through enabling the `parallel` feature flag, significantly boosting performance. Additionally, the aes dependency crate allows you to use aesni, if you change some rustc flags; which will boost performance significantly. 

With parallelization + aesni, a database that took an upward amount of 300+ seconds in decryption with pysqlsimplecipher; took <40 ms in decryption and <80 ms in encryption.

## Additional notes
Not fuzz safe!