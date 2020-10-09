# SQLCrypto
SQLCrypto is a pure Rust port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust

## Performance
This library outperforms pysqlsimplecipher by in order of magnitudes, the Dokkan Battle database took up to 300+ seconds on my machine, down to <700 ms in decryption and less than <1000 ms in encryption, and consumes significantly less memory.
Other than that, I don't have benchmarks in place.

## WASM support
WASM is supported however, hmac verification is disabled. Additionally, WASM bind gen is not enabled! This means you have to use your own rust crate to interact with this crate to access it with WASM.

## Security
Please note that this is not production ready, and in its current state; this library has some compromises with regard to security.