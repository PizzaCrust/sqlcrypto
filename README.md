# SQLCrypto
SQLCrypto is a port of [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher) for Rust, which is a utility to decrypt and encrypt SQLite databases. SQLCipher is still a tad faster, but if you want a pure Rust implementation; here ya go.

## Performance
This library outperforms pysqlsimplecipher by in order of magnitudes, the Dokkan Battle database took up to 300+ seconds on my machine, down to <700 ms in decryption and less than <100 ms in encryption, and consumes significantly less memory.
Other than that, I don't have benchmarks in place.

## Security
Please note that this is not production ready, and in its current state; this library has some compromises with regard to security.