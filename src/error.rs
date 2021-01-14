use thiserror::Error;

/// Crate's result
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    Io(#[from] std::io::Error),
    Iv(#[from] block_modes::InvalidKeyIvLength),
    BlockMode(#[from] block_modes::BlockModeError),
    KeyLength(#[from] hmac::crypto_mac::InvalidKeyLength),
    Random(#[from] getrandom::Error),
    #[error("invalid database header")]
    Header,
    #[error("invalid page size")]
    PageSize,
    #[error("expected reserve, found no reserve")]
    Reserve
}
