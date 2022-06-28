use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Parse error: {source}")]
    ParseError {
        #[from]
        source: hex::FromHexError,
    },
    #[error("Key error: {source}")]
    KeyError {
        #[from]
        source: argon2::Error,
    },
    #[error("Fatal error")]
    Fatal,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        CryptoError::Fatal
    }
}
