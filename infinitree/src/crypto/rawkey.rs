use super::CryptoError;
use secrecy::{ExposeSecret, Secret};
use std::{str::FromStr, sync::Arc};

pub const KEY_SIZE: usize = 32;

/// A cryptographic key
#[derive(Clone)]
pub struct RawKey(Arc<Secret<[u8; KEY_SIZE]>>);

impl RawKey {
    pub(crate) fn new(k: [u8; KEY_SIZE]) -> Self {
        Self(Secret::new(k).into())
    }
}

impl FromStr for RawKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = [0u8; KEY_SIZE];
        hex::decode_to_slice(s, &mut buf)?;

        Ok(buf.into())
    }
}

impl ToString for RawKey {
    #[inline(always)]
    fn to_string(&self) -> String {
        hex::encode(self.0.expose_secret())
    }
}

impl ExposeSecret<[u8; KEY_SIZE]> for RawKey {
    fn expose_secret(&self) -> &[u8; KEY_SIZE] {
        self.0.expose_secret()
    }
}

impl From<[u8; KEY_SIZE]> for RawKey {
    fn from(k: [u8; KEY_SIZE]) -> Self {
        Self(Arc::new(k.into()))
    }
}
