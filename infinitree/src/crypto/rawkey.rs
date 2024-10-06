use super::CryptoError;
use secrecy::ExposeSecret;
use std::{str::FromStr, sync::Arc};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(super) const KEY_SIZE: usize = 32;

/// A raw cryptographic key
#[derive(Zeroize, ZeroizeOnDrop)]
struct RawKeyInner([u8; KEY_SIZE]);

impl AsRef<[u8; KEY_SIZE]> for RawKeyInner {
    fn as_ref(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

#[derive(Clone)]
pub struct RawKey(Arc<RawKeyInner>);

impl RawKey {
    pub(crate) fn new(k: [u8; KEY_SIZE]) -> Self {
        Self(RawKeyInner(k).into())
    }

    pub(crate) fn write_to(&self, output: &mut [u8]) -> usize {
        output[..KEY_SIZE].copy_from_slice(self.expose_secret());
        KEY_SIZE
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
        hex::encode(self.expose_secret())
    }
}

impl ExposeSecret<[u8; KEY_SIZE]> for RawKey {
    fn expose_secret(&self) -> &[u8; KEY_SIZE] {
        self.0.as_ref().as_ref()
    }
}

impl From<[u8; KEY_SIZE]> for RawKey {
    fn from(k: [u8; KEY_SIZE]) -> Self {
        RawKey::new(k)
    }
}

impl From<&[u8]> for RawKey {
    fn from(k: &[u8]) -> Self {
        assert!(k.len() >= KEY_SIZE);
        let mut buf = [0; KEY_SIZE];
        buf.copy_from_slice(&k[..KEY_SIZE]);
        RawKey::new(buf)
    }
}
