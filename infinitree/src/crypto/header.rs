use super::KeySource;
use crate::chunks::RawChunkPointer;
use std::ops::{Deref, DerefMut};

pub const HEADER_SIZE: usize = 512;

#[derive(Clone)]
pub struct CleartextHeader {
    pub(crate) root_ptr: RawChunkPointer,
    pub(crate) key: KeySource,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SealedHeader(pub(crate) [u8; HEADER_SIZE]);

impl From<[u8; HEADER_SIZE]> for SealedHeader {
    fn from(buf: [u8; HEADER_SIZE]) -> Self {
        Self(buf)
    }
}

impl DerefMut for SealedHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for SealedHeader {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for SealedHeader {
    fn default() -> Self {
        Self([0; std::mem::size_of::<Self>()])
    }
}

impl AsRef<[u8]> for SealedHeader {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SealedHeader {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
