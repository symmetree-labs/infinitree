use super::Key;
use crate::chunks::RawChunkPointer;
use std::ops::{Deref, DerefMut};

pub const HEADER_SIZE: usize = 512;

macro_rules! header_size_struct {
    ($name:tt) => {
        #[derive(PartialEq, Eq, Debug, Clone)]
        pub struct $name(pub(super) [u8; HEADER_SIZE]);

        impl From<[u8; HEADER_SIZE]> for $name {
            fn from(buf: [u8; HEADER_SIZE]) -> Self {
                Self(buf)
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self([0; std::mem::size_of::<Self>()])
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }
    };
}

#[derive(Clone)]
pub struct Header {
    pub(crate) root_ptr: RawChunkPointer,
    pub(crate) key: Key,
}

header_size_struct!(SealedHeader);
header_size_struct!(OpenHeader);
