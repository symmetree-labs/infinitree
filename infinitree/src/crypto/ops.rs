use crate::{ChunkPointer, Digest, ObjectId};
use blake3::Hasher;
use std::sync::Arc;

/// A derived key that's directly usable to execute encypt/decrypt operations.
pub(crate) type CryptoOps = Arc<dyn ICryptoOps>;

/// Low level encrypt/decrypt operations using a derivative key.
pub(crate) trait ICryptoOps: Send + Sync {
    fn encrypt_chunk(
        &self,
        object_id: ObjectId,
        offs: u32,
        hash: &Digest,
        data: &mut [u8],
    ) -> ChunkPointer;

    fn decrypt_chunk<'buf>(
        &self,
        target: &'buf mut [u8],
        source: &[u8],
        chunk: &ChunkPointer,
    ) -> &'buf mut [u8];

    /// Provide a hash (or HMAC) of `data`
    fn hash(&self, data: &[u8]) -> Digest;

    /// Return a freely usable and cloneable Hasher. May be keyed.
    fn hasher(&self) -> Hasher;
}

macro_rules! key_type {
    ($name:ident) => {
        #[derive(Clone)]
        pub struct $name(pub(crate) CryptoOps);

        impl $name {
            #[allow(unused)]
            pub(crate) fn new(ops: impl ICryptoOps + 'static) -> Self {
                Self(Arc::new(ops))
            }

            #[allow(unused)]
            pub(crate) fn into_inner(self) -> CryptoOps {
                self.0
            }
        }

        impl ICryptoOps for $name {
            fn encrypt_chunk(
                &self,
                object_id: ObjectId,
                offs: u32,
                hash: &Digest,
                data: &mut [u8],
            ) -> ChunkPointer {
                self.0.encrypt_chunk(object_id, offs, hash, data)
            }

            fn decrypt_chunk<'buf>(
                &self,
                target: &'buf mut [u8],
                source: &[u8],
                chunk: &ChunkPointer,
            ) -> &'buf mut [u8] {
                self.0.decrypt_chunk(target, source, chunk)
            }

            fn hash(&self, data: &[u8]) -> Digest {
                self.0.hash(data)
            }

            fn hasher(&self) -> Hasher {
                self.0.hasher()
            }
        }
    };
}

pub(crate) use private::*;
mod private {
    use super::*;

    key_type!(IndexKey);
    key_type!(ChunkKey);
    key_type!(StorageKey);
}
