use super::{BlockBuffer, Result};
use crate::{
    backends::Backend,
    compress,
    crypto::{ChunkKey, CryptoOps, IndexKey, StorageKey},
    ChunkPointer, ObjectId,
};

use std::sync::Arc;

type GetObjectId = Box<dyn Fn(&ChunkPointer) -> ObjectId + Send + Sync>;
fn default_object_getter() -> GetObjectId {
    Box::new(|cp| *cp.object_id())
}

pub trait Reader: Send {
    fn read_chunk<'target>(
        &mut self,
        pointer: &ChunkPointer,
        target: &'target mut [u8],
    ) -> Result<&'target [u8]>;
}

pub struct AEADReader {
    backend: Arc<dyn Backend>,
    crypto: CryptoOps,
    buffer: BlockBuffer,
    get_object_id: GetObjectId,
}

impl AEADReader {
    pub fn new(backend: Arc<dyn Backend>, crypto: ChunkKey) -> Self {
        AEADReader {
            backend,
            crypto: crypto.into_inner(),
            buffer: BlockBuffer::default(),
            get_object_id: default_object_getter(),
        }
    }

    pub(crate) fn for_storage(backend: Arc<dyn Backend>, crypto: StorageKey) -> Self {
        AEADReader {
            backend,
            crypto: crypto.into_inner(),
            buffer: BlockBuffer::default(),
            get_object_id: default_object_getter(),
        }
    }

    pub(crate) fn for_root(backend: Arc<dyn Backend>, crypto: IndexKey) -> Self {
        AEADReader {
            backend,
            crypto: crypto.into_inner(),
            buffer: BlockBuffer::default(),
            get_object_id: default_object_getter(),
        }
    }

    pub(crate) fn override_root_id(&mut self, from: ObjectId, to: ObjectId) {
        self.get_object_id = Box::new(move |cp| {
            let oid = cp.object_id();

            if oid == &from {
                to
            } else {
                *oid
            }
        })
    }

    pub(crate) fn decrypt_decompress<'target>(
        &mut self,
        target: &'target mut [u8],
        source: &[u8],
        pointer: &ChunkPointer,
    ) -> Result<&'target [u8]> {
        let cryptbuf: &mut [u8] = self.buffer.as_mut();
        let buf = self.crypto.decrypt_chunk(cryptbuf, source, pointer);
        let size = compress::decompress_into(buf, target)?;

        Ok(&target[..size])
    }
}

impl AsMut<Self> for AEADReader {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl Reader for AEADReader {
    fn read_chunk<'target>(
        &mut self,
        pointer: &ChunkPointer,
        target: &'target mut [u8],
    ) -> Result<&'target [u8]> {
        let object = self.backend.read_object(&(self.get_object_id)(pointer))?;

        self.decrypt_decompress(target, object.as_inner(), pointer)
    }
}
