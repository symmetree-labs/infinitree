use super::{BlockBuffer, Result};
use crate::{
    backends::Backend,
    compress,
    crypto::{ChunkKey, CryptoProvider, RootKey},
    ChunkPointer, ObjectId,
};

use std::sync::Arc;

type GetObjectId = Box<dyn Fn(&ChunkPointer) -> ObjectId + Send + Sync>;
fn default_object_getter() -> GetObjectId {
    Box::new(|cp| *cp.object_id())
}

#[derive(Clone)]
enum Mode {
    SealRoot,
    Data,
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
    crypto: ChunkKey,
    buffer: BlockBuffer,
    mode: Mode,
    get_object_id: GetObjectId,
}

impl AEADReader {
    pub fn new(backend: Arc<dyn Backend>, crypto: ChunkKey) -> Self {
        AEADReader {
            backend,
            crypto,
            buffer: BlockBuffer::default(),
            mode: Mode::Data,
            get_object_id: default_object_getter(),
        }
    }

    pub(crate) fn for_root(backend: Arc<dyn Backend>, crypto: RootKey) -> Self {
        AEADReader {
            backend,
            crypto,
            buffer: BlockBuffer::default(),
            mode: Mode::SealRoot,
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
        let buf = self.crypto.decrypt_chunk(
            cryptbuf,
            source,
            match self.mode {
                Mode::Data => Some(*pointer.object_id()),
                Mode::SealRoot => None,
            },
            pointer.as_raw(),
        );
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
