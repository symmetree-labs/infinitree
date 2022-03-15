use super::{ObjectError, ObjectId, Result, WriteObject};
use crate::{
    backends::Backend,
    compress,
    crypto::{ChunkKey, CryptoProvider, Digest},
    ChunkPointer,
};
use std::sync::Arc;

pub trait Writer: Send {
    fn write_chunk(&mut self, hash: &Digest, data: &[u8]) -> Result<ChunkPointer>;
    fn flush(&mut self) -> Result<()>;
}

pub struct AEADWriter {
    backend: Arc<dyn Backend>,
    crypto: ChunkKey,
    object: WriteObject,
}

impl AEADWriter {
    pub fn new(backend: Arc<dyn Backend>, crypto: ChunkKey) -> Self {
        let mut object = WriteObject::default();
        object.reset_id(&crypto);

        AEADWriter {
            backend,
            crypto,
            object,
        }
    }
}

impl Clone for AEADWriter {
    fn clone(&self) -> Self {
        let mut object = self.object.clone();
        object.set_id(ObjectId::new(&self.crypto));

        AEADWriter {
            object,
            backend: self.backend.clone(),
            crypto: self.crypto.clone(),
        }
    }
}

impl Drop for AEADWriter {
    fn drop(&mut self) {
        if self.object.position() > 0 {
            self.flush().unwrap();
        }
    }
}

impl Writer for AEADWriter {
    fn write_chunk(&mut self, hash: &Digest, data: &[u8]) -> Result<ChunkPointer> {
        let size = {
            let buffer = self.object.tail_mut();

            match compress::compress_into(data, buffer) {
                Ok(size) => size,
                Err(_e) => {
                    self.flush()?;

                    let buffer = self.object.tail_mut();
                    compress::compress_into(data, buffer).map_err(|_| {
                        ObjectError::ChunkTooLarge {
                            size: data.len(),
                            max_size: ((self.object.capacity() - 16 - 4) as f64 / 1.1) as usize,
                        }
                    })?
                }
            }
        };

        let oid = *self.object.id();
        let (size, tag) = {
            let buffer = self.object.tail_mut();
            let tag = self.crypto.encrypt_chunk(&oid, hash, &mut buffer[..size]);

            (size, tag)
        };

        let offs = self.object.position();
        *self.object.position_mut() += size;

        Ok(ChunkPointer::new(offs as u32, size as u32, oid, *hash, tag))
    }

    fn flush(&mut self) -> Result<()> {
        self.object.finalize(&self.crypto);
        self.backend.write_object(&self.object)?;

        self.object.reset_id(&self.crypto);
        self.object.reset_cursor();

        Ok(())
    }
}
