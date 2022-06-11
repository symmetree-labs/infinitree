use super::{ObjectError, ObjectId, Result, WriteObject};
use crate::{
    backends::Backend,
    compress,
    crypto::{ChunkKey, CryptoProvider, Digest, Random, RootKey},
    ChunkPointer,
};
use std::{
    io::{Seek, SeekFrom},
    sync::Arc,
};

#[derive(Clone)]
enum Mode {
    SealRoot(u64),
    Data,
}

impl Mode {
    fn skip(&self) -> u64 {
        match self {
            Self::SealRoot(skip) => *skip,
            Self::Data => 0,
        }
    }
}

pub trait Writer: Send {
    fn write(&mut self, data: &[u8]) -> Result<ChunkPointer>;
    fn write_chunk(&mut self, hash: &Digest, data: &[u8]) -> Result<ChunkPointer>;
    fn flush(&mut self) -> Result<()>;
}

pub struct AEADWriter {
    backend: Arc<dyn Backend>,
    crypto: ChunkKey,
    object: WriteObject,
    mode: Mode,
    rewrite: Vec<ObjectId>,
}

impl AEADWriter {
    pub fn new(backend: Arc<dyn Backend>, crypto: ChunkKey) -> Self {
        let mut object = WriteObject::default();
        object.reset_id(&crypto);

        AEADWriter {
            backend,
            crypto,
            object,
            mode: Mode::Data,
            rewrite: vec![],
        }
    }

    pub fn for_root(
        backend: Arc<dyn Backend>,
        crypto: RootKey,
        header_size: u64,
        mut rewrite: Vec<ObjectId>,
    ) -> Self {
        let mut object = WriteObject::default();
        object.seek(SeekFrom::Start(header_size)).unwrap();

        reset_id(&mut object, &crypto, &mut rewrite);

        AEADWriter {
            backend,
            crypto,
            object,
            rewrite,
            mode: Mode::SealRoot(header_size),
        }
    }

    pub(crate) fn flush_root_head(&mut self, id: ObjectId, head: &[u8]) -> Result<()> {
        self.object.set_id(id);
        self.object.write_head(head);
        self.object.finalize(&self.crypto);
        self.backend.write_object(&self.object)?;

        self.rewrite.clear();
        self.object.reset_id(&self.crypto);
        self.object.seek(SeekFrom::Start(self.mode.skip()))?;

        Ok(())
    }
}

impl Clone for AEADWriter {
    fn clone(&self) -> Self {
        let mut object = self.object.clone();
        object.reset_id(&self.crypto);

        AEADWriter {
            object,
            backend: self.backend.clone(),
            crypto: self.crypto.clone(),
            mode: self.mode.clone(),
            rewrite: vec![],
        }
    }
}

impl Drop for AEADWriter {
    fn drop(&mut self) {
        if self.object.position() > self.mode.skip() as usize {
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
        let mut pointer = {
            let buffer = self.object.tail_mut();

            self.crypto.encrypt_chunk(
                match self.mode {
                    Mode::Data => Some(oid),
                    Mode::SealRoot(_) => None,
                },
                hash,
                &mut buffer[..size],
            )
        };

        pointer.file = oid;
        pointer.offs = self.object.position() as u32;
        *self.object.position_mut() += pointer.size as usize;

        Ok(pointer.into())
    }

    fn flush(&mut self) -> Result<()> {
        if let Mode::SealRoot(header_size) = self.mode {
            self.object
                .randomize_head(&self.crypto, header_size.try_into().unwrap());
        }
        self.object.finalize(&self.crypto);
        self.backend.write_object(&self.object)?;

        reset_id(&mut self.object, &self.crypto, &mut self.rewrite);

        self.object.seek(SeekFrom::Start(self.mode.skip()))?;

        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<ChunkPointer> {
        self.write_chunk(&self.crypto.hash(data), data)
    }
}

#[inline(always)]
fn reset_id(object: &mut WriteObject, random: &impl Random, rewrite: &mut Vec<ObjectId>) {
    object.set_id(rewrite.pop().unwrap_or_else(|| ObjectId::new(random)));
}
