use super::{ObjectError, ObjectId, Result, WriteObject};
use crate::{
    backends::Backend,
    compress,
    crypto::{ChunkKey, CryptoOps, Digest, IndexKey},
    ChunkPointer,
};
use ring::rand::{SecureRandom, SystemRandom};
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
    random: SystemRandom,
    crypto: CryptoOps,
    object: WriteObject,
    mode: Mode,
    rewrite: Vec<ObjectId>,
}

impl AEADWriter {
    pub fn new(backend: Arc<dyn Backend>, crypto: ChunkKey) -> Self {
        let mut object = WriteObject::default();
        let random = SystemRandom::new();
        reset_id(&mut object, &random);

        AEADWriter {
            backend,
            object,
            random,
            crypto: crypto.unwrap(),
            mode: Mode::Data,
            rewrite: vec![],
        }
    }

    pub fn for_root(
        backend: Arc<dyn Backend>,
        crypto: IndexKey,
        header_size: u64,
        mut rewrite: Vec<ObjectId>,
    ) -> Self {
        let random = SystemRandom::new();
        let mut object = WriteObject::default();
        object.seek(SeekFrom::Start(header_size)).unwrap();

        rewrite_or_reset_id(&mut object, &random, &mut rewrite);

        AEADWriter {
            backend,
            object,
            rewrite,
            random,
            crypto: crypto.unwrap(),
            mode: Mode::SealRoot(header_size),
        }
    }

    pub(crate) fn flush_root_head(&mut self, id: ObjectId, head: &[u8]) -> Result<()> {
        self.object.set_id(id);
        self.write_head(head);
        self.finalize()?;
        self.backend.write_object(&self.object)?;

        self.rewrite.clear();
        reset_id(&mut self.object, &self.random);
        self.object.seek(SeekFrom::Start(self.mode.skip()))?;

        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        self.random
            .fill(self.object.tail_mut())
            .map_err(|_| ObjectError::Fatal)?;
        Ok(())
    }

    fn write_head(&mut self, content: &[u8]) {
        self.object.head_mut(content.len()).copy_from_slice(content);
    }
}

impl Clone for AEADWriter {
    fn clone(&self) -> Self {
        let mut object = self.object.clone();
        reset_id(&mut object, &self.random);

        AEADWriter {
            object,
            random: self.random.clone(),
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
        let pointer = {
            let offs = self.object.position() as u32;
            let buffer = self.object.tail_mut();

            self.crypto
                .encrypt_chunk(oid, offs, hash, &mut buffer[..size])
        };

        *self.object.position_mut() += pointer.size();

        Ok(pointer)
    }

    fn flush(&mut self) -> Result<()> {
        if let Mode::SealRoot(header_size) = self.mode {
            self.random
                .fill(self.object.head_mut(header_size.try_into().unwrap()))
                .map_err(|_| ObjectError::Fatal)?;
        }
        self.finalize()?;
        self.backend.write_object(&self.object)?;

        rewrite_or_reset_id(&mut self.object, &self.random, &mut self.rewrite);

        self.object.seek(SeekFrom::Start(self.mode.skip()))?;

        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<ChunkPointer> {
        self.write_chunk(&self.crypto.hash(data), data)
    }
}

#[inline(always)]
fn rewrite_or_reset_id(
    object: &mut WriteObject,
    random: &impl SecureRandom,
    rewrite: &mut Vec<ObjectId>,
) {
    object.set_id(rewrite.pop().unwrap_or_else(|| ObjectId::new(random)));
}

#[inline(always)]
fn reset_id(object: &mut WriteObject, random: &impl SecureRandom) {
    object.set_id(ObjectId::new(random));
}
