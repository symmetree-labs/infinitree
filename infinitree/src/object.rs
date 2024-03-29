//! Tools for working directly with objects, without the indexing system.

use crate::{
    backends::BackendError,
    compress::{CompressError, DecompressError},
    BLOCK_SIZE,
};

use thiserror::Error;

use std::{io, sync::Arc};

mod pool;
pub use pool::{buffer::BlockBuffer, writer::WriterPool, Pool, PoolRef};

mod reader;
pub use reader::{AEADReader, Reader};

mod writer;
pub use writer::{AEADWriter, Writer};

mod bufferedstream;
pub use bufferedstream::*;

pub mod serializer;

pub type ObjectId = crate::Id;

#[derive(Error, Debug)]
pub enum ObjectError {
    #[error("IO error")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Backend error")]
    Backend {
        #[from]
        source: BackendError,
    },
    #[error("Compress failed")]
    Compress {
        #[from]
        source: CompressError,
    },
    #[error("Decompress failed")]
    Decompress {
        #[from]
        source: DecompressError,
    },
    #[error("Chunk too large to be written: {size}, max: {max_size}")]
    ChunkTooLarge { max_size: usize, size: usize },
    #[error("Buffer ({buf_size}) is smaller than required size: {min_size}")]
    BufferTooSmall { min_size: usize, buf_size: usize },
    #[error("Serialize failed")]
    Serialize {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Deserialize failed")]
    Deserialize {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Fatal internal error")]
    Fatal,
}

pub type Result<T> = std::result::Result<T, ObjectError>;

pub type WriteObject = Object<BlockBuffer>;
pub type ReadObject = Object<ReadBuffer>;

pub struct ReadBuffer(ReadBufferInner);
type ReadBufferInner = Arc<dyn AsRef<[u8]> + Send + Sync + 'static>;

impl<RO> From<RO> for Object<BlockBuffer>
where
    RO: AsRef<ReadObject>,
{
    fn from(rwr: RO) -> Object<BlockBuffer> {
        let rw = rwr.as_ref();

        Object::with_id(rw.id, rw.buffer.as_ref().to_vec().into_boxed_slice().into())
    }
}

impl<WO> From<WO> for ReadObject
where
    WO: AsRef<WriteObject>,
{
    fn from(rwr: WO) -> ReadObject {
        let rw = rwr.as_ref();

        Object::with_id(rw.id, ReadBuffer(Arc::new(rw.buffer.clone())))
    }
}

impl ReadBuffer {
    pub fn new(buf: impl AsRef<[u8]> + Send + Sync + 'static) -> ReadBuffer {
        ReadBuffer(Arc::new(buf))
    }

    pub fn with_inner(buf: Arc<dyn AsRef<[u8]> + Send + Sync + 'static>) -> ReadBuffer {
        ReadBuffer(buf)
    }
}

impl AsRef<[u8]> for ReadBuffer {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

pub struct Object<T> {
    id: ObjectId,
    buffer: T,
    cursor: usize,
}

impl<T> Object<T> {
    pub fn new(buffer: T) -> Self {
        Object {
            id: ObjectId::default(),
            cursor: 0,
            buffer,
        }
    }
}

impl<T> Object<T> {
    #[inline(always)]
    pub fn id(&self) -> &ObjectId {
        &self.id
    }

    #[inline(always)]
    pub fn set_id(&mut self, id: ObjectId) {
        self.id = id;
    }

    #[inline(always)]
    pub const fn capacity(&self) -> usize {
        BLOCK_SIZE
    }

    #[inline(always)]
    pub fn position(&self) -> usize {
        self.cursor
    }
}

impl<T> Object<T>
where
    T: AsRef<[u8]>,
{
    #[inline(always)]
    pub fn as_inner(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    #[inline(always)]
    pub fn head(&self, len: usize) -> &[u8] {
        &self.as_inner()[..len]
    }

    pub fn with_id(id: ObjectId, buffer: T) -> Object<T> {
        let mut object = Object {
            id: ObjectId::default(),
            cursor: 0,
            buffer,
        };
        object.set_id(id);
        object
    }
}

impl<T> Object<T>
where
    T: AsMut<[u8]>,
{
    #[inline(always)]
    pub fn as_inner_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.as_inner_mut().fill(0)
    }

    #[inline(always)]
    pub fn tail_mut(&mut self) -> &mut [u8] {
        let cursor = self.cursor;
        &mut self.as_inner_mut()[cursor..]
    }

    #[inline(always)]
    pub fn position_mut(&mut self) -> &mut usize {
        &mut self.cursor
    }

    #[inline(always)]
    pub fn head_mut(&mut self, len: usize) -> &mut [u8] {
        &mut self.as_inner_mut()[..len]
    }
}

impl io::Write for WriteObject {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ofs = self.cursor;
        let len = buf.len();

        let slice = self.as_inner_mut().get_mut(ofs..(ofs + len));

        match slice {
            Some(slice) => {
                slice.copy_from_slice(buf);
                self.cursor += len;
                Ok(len)
            }
            _ => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl io::Read for ReadObject {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let end = buf.len() + self.cursor;
        let inner = self.as_inner().get(self.cursor..end);

        match inner {
            Some(inner) => {
                buf.copy_from_slice(inner);
                self.cursor = end;
                Ok(buf.len())
            }
            _ => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
        }
    }
}

impl<T> io::Seek for Object<T> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        use io::SeekFrom::*;

        let umax = self.capacity() as u64;
        let imax = self.capacity() as i64;

        match pos {
            Start(s) => match s {
                s if s > umax => Err(io::Error::from(io::ErrorKind::InvalidInput)),
                s => {
                    self.cursor = s as usize;
                    Ok(self.cursor as u64)
                }
            },
            End(e) => match e {
                e if e < 0 => Err(io::Error::from(io::ErrorKind::InvalidInput)),
                e if e > imax => Err(io::Error::from(io::ErrorKind::InvalidInput)),
                e => {
                    self.cursor = self.capacity() - e as usize;
                    Ok(self.cursor as u64)
                }
            },
            Current(c) => {
                let new_pos = self.cursor as i64 + c;

                match new_pos {
                    p if p < 0 => Err(io::Error::from(io::ErrorKind::InvalidInput)),
                    p if p > imax => Err(io::Error::from(io::ErrorKind::InvalidInput)),
                    p => {
                        self.cursor = p as usize;
                        Ok(self.cursor as u64)
                    }
                }
            }
        }
    }
}

impl<T> Clone for Object<T>
where
    T: Clone,
{
    fn clone(&self) -> Object<T> {
        Object {
            id: self.id,
            buffer: self.buffer.clone(),
            cursor: self.cursor,
        }
    }
}

impl<T> Default for Object<T>
where
    T: Default + AsRef<[u8]>,
{
    fn default() -> Object<T> {
        let buffer = T::default();
        Object {
            id: ObjectId::default(),
            cursor: 0,
            buffer,
        }
    }
}

impl<T> AsRef<[u8]> for Object<T>
where
    T: AsRef<[u8]>,
{
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T> AsMut<[u8]> for Object<T>
where
    T: AsMut<[u8]>,
{
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<T> AsRef<Object<T>> for Object<T> {
    #[inline(always)]
    fn as_ref(&self) -> &Object<T> {
        self
    }
}

#[cfg(any(test, feature = "test"))]
pub mod test {
    use crate::{ChunkPointer, Digest};

    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    pub struct NullStorage(Arc<std::sync::Mutex<usize>>);

    impl Writer for NullStorage {
        fn write_chunk(&mut self, _hash: &Digest, data: &[u8]) -> Result<ChunkPointer> {
            *self.0.lock().unwrap() += data.len();
            Ok(ChunkPointer::default())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }

        fn write(&mut self, data: &[u8]) -> Result<ChunkPointer> {
            self.write_chunk(&Digest::default(), data)
        }
    }
}
