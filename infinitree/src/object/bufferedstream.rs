use super::{AEADReader, BlockBuffer, PoolRef, Reader, Writer};
use crate::{chunks::ChunkPointer, ObjectId};
use std::io::{self, Read, Write};

/// Smaller chunks will lower the storage overhead, achieving lowerhead.
/// This seems like a sensible tradeoff, but may change in the future.
const CHUNK_SIZE: usize = 500 * 1024;

/// A descriptor that contains necessary data to deserialize a stream.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Stream(Vec<ChunkPointer>);
pub type DeserializeStream =
    crate::Deserializer<rmp_serde::decode::ReadReader<BufferedStream<PoolRef<AEADReader>>>>;

impl Stream {
    /// Open a reader that implements [`std::io::Read`].
    ///
    /// Note that you can't [`std::io::Seek`] in this stream at this
    /// point efficiently. If that is your use case, I recommend
    /// implementing another layer of indirection, and storing
    /// `Stream` e.g. in a [`VersionedMap<K,
    /// Stream>`][crate::fields::VersionedMap]
    pub fn open_reader<R: Reader, M: AsMut<R>>(&self, reader: M) -> BufferedStream<M> {
        self.open_with_buffer(reader, BlockBuffer::default())
    }

    /// Open a reader that implements [`std::io::Read`] with buffer.
    ///
    /// See [`Stream::open_reader`] for details
    pub fn open_with_buffer<R: Reader, M: AsMut<R>>(
        &self,
        reader: M,
        buffer: BlockBuffer,
    ) -> BufferedStream<M> {
        BufferedStream {
            reader,
            chunks: self.0.iter().rev().cloned().collect(),
            pos: None,
            len: None,
            buffer,
        }
    }

    /// Returns true if the stream has data in it.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// List of objects that the Stream spans.
    ///
    /// Note these may not _exclusively_ contain this particular
    /// stream, or even just streams.
    pub fn objects(&self) -> Vec<ObjectId> {
        let mut objects = self
            .0
            .iter()
            .map(|p| *p.object_id())
            .collect::<std::collections::HashSet<_>>();

        objects.drain().collect()
    }
}

impl From<Vec<ChunkPointer>> for Stream {
    fn from(ptrs: Vec<ChunkPointer>) -> Self {
        Self(ptrs)
    }
}

/// Reader for an infinite stream spanning arbitrary number of objects.
///
/// For more details about internals, look at [`BufferedSink`].
pub struct BufferedStream<Reader = AEADReader> {
    reader: Reader,
    buffer: BlockBuffer,
    chunks: Vec<ChunkPointer>,
    pos: Option<usize>,
    len: Option<usize>,
}

impl<R: Reader> BufferedStream<R> {
    fn open_next_chunk(&mut self) -> io::Result<Option<usize>> {
        // we expect the list to be reversed in order, so we can just pop
        let ptr = match self.chunks.pop() {
            Some(ptr) => ptr,
            _ => return Ok(None),
        };

        let chunk = self
            .reader
            .read_chunk(&ptr, self.buffer.as_mut())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Some(chunk.len()))
    }
}

impl<R: Reader> Read for BufferedStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;

        while written < buf.len() {
            match (self.pos, self.len) {
                (Some(pos), Some(len)) if pos != len => {
                    let size = (buf.len() - written).min(len - pos);
                    buf[written..written + size].copy_from_slice(&self.buffer[pos..pos + size]);

                    self.pos = Some(pos + size);
                    written += size;
                }
                _ => match self.open_next_chunk()? {
                    Some(len) => {
                        self.pos = Some(0);
                        self.len = Some(len);
                    }
                    _ => break,
                },
            }
        }

        Ok(written)
    }
}

/// Buffered object writer that supports `std::io::Write`.
///
/// Due to performance and storage waste considerations, this will
/// generate a new chunk roughly about every 500kB of the input
/// stream.
///
/// You need to take this into account when you want to create the
/// indexes around the stream, as every [`ChunkPointer`] is 88 bytes
/// in size, which will occupy memory and storage.
///
/// Note that you can't [`std::io::Seek`] in this stream at this point
/// when reading it.
///
/// # Examples
///
/// ```
/// use std::io::Write;
/// use infinitree::{Infinitree, Key, fields::Serialized, backends::test::InMemoryBackend, object::{BufferedSink, Stream}};
///
/// let mut tree = Infinitree::<infinitree::fields::VersionedMap<String, Stream>>::empty(
///     InMemoryBackend::shared(),
///     Key::from_credentials("username", "password").unwrap()
/// ).unwrap();
///
/// let mut sink = BufferedSink::new(tree.object_writer().unwrap());
///
/// sink.write(b"it's going in the sink");
/// tree.index().insert("message_1".to_string(), sink.finish().unwrap());
/// tree.commit(None);
/// ```
pub struct BufferedSink<Writer = super::AEADWriter, Buffer = BlockBuffer> {
    writer: Writer,
    buffer: Buffer,
    chunks: Vec<ChunkPointer>,
    pos: usize,
    len: usize,
}

impl<W> BufferedSink<W>
where
    W: Writer,
{
    /// Create a new [`BufferedSink`] with the underlying
    /// [`Writer`][crate::object::Writer] instance.
    pub fn new(writer: W) -> BufferedSink<W> {
        Self {
            writer,
            buffer: BlockBuffer::default(),
            chunks: vec![],
            pos: 0,
            len: 0,
        }
    }
}

impl<W, Buffer> BufferedSink<W, Buffer>
where
    W: Writer,
    Buffer: AsMut<[u8]>,
{
    /// Create a new [`BufferedSink`] with the underlying
    /// [`Writer`][crate::object::Writer] and buffer.
    pub fn with_buffer(writer: W, mut buffer: Buffer) -> super::Result<Self> {
        if buffer.as_mut().len() < CHUNK_SIZE {
            return Err(super::ObjectError::BufferTooSmall {
                min_size: CHUNK_SIZE,
            });
        }

        Ok(Self {
            writer,
            buffer,
            chunks: vec![],
            pos: 0,
            len: 0,
        })
    }

    /// Clear the internal buffer without flushing the underlying [`Writer`].
    ///
    /// Calling `clear()` over [`finish`][Self::finish] allows re-using the same buffer
    /// and avoids fragmenting data written to storage.
    ///
    /// Returns the stream's descriptor which can be freely serialized or used in an index.
    pub fn clear(&mut self) -> super::Result<Stream> {
        self.empty_buffer()?;

        self.pos = 0;
        self.len = 0;
        self.buffer.as_mut().fill(0);

        let chunks = Stream(self.chunks.clone());
        self.chunks.clear();
        Ok(chunks)
    }

    /// Finish using the `BufferedSink` instance, flush and close the underlying Writer.
    ///
    /// Returns the stream's descriptor which can be freely serialized or used in an index.
    pub fn finish(mut self) -> super::Result<Stream> {
        self.empty_buffer()?;
        self.flush()?;
        Ok(Stream(self.chunks))
    }

    fn empty_buffer(&mut self) -> super::Result<()> {
        let internal = self.buffer.as_mut();

        if self.len > 0 {
            self.chunks.push(self.writer.write_chunk(
                &crate::crypto::secure_hash(&internal[0..self.len]),
                &internal[0..self.len],
            )?);
        }

        Ok(())
    }
}

impl<W, Buffer> Write for BufferedSink<W, Buffer>
where
    W: Writer,
    Buffer: AsMut<[u8]>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let read_size = |start: usize, pos: usize| (CHUNK_SIZE - pos).min(buf.len() - start);

        let mut start = 0;
        let mut size = read_size(start, self.pos);

        while size > 0 {
            let end = start + size;
            self.len += size;

            self.buffer.as_mut()[self.pos..self.len].copy_from_slice(&buf[start..end]);

            if self.len == CHUNK_SIZE {
                self.empty_buffer()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                self.pos = 0;
                self.len = 0;
                self.buffer.as_mut().fill(0);
            } else {
                self.pos += size;
            }

            start += size;
            size = read_size(start, self.pos);
        }

        Ok(start)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .flush()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn large_buffer_write_then_read() {
        use super::{
            super::{AEADReader, AEADWriter},
            BufferedSink,
        };
        use crate::{backends::test::InMemoryBackend, Key};
        use std::io::{Read, Write};

        let key = Key::from_credentials("asdf", "fdsa").unwrap();
        let backend = InMemoryBackend::shared();
        let mut sink = BufferedSink::new(AEADWriter::new(
            backend.clone(),
            key.get_object_key().unwrap(),
        ));

        // note this is an extreme case, so this test is slow.  the
        // input simultaneously compresses incredibly well, and is
        // hitting an edge case of the `lz4_flex` library, because it's so big.
        //
        // the result is that we generate a lot of chunks, and it's really slow
        const SIZE: usize = 3 * crate::BLOCK_SIZE;
        let buffer = vec![123u8; SIZE];

        assert_eq!(SIZE, sink.write(&buffer).unwrap());

        let chunks = sink.finish().unwrap();
        assert_eq!(25, chunks.0.len());

        let mut buffer2 = vec![0u8; SIZE];
        chunks
            .open_reader(AEADReader::new(
                backend.clone(),
                key.get_object_key().unwrap(),
            ))
            .read(&mut buffer2)
            .unwrap();

        assert_eq!(buffer, buffer2);
    }
}
