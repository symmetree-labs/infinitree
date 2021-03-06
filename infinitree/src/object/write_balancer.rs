use super::{Result, Writer};
use crate::{crypto::Digest, ChunkPointer};

pub type WriterPool<W> = super::Pool<W>;

impl<W: 'static + Writer> Writer for WriterPool<W> {
    fn write_chunk(&mut self, hash: &Digest, data: &[u8]) -> Result<ChunkPointer> {
        let mut writer = self.lease()?;
        let result = writer.write_chunk(hash, data);

        result
    }

    fn flush(&mut self) -> Result<()> {
        for _ in 0..self.count() {
            let mut writer = self.lease()?;
            writer.flush()?;
        }

        Ok(())
    }
}
