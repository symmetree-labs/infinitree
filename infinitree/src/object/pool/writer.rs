use crate::{
    crypto::Digest,
    object::{Result, Writer},
    ChunkPointer,
};

pub type WriterPool<W> = super::Pool<W>;

impl<W: 'static + Writer> Writer for WriterPool<W> {
    fn write(&mut self, data: &[u8]) -> Result<ChunkPointer> {
        let mut writer = self.lease()?;

        writer.write(data)
    }

    fn write_chunk(&mut self, hash: &Digest, data: &[u8]) -> Result<ChunkPointer> {
        let mut writer = self.lease()?;

        writer.write_chunk(hash, data)
    }

    fn flush(&mut self) -> Result<()> {
        for _ in 0..self.count() {
            let mut writer = self.lease()?;
            writer.flush()?;
        }

        Ok(())
    }
}
