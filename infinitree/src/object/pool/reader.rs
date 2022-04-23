use super::{
    super::{AEADReader, Reader, Result},
    PoolRef,
};
use crate::ChunkPointer;

impl Reader for PoolRef<AEADReader> {
    fn read_chunk<'target>(
        &mut self,
        pointer: &ChunkPointer,
        target: &'target mut [u8],
    ) -> Result<&'target [u8]> {
        self.instance.as_mut().unwrap().read_chunk(pointer, target)
    }
}
