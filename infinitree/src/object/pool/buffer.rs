use super::PoolRef;
use crate::BLOCK_SIZE;

pub type BlockBuffer = PoolRef<Box<[u8]>>;

impl Clone for BlockBuffer {
    fn clone(&self) -> Self {
        PoolRef {
            instance: self.instance.clone(),
            enqueue: None,
        }
    }
}

impl Default for BlockBuffer {
    #[inline]
    fn default() -> BlockBuffer {
        BlockBuffer {
            instance: Some(vec![0; BLOCK_SIZE].into_boxed_slice()),
            enqueue: None,
        }
    }
}

impl AsMut<[u8]> for BlockBuffer {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.instance.as_mut().unwrap()
    }
}

impl AsRef<[u8]> for BlockBuffer {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.instance.as_ref().unwrap()
    }
}
