use crate::crypto::{Digest, Tag};
use crate::object::ObjectId;
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub struct RawChunkPointer {
    pub offs: u32,
    pub size: u32,
    pub object: ObjectId,
    pub key: Digest,
    pub tag: Tag,
}

impl RawChunkPointer {
    pub(crate) fn parse<T: AsRef<[u8]>>(buffer: T) -> (usize, Self) {
        let buffer = buffer.as_ref();
        let mut pointer = RawChunkPointer::default();

        let mut read = 0;
        let mut next = 0;

        pointer.offs = {
            let mut bu32: [u8; 4] = Default::default();

            next += size_of::<u32>();
            bu32.copy_from_slice(&buffer[read..next]);
            read = next;

            u32::from_ne_bytes(bu32)
        };

        pointer.size = {
            let mut bu32: [u8; 4] = Default::default();

            next += size_of::<u32>();
            bu32.copy_from_slice(&buffer[read..next]);
            read = next;

            u32::from_ne_bytes(bu32)
        };

        next += size_of::<ObjectId>();
        pointer.object = ObjectId::from_bytes(&buffer[read..next]);
        read = next;

        next += size_of::<Digest>();
        pointer.key.copy_from_slice(&buffer[read..next]);
        read = next;

        next += size_of::<Tag>();
        pointer.tag.copy_from_slice(&buffer[read..next]);

        debug_assert!(next == size_of::<Self>());

        (next, pointer)
    }

    pub fn write_to(&self, buf: &mut [u8]) -> usize {
        assert!(buf.len() >= size_of::<RawChunkPointer>());

        let mut wrote = 0;
        let mut next = 0;

        next += size_of::<u32>();
        buf[wrote..next].copy_from_slice(&self.offs.to_ne_bytes());
        wrote = next;

        next += size_of::<u32>();
        buf[wrote..next].copy_from_slice(&self.size.to_ne_bytes());
        wrote = next;

        next += size_of::<ObjectId>();
        buf[wrote..next].copy_from_slice(self.object.as_ref());
        wrote = next;

        next += size_of::<Digest>();
        buf[wrote..next].copy_from_slice(self.key.as_ref());
        wrote = next;

        next += size_of::<Tag>();
        buf[wrote..next].copy_from_slice(self.tag.as_ref());

        next
    }
}

impl<const N: usize> From<RawChunkPointer> for [u8; N] {
    fn from(ptr: RawChunkPointer) -> Self {
        let mut buf = [0; N];
        ptr.write_to(&mut buf);
        buf
    }
}

/// A pointer for a chunk of data in the object system.
///
/// A `ChunkPointer`, in addition to a [`KeySource`][crate::crypto::KeySource] is required
/// to access most data that's outside the index system.
///
/// # Examples
/// ```
/// use infinitree::ChunkPointer;
///
/// assert_eq!(std::mem::size_of::<ChunkPointer>(), 88);
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub struct ChunkPointer(RawChunkPointer);

impl ChunkPointer {
    #[inline(always)]
    pub fn object_id(&self) -> &ObjectId {
        &self.0.object
    }

    #[inline(always)]
    pub fn hash(&self) -> &Digest {
        &self.0.key
    }

    #[inline(always)]
    pub(crate) fn size(&self) -> usize {
        self.0.size as usize
    }

    #[inline(always)]
    pub(crate) fn into_raw(self) -> RawChunkPointer {
        self.0
    }

    #[inline(always)]
    pub(crate) fn as_raw(&self) -> &RawChunkPointer {
        &self.0
    }
}

impl From<RawChunkPointer> for ChunkPointer {
    #[inline(always)]
    fn from(inner: RawChunkPointer) -> Self {
        Self(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::RawChunkPointer;
    use crate::ObjectId;

    #[test]
    fn encode_and_decode_raw_pointer() {
        let ptr = RawChunkPointer {
            offs: 1234,
            size: 1337,
            object: ObjectId::default(),
            key: [
                // intricately weaved pattern to make sure there's no repetition
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0,
                0xc0, 0xd0, 0xe0, 0xf0,
            ],
            tag: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        };

        let buffer: [u8; 128] = ptr.clone().into();
        assert_eq!(RawChunkPointer::parse(buffer).1, ptr);
    }
}
