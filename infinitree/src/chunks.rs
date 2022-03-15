use crate::crypto::{Digest, Tag};
use crate::object::ObjectId;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub(crate) struct RawChunkPointer {
    pub offs: u32,
    pub size: u32,
    pub file: ObjectId,
    pub hash: Digest,
    pub tag: Tag,
}

/// A pointer for a chunk of data in the object system.
///
/// A `ChunkPointer`, in addition to a [`Key`][crate::Key] is required
/// to access most data that's outside the index system.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub struct ChunkPointer(RawChunkPointer);

impl ChunkPointer {
    #[inline(always)]
    pub(crate) fn new(offs: u32, size: u32, file: ObjectId, hash: Digest, tag: Tag) -> Self {
        Self(RawChunkPointer {
            offs,
            size,
            file,
            hash,
            tag,
        })
    }

    #[inline(always)]
    pub(crate) fn as_raw(&self) -> &RawChunkPointer {
        &self.0
    }

    #[inline(always)]
    pub fn object_id(&self) -> &ObjectId {
        &self.0.file
    }

    #[inline(always)]
    pub fn hash(&self) -> &Digest {
        &self.0.hash
    }
}
