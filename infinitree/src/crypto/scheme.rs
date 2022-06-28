use super::{header::*, ops::*, RawKey, Result};
use crate::ObjectId;
use std::sync::Arc;

/// Sealed trait to mark encryption schemes usable in Infinitree.
pub trait IKeySource: 'static + CryptoScheme + Send + Sync {}
impl<T> IKeySource for T where T: 'static + CryptoScheme + Send + Sync {}

/// Key source for all crypto operations.
pub type KeySource = Arc<dyn IKeySource>;

/// A trait that pulls together together all cryptographic
/// operations that must be supported by a scheme.
pub trait CryptoScheme {
    fn root_object_id(&self) -> Result<ObjectId>;
    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<CleartextHeader>;
    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader>;

    fn chunk_key(&self) -> Result<ChunkKey>;
    fn index_key(&self) -> Result<IndexKey>;
    fn storage_key(&self) -> Result<StorageKey> {
        self.chunk_key().map(|ck| StorageKey(ck.0))
    }

    fn expose_convergence_key(&self) -> Option<RawKey>;
}
