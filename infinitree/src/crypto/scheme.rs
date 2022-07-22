use super::{header::*, ops::*, *};
use crate::{chunks::RawChunkPointer, ObjectId};
use std::sync::Arc;

/// Sealed trait to mark encryption schemes usable in Infinitree.
pub trait KeySource: 'static + Scheme {}
impl<T> KeySource for T where T: 'static + Scheme {}

/// Key source for all crypto operations.
pub type Key = Arc<dyn KeySource>;

/// Binds header and internal encryption. This type can only be
/// instantiated through type aliases.
pub struct KeyingScheme<H, I> {
    pub(crate) header: Arc<H>,
    pub(crate) convergence: I,
}

impl<H, I> KeyingScheme<H, I> {
    pub(super) fn new(header: H, convergence: I) -> Self {
        Self {
            header: header.into(),
            convergence,
        }
    }
}

// Seems like `.into()` doesn't work well for dynamic types, so
// explicitly define it here
#[allow(clippy::from_over_into)]
impl<H, I> Into<Key> for KeyingScheme<H, I>
where
    H: HeaderScheme + 'static,
    I: InternalScheme + 'static,
{
    fn into(self) -> Key {
        Arc::new(self)
    }
}

impl<H, I> Scheme for KeyingScheme<H, I>
where
    H: HeaderScheme + 'static,
    I: InternalScheme,
{
    fn root_object_id(&self) -> Result<ObjectId> {
        self.header.root_object_id()
    }

    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<Header> {
        let (root_ptr, key) = self.header.clone().open_header(header, &self.convergence)?;

        Ok(Header {
            root_ptr,
            key: Arc::new(key),
        })
    }

    fn seal_root(&self, root_ptr: &RawChunkPointer) -> Result<SealedHeader> {
        let mut open = OpenHeader::default();
        let pos = root_ptr.write_to(&mut open);
        self.convergence.write_key(&mut open[pos..]);
        self.header.seal_root(open)
    }

    fn chunk_key(&self) -> Result<ChunkKey> {
        self.convergence.chunk_key()
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.convergence.index_key()
    }

    fn storage_key(&self) -> Result<StorageKey> {
        self.convergence.storage_key()
    }
}

/// Change the header key on sealing a tree.
///
/// You will need to use this key to open a the tree, then create a
/// commit or reseal to apply the changes.
///
/// # Examples
///
/// ```no_run
/// use infinitree::{*, crypto::*, fields::VersionedMap, backends::Directory};
///
/// let key = ChangeHeaderKey::swap_on_seal(
///     UsernamePassword::with_credentials("username".to_string(),
///                                        "old_password".to_string()).unwrap(),
///     UsernamePassword::with_credentials("username".to_string(),
///                                            "new_password".to_string()).unwrap(),
/// );
///
/// let mut tree = Infinitree::<VersionedMap<String, String>>::open(
///     Directory::new("/storage").unwrap(),
///     key
/// ).unwrap();
///
/// tree.reseal();
/// ```
pub struct ChangeHeaderKey<H, N, I> {
    opener: Arc<H>,
    sealer: Arc<N>,
    convergence: I,
}

#[allow(clippy::from_over_into)]
impl<H, N, I> Into<Key> for ChangeHeaderKey<H, N, I>
where
    H: HeaderScheme + 'static,
    N: HeaderScheme + 'static,
    I: InternalScheme + 'static,
{
    fn into(self) -> Key {
        Arc::new(self)
    }
}

impl<H, N, I> ChangeHeaderKey<H, N, I> {
    pub fn swap_on_seal(original: KeyingScheme<H, I>, new: KeyingScheme<N, I>) -> Self {
        Self {
            opener: original.header,
            sealer: new.header,
            convergence: original.convergence,
        }
    }
}

impl<H, N, I> Scheme for ChangeHeaderKey<H, N, I>
where
    H: HeaderScheme + 'static,
    N: HeaderScheme + 'static,
    I: InternalScheme,
{
    fn root_object_id(&self) -> Result<ObjectId> {
        self.opener.root_object_id()
    }

    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<Header> {
        let (root_ptr, key) = self.opener.clone().open_header(header, &self.convergence)?;

        Ok(Header {
            root_ptr,
            key: Arc::new(KeyingScheme {
                header: self.sealer.clone(),
                convergence: key.convergence,
            }),
        })
    }

    fn seal_root(&self, root_ptr: &RawChunkPointer) -> Result<SealedHeader> {
        let mut open = OpenHeader::default();
        let pos = root_ptr.write_to(&mut open);
        self.convergence.write_key(&mut open[pos..]);
        self.sealer.seal_root(open)
    }

    fn chunk_key(&self) -> Result<ChunkKey> {
        self.convergence.chunk_key()
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.convergence.index_key()
    }

    fn storage_key(&self) -> Result<StorageKey> {
        self.convergence.storage_key()
    }
}

pub(crate) use private::*;
pub(crate) mod private {
    use super::*;

    pub type InternalKey = Arc<dyn InternalScheme>;

    /// A trait that pulls together together all cryptographic
    /// operations that must be supported by a scheme.
    pub trait Scheme: Send + Sync {
        fn root_object_id(&self) -> Result<ObjectId>;
        fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<Header>;
        fn seal_root(&self, root_ptr: &RawChunkPointer) -> Result<SealedHeader>;

        fn chunk_key(&self) -> Result<ChunkKey>;
        fn index_key(&self) -> Result<IndexKey>;
        fn storage_key(&self) -> Result<StorageKey>;
    }

    pub trait HeaderScheme: Send + Sync {
        fn open_root(&self, header: SealedHeader) -> Result<OpenHeader>;

        fn seal_root(&self, header: OpenHeader) -> Result<SealedHeader>;

        fn open_header<IS: InternalScheme>(
            self: Arc<Self>,
            header: SealedHeader,
            internal: &IS,
        ) -> Result<(RawChunkPointer, KeyingScheme<Self, InternalKey>)>
        where
            Self: Sized + 'static,
        {
            let open = self.open_root(header)?;
            let (pos, root_ptr) = RawChunkPointer::parse(&open);
            let convergence = internal.read_key(&open[pos..]);

            Ok((
                root_ptr,
                KeyingScheme {
                    header: self,
                    convergence,
                },
            ))
        }

        fn root_object_id(&self) -> Result<ObjectId>;
    }

    pub trait InternalScheme: Send + Sync {
        fn chunk_key(&self) -> Result<ChunkKey>;
        fn index_key(&self) -> Result<IndexKey>;
        fn storage_key(&self) -> Result<StorageKey>;

        fn read_key(&self, raw_head: &[u8]) -> InternalKey;
        fn write_key(&self, raw_head: &mut [u8]) -> usize;
    }

    impl InternalScheme for Arc<dyn InternalScheme> {
        fn chunk_key(&self) -> Result<ChunkKey> {
            Arc::as_ref(self).chunk_key()
        }

        fn index_key(&self) -> Result<IndexKey> {
            Arc::as_ref(self).index_key()
        }

        fn storage_key(&self) -> Result<StorageKey> {
            Arc::as_ref(self).storage_key()
        }

        fn read_key(&self, raw_head: &[u8]) -> InternalKey {
            Arc::as_ref(self).read_key(raw_head)
        }

        fn write_key(&self, raw_head: &mut [u8]) -> usize {
            Arc::as_ref(self).write_key(raw_head)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{crypto::UsernamePassword, fields::VersionedMap, Infinitree};

    #[test]
    fn change_key() {
        let storage = crate::backends::test::InMemoryBackend::shared();
        let old_key = || {
            UsernamePassword::with_credentials("change_key".to_string(), "old_password".to_string())
                .unwrap()
        };
        let new_key = || {
            UsernamePassword::with_credentials("change_key".to_string(), "new_password".to_string())
                .unwrap()
        };

        // crate a tree and put some data into it
        {
            let mut tree =
                Infinitree::<VersionedMap<usize, usize>>::empty(storage.clone(), old_key())
                    .unwrap();
            tree.index().insert(1000, 1000);
            tree.commit(None).unwrap();
            tree.index().clear();

            for i in 0..100 {
                tree.index().insert(i, i + 1);
            }

            tree.commit(None).unwrap();
        }

        // change the key and reseal
        {
            let key = ChangeHeaderKey::swap_on_seal(old_key(), new_key());
            let mut tree =
                Infinitree::<VersionedMap<usize, usize>>::open(storage.clone(), key).unwrap();
            tree.reseal().unwrap();
        }

        // the tree now can be opened with the new key
        let tree =
            Infinitree::<VersionedMap<usize, usize>>::open(storage.clone(), new_key()).unwrap();
        tree.load_all().unwrap();

        for i in 0..100 {
            assert_eq!(i + 1, *tree.index().get(&i).unwrap());
        }

        assert_eq!(tree.index().len(), 101);
    }
}
