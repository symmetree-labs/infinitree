//! Main tree and commit management
#![deny(missing_docs)]

use crate::{
    fields::{
        self, depth::Depth, Collection, Intent, Load, Query, QueryAction, QueryIteratorOwned,
    },
    index::{self, Index, IndexExt, TransactionList},
    object::{AEADReader, AEADWriter, BlockBuffer, BufferedSink, Pool, PoolRef},
    Backend, Key,
};
use anyhow::Result;
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use std::{ops::Deref, sync::Arc, time::SystemTime};

mod commit;
pub use commit::*;

mod root;
pub(crate) use root::*;

mod sealed_root;

/// Allows changing commit behaviour.
pub enum CommitMode {
    /// Always create a new commit even if it's empty.
    Always,
    /// Only create a new commit when there are changes to the index.
    OnlyOnChange,
}

/// An Infinitree root.
///
/// This is primarily a wrapper around an [`Index`] that manages
/// versioning and key management.
pub struct Infinitree<I, CustomData = ()>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// All versioning-related stuff is in the `RootIndex`.
    root: RootIndex<CustomData>,

    /// The Index we're currently working with.
    /// The RwLock helps lock the entire Index during a commit
    index: RwLock<I>,

    /// Backend reference.
    backend: Arc<dyn Backend>,

    /// Key that's used to derive all internal keys.
    master_key: Key,

    /// These are the generations we're currently working on.
    commit_filter: CommitFilter,

    /// Pool for object readers
    reader_pool: Pool<AEADReader>,
}

impl<I, CustomData> Drop for Infinitree<I, CustomData>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.backend.sync().unwrap();
    }
}

impl<I: Index + Default, CustomData> Infinitree<I, CustomData>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync,
{
    /// Initialize an empty index and tree with no version history.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use infinitree::{Infinitree, Key, fields::Serialized, backends::Directory};
    ///
    /// #[derive(infinitree::Index, Default)]
    /// struct Measurements {
    ///     list: Serialized<Vec<usize>>
    /// }
    ///
    /// let mut tree = Infinitree::<Measurements>::empty(
    ///     Directory::new("/storage").unwrap(),
    ///     Key::from_credentials("username", "password").unwrap()
    /// ).unwrap();
    /// ```
    pub fn empty(backend: Arc<dyn Backend>, master_key: Key) -> Result<Self> {
        Self::with_key(backend, I::default(), master_key)
    }

    /// Load all version information from the tree.
    ///
    /// This method doesn't load the index, only the associated
    /// metadata.
    pub fn open(backend: Arc<dyn Backend>, master_key: Key) -> Result<Self> {
        let root_object = master_key.root_object_id()?;
        let root_key = master_key.get_root_key()?;

        let root = sealed_root::open(
            root_object,
            BlockBuffer::default(),
            backend.clone(),
            root_key,
        )?;

        let chunk_key = master_key.get_object_key()?;
        let reader_pool = {
            let backend = backend.clone();
            Pool::with_constructor(0, move || {
                AEADReader::new(backend.clone(), chunk_key.clone())
            })
        };
        Ok(Self {
            root,
            master_key,
            reader_pool,
            backend: backend.clone(),
            index: I::default().into(),
            commit_filter: CommitFilter::default(),
        })
    }
}

impl<I: Index, CustomData> Infinitree<I, CustomData>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + Default,
{
    /// Create a commit if there are changes in the index.
    ///
    /// This persists currently in-memory data, and also records the
    /// commit with `message` to the log.
    ///
    /// # Examples
    ///
    /// Any commit message works that implements [`ToString`].
    ///
    /// ```no_run
    /// use infinitree::{Infinitree, Key, fields::Serialized, backends::Directory};
    ///
    /// let mut tree = Infinitree::<infinitree::fields::VersionedMap<String, String>>::empty(
    ///     Directory::new("/storage").unwrap(),
    ///     Key::from_credentials("username", "password").unwrap()
    /// ).unwrap();
    ///
    /// // Commit message can be omitted using `None`
    /// tree.commit(None);
    ///
    /// // Otherwise a hardcoded &str also works
    /// tree.commit("this is a message");
    ///
    /// // Or even a String instance
    /// let message = "this is a string".to_string();
    /// tree.commit(message);
    /// ```
    pub fn commit(&mut self, message: impl Into<Message>) -> Result<()> {
        let metadata = CommitMetadata {
            time: SystemTime::now(),
            message: message.into().into(),
            previous: self.root.commit_list.read().last().map(|c| c.id),
            ..Default::default()
        };

        self.commit_with_metadata(metadata, CommitMode::OnlyOnChange)
    }
}

impl<I: Index, CustomData> Infinitree<I, CustomData>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync,
{
    /// Wraps the given `index` in an Infinitree.
    ///
    /// This is primarily useful if you're done writing an `Index`,
    /// and want to commit and persist it, or if you need extra
    /// initialization because `Default` is not viable.
    pub fn with_key(backend: Arc<dyn Backend>, index: I, master_key: Key) -> Result<Self> {
        let chunk_key = master_key.get_object_key()?;

        Ok(Self {
            master_key,
            backend: backend.clone(),
            index: index.into(),
            root: RootIndex::default(),
            commit_filter: CommitFilter::default(),
            reader_pool: Pool::with_constructor(0, move || {
                AEADReader::new(backend.clone(), chunk_key.clone())
            }),
        })
    }

    /// Return all generations in the tree.
    pub fn commit_list(&self) -> impl Deref<Target = Vec<Commit<CustomData>>> + '_ {
        self.root.commit_list.read()
    }

    /// Only run persistence query operations
    /// ([`query`][Infinitree::query], [`load`][Infinitree::load],
    /// [`iter`][Infinitree::iter]) on the selected generations.
    pub fn filter_commits(&mut self, version: CommitFilter) {
        self.commit_filter = version;
    }

    /// Commit changes currently in the index.
    ///
    /// For full documentation, please read [`Infinitree::commit`].
    pub fn commit_with_custom_data(
        &mut self,
        message: impl Into<Message>,
        mode: CommitMode,
        custom_data: CustomData,
    ) -> Result<()> {
        let metadata = CommitMetadata {
            time: SystemTime::now(),
            message: message.into().into(),
            previous: self.root.commit_list.read().last().map(|c| c.id),
            custom_data,
        };

        self.commit_with_metadata(metadata, mode)
    }

    /// Commit using manually prepared metadata
    ///
    /// For full documentation, please read [`Infinitree::commit`].
    pub fn commit_with_metadata(
        &mut self,
        metadata: CommitMetadata<CustomData>,
        mode: CommitMode,
    ) -> Result<()> {
        let mut object = self.object_writer()?;
        let mut sink = BufferedSink::new(self.object_writer()?);

        let (id, changeset) = self.index.write().commit(
            &mut sink,
            &mut object,
            crate::serialize_to_vec(&metadata)?,
        )?;

        if let CommitMode::OnlyOnChange = mode {
            if changeset.iter().all(|(_, stream)| stream.is_empty()) {
                return Ok(());
            }
        }

        self.root.commit_list.write().push(Commit { id, metadata });

        // scope for rewriting history. this is critical, the log is locked.
        {
            let mut tr_log = self.root.transaction_log.write();
            let size = tr_log.len() + changeset.len();
            let history = std::mem::replace(&mut *tr_log, Vec::with_capacity(size));

            tr_log.extend(changeset.into_iter().map(|(field, oid)| (id, field, oid)));
            tr_log.extend(history);
        }

        sealed_root::commit(
            &mut self.root,
            self.master_key.root_object_id()?,
            self.backend.clone(),
            self.master_key.get_root_key()?,
        )?;
        Ok(())
    }

    /// Load into memory all fields for the selected version ranges
    pub fn load_all(&mut self) -> Result<()> {
        self.index
            .write()
            .load_all_from(&self.filter_generations(), &self.reader_pool)
    }

    /// Load the field for the selected generation set
    pub fn load(&self, field: impl Into<Intent<Box<dyn Load>>>) -> Result<()> {
        let mut field = field.into();
        let commits_for_field = self.field_for_version(&field.name);

        field
            .strategy
            .load(self.reader_pool.clone(), commits_for_field);

        Ok(())
    }

    /// Load into memory all data from `field` where `pred` returns `true`
    pub fn query<K>(
        &self,
        mut field: Intent<Box<impl Query<Key = K>>>,
        pred: impl Fn(&K) -> QueryAction,
    ) -> Result<()> {
        let commits_for_field = self.field_for_version(&field.name);

        field
            .strategy
            .select(self.reader_pool.clone(), commits_for_field, pred);

        Ok(())
    }

    /// Same as [`query`][Self::query], but returns an `Iterator`
    pub fn iter<K, O, Q>(
        &self,
        mut field: Intent<Box<Q>>,
        pred: impl Fn(&K) -> QueryAction + 'static,
    ) -> Result<impl Iterator<Item = O> + '_>
    where
        for<'de> <Q as fields::Collection>::Serialized: serde::Deserialize<'de>,
        Q: Collection<Key = K, Item = O> + 'static,
    {
        let pred = Arc::new(pred);
        let commits_for_field = self.field_for_version(&field.name);

        Ok(
            <Q as Collection>::Depth::resolve(self.reader_pool.clone(), commits_for_field)
                .flat_map(move |transaction| {
                    QueryIteratorOwned::new(
                        transaction,
                        self.reader_pool.lease().unwrap(),
                        pred.clone(),
                        field.strategy.as_mut(),
                    )
                }),
        )
    }

    fn filter_generations(&self) -> TransactionList {
        self.root
            .transaction_log
            .read()
            .iter()
            .skip_while(|(gen, _, _)| match &self.commit_filter {
                CommitFilter::All => false,
                CommitFilter::Single(target) => gen != target,
                CommitFilter::UpTo(_target) => false,
                CommitFilter::Range(start, _end) => gen != start,
            })
            .take_while(|(gen, _, _)| match &self.commit_filter {
                CommitFilter::All => true,
                CommitFilter::Single(target) => gen == target,
                CommitFilter::UpTo(target) => self
                    .root
                    .version_after(target)
                    .map(|ref v| v != gen)
                    .unwrap_or(true),
                CommitFilter::Range(_start, end) => self
                    .root
                    .version_after(end)
                    .map(|ref v| v != gen)
                    .unwrap_or(true),
            })
            .cloned()
            .collect()
    }

    fn field_for_version(&self, field: &index::Field) -> TransactionList {
        self.filter_generations()
            .into_iter()
            .filter(|(_, name, _)| name == field)
            .collect::<Vec<_>>()
    }

    /// Return a handle for an object writer.
    ///
    /// This can be used to manually write sparse data if you don't
    /// want to store it in memory. Especially useful for e.g. files.
    ///
    /// Note that currently there's no fragmenting internally, so
    /// anything written using an ObjectWriter **must** be less than
    /// about 4MB.
    pub fn object_writer(&self) -> Result<AEADWriter> {
        Ok(AEADWriter::new(
            self.backend.clone(),
            self.master_key.get_object_key()?,
        ))
    }

    /// Return a handle for an object reader
    ///
    /// The object reader is for reading out those [`ChunkPointer`][crate::ChunkPointer]s
    /// that you get when using an [`AEADWriter`] stack manually.
    ///
    /// You can obtain an [`AEADWriter`] using [`object_writer`][Self::object_writer].
    pub fn object_reader(&self) -> Result<PoolRef<AEADReader>> {
        Ok(self.reader_pool.lease()?)
    }

    /// Return an immutable reference to the internal index.
    ///
    /// By design this is read-only, as the index fields
    /// should use internal mutability and be thread-safe
    /// individually.
    pub fn index(&self) -> impl Deref<Target = I> + '_ {
        self.index.read()
    }

    /// Return the backend
    ///
    /// This allows synchronization of backends that queue upload
    /// jobs, or other background tasks.
    pub fn backend(&self) -> Arc<dyn Backend> {
        self.backend.clone()
    }
}
