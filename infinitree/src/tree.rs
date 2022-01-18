#![deny(missing_docs)]

use crate::{
    fields::{
        self, depth::Depth, Collection, Intent, Load, Query, QueryAction, QueryIteratorOwned,
        Serialized, Store,
    },
    index::{self, Generation, Index, IndexExt, TransactionList},
    object::{AEADReader, AEADWriter},
    Backend, Key, ObjectId,
};
use anyhow::Result;
use parking_lot::RwLock;
use serde_with::serde_as;
use std::{ops::Deref, sync::Arc, time::SystemTime};

/// This is primarily a serialization helper, so we can hash all of
/// this metadata consistently with [`CommitMetadata`]
#[serde_as]
#[derive(Serialize, Debug, Clone)]
struct PreCommitMetadata {
    previous: Option<Generation>,
    message: Option<String>,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    time: SystemTime,
}

impl PreCommitMetadata {
    fn finalize(self, digest: Generation) -> CommitMetadata {
        CommitMetadata {
            digest,
            previous: self.previous,
            message: self.message,
            time: self.time,
        }
    }
}

/// All fields of this struct are hashed into `digest` to make a
/// [`Generation`]
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitMetadata {
    digest: Generation,
    previous: Option<Generation>,
    message: Option<String>,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    time: SystemTime,
}

/// Enum to navigate the versions that are available in an Infinitree
#[allow(unused)]
pub enum GenerationSet {
    /// On querying, all versions will be crawled. This is the
    /// default.
    All,
    /// Only a single generation will be looked at during querying.
    Single(Generation),
    /// All generations up to and including the given one will be queried.
    UpTo(Generation),
    /// Only use generations between the two given versions.
    /// The first parameter **must** be earlier generation than the
    /// second.
    Range(Generation, Generation),
}

impl Default for GenerationSet {
    fn default() -> Self {
        Self::All
    }
}

/// The root index of the tree that stores version information
#[derive(Default, infinitree_macros::Index)]
struct RootIndex {
    /// Transaction log of individual fields included in each
    /// generation.
    ///
    /// The last generation's transactions are at _the front_, so
    /// looping through this naively will yield the last commit
    /// _first_.
    transaction_log: Serialized<TransactionList>,

    /// Chronologically ordered list of commits
    commit_metadata: Serialized<Vec<CommitMetadata>>,
}

impl RootIndex {
    fn version_after(&self, gen: &Generation) -> Option<Generation> {
        let handle = self.commit_metadata.read();

        // walking in reverse may hit faster
        let mut iter = handle.iter().rev().map(|c| c.digest).peekable();
        while let Some(i) = iter.next() {
            if Some(gen) == iter.peek() {
                return Some(i);
            }
        }

        None
    }
}

/// An Infinitree root.
///
/// This is primarily a wrapper around an [`Index`] that manages
/// versioning and key management.
pub struct Infinitree<I> {
    /// All versioning-related stuff is in the `RootIndex`.
    root: RootIndex,

    /// The Index we're currently working with.
    /// The RwLock helps lock the entire Index during a commit
    index: RwLock<I>,

    /// Backend reference.
    backend: Arc<dyn Backend>,

    /// Key that's used to derive all internal keys.
    master_key: Key,

    /// These are the generations we're currently working on.
    selected_gens: GenerationSet,
}

impl<I: Index + Default> Infinitree<I> {
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
    /// );
    /// ```
    pub fn empty(backend: Arc<dyn Backend>, master_key: Key) -> Self {
        Self::with_key(backend, I::default(), master_key)
    }

    /// Load all version information from the tree.
    ///
    /// This method doesn't load the index, only the associated
    /// metadata.
    pub fn open(backend: Arc<dyn Backend>, master_key: Key) -> Result<Self> {
        let root_object = master_key.root_object_id()?;
        let mut root = RootIndex::default();

        open_root(&mut root, backend.clone(), &master_key, root_object)?;

        Ok(Self {
            root,
            backend,
            master_key,
            index: I::default().into(),
            selected_gens: GenerationSet::default(),
        })
    }
}

fn open_root(
    root: &mut RootIndex,
    backend: Arc<dyn Backend>,
    master_key: &Key,
    root_object: ObjectId,
) -> Result<()> {
    let reader = index::Reader::new(backend.clone(), master_key.get_meta_key()?);

    root.load_all_from(
        &root
            .fields()
            .iter()
            .cloned()
            .map(|fname| (crate::Digest::default(), fname, root_object))
            .collect::<TransactionList>(),
        &reader,
        &mut AEADReader::new(backend.clone(), master_key.get_object_key()?),
    )?;

    Ok(())
}

pub enum Message {
    Empty,
    Some(String),
}

impl From<&str> for Message {
    fn from(from: &str) -> Self {
        Self::Some(from.to_string())
    }
}

impl From<Option<String>> for Message {
    fn from(from: Option<String>) -> Self {
        match from {
            Some(s) => Self::Some(s),
            None => Self::Empty,
        }
    }
}

impl From<String> for Message {
    fn from(from: String) -> Self {
        Self::Some(from)
    }
}

impl From<Message> for Option<String> {
    fn from(from: Message) -> Option<String> {
        match from {
            Message::Empty => None,
            Message::Some(s) => Some(s),
        }
    }
}

impl<I: Index> Infinitree<I> {
    /// Wraps the given `index` in an Infinitree.
    ///
    /// This is primarily useful if you're done writing an `Index`,
    /// and want to commit and persist it, or if you need extra
    /// initialization because `Default` is not viable.
    pub fn with_key(backend: Arc<dyn Backend>, index: I, master_key: Key) -> Self {
        Self {
            backend,
            master_key,
            index: index.into(),
            root: RootIndex::default(),
            selected_gens: GenerationSet::default(),
        }
    }

    /// Only run persistence query operations
    /// ([`query`][Infinitree::query], [`load`][Infinitree::load],
    /// [`iter`][Infinitree::iter]) on the selected generations.
    pub fn select(&mut self, version: GenerationSet) {
        self.selected_gens = version;
    }

    /// Return all generations in the tree.
    pub fn generations(&self) -> Vec<CommitMetadata> {
        self.root.commit_metadata.read().clone()
    }

    /// Commit changes currently in the index.
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
    /// );
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
        let key = self.master_key.get_meta_key()?;
        let start_meta = ObjectId::new(&key);

        let mut index = index::Writer::new(start_meta, self.backend.clone(), key.clone())?;
        let mut object = self.object_writer()?;

        let precommit = PreCommitMetadata {
            time: SystemTime::now(),
            message: message.into().into(),
            previous: self.root.commit_metadata.read().last().map(|c| c.digest),
        };
        let (digest, changeset) = self.index.write().commit(
            &mut index,
            &mut object,
            crate::serialize_to_vec(&precommit)?,
        )?;

        self.root
            .commit_metadata
            .write()
            .push(precommit.finalize(digest));

        // scope for rewriting history. this is critical, the log is locked.
        {
            let mut tr_log = self.root.transaction_log.write();
            let size = tr_log.len() + changeset.len();
            let history = std::mem::replace(&mut *tr_log, Vec::with_capacity(size));

            tr_log.extend(
                changeset
                    .into_iter()
                    .map(|(field, oid)| (digest, field, oid)),
            );
            tr_log.extend(history);
        }

        let mut index =
            index::Writer::new(self.master_key.root_object_id()?, self.backend.clone(), key)?;

        // ok to discard this as we're flushing the whole root object
        // anyway
        let _ = self.root.commit(&mut index, &mut object, vec![])?;
        Ok(())
    }

    /// Load into memory all fields for the selected version ranges
    pub fn load_all(&mut self) -> Result<()> {
        self.index.write().load_all_from(
            &self.filter_generations(),
            &self.meta_reader()?,
            &mut self.object_reader()?,
        )
    }

    /// I don't think this function makes sense publicly in this form.
    ///
    /// TODO: how this would work well is an open question.
    #[allow(unused)]
    pub(crate) fn store(&self, field: impl Into<Intent<Box<dyn Store>>>) -> Result<ObjectId> {
        let mut field = field.into();
        let start_object = self.store_start_object(&field.name);

        Ok(self.index.read().store(
            &mut self.meta_writer(start_object)?,
            &mut self.object_writer()?,
            &mut field,
        ))
    }

    /// Load the field for the selected generation set
    pub fn load(&self, field: impl Into<Intent<Box<dyn Load>>>) -> Result<()> {
        let mut field = field.into();
        let commits_for_field = self.field_for_version(&field.name);

        field.strategy.load(
            &self.meta_reader()?,
            &mut self.object_reader()?,
            commits_for_field,
        );

        Ok(())
    }

    /// Load into memory all data from `field` where `pred` returns `true`
    pub fn query<K>(
        &self,
        mut field: Intent<Box<impl Query<Key = K>>>,
        pred: impl Fn(&K) -> QueryAction,
    ) -> Result<()> {
        let commits_for_field = self.field_for_version(&field.name);

        field.strategy.select(
            &self.meta_reader()?,
            &mut self.object_reader()?,
            commits_for_field,
            pred,
        );

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
        let index = self.meta_reader()?;
        let object = self.object_reader()?;
        let commits_for_field = self.field_for_version(&field.name);

        Ok(
            <Q as Collection>::Depth::resolve(index, commits_for_field).flat_map(
                move |transaction| {
                    QueryIteratorOwned::new(
                        transaction,
                        object.clone(),
                        pred.clone(),
                        field.strategy.as_mut(),
                    )
                },
            ),
        )
    }

    fn store_start_object(&self, _name: &str) -> ObjectId {
        ObjectId::new(&self.master_key.get_meta_key().unwrap())
    }

    fn filter_generations(&self) -> TransactionList {
        self.root
            .transaction_log
            .read()
            .iter()
            .skip_while(|(gen, _, _)| match &self.selected_gens {
                GenerationSet::All => false,
                GenerationSet::Single(target) => gen != target,
                GenerationSet::UpTo(_target) => false,
                GenerationSet::Range(start, _end) => gen != start,
            })
            .take_while(|(gen, _, _)| match &self.selected_gens {
                GenerationSet::All => true,
                GenerationSet::Single(target) => gen == target,
                GenerationSet::UpTo(target) => self
                    .root
                    .version_after(target)
                    .map(|ref v| v != gen)
                    .unwrap_or(true),
                GenerationSet::Range(_start, end) => self
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

    fn meta_writer(&self, start_object: ObjectId) -> Result<index::Writer> {
        Ok(index::Writer::new(
            start_object,
            self.backend.clone(),
            self.master_key.get_meta_key()?,
        )?)
    }

    fn meta_reader(&self) -> Result<index::Reader> {
        Ok(index::Reader::new(
            self.backend.clone(),
            self.master_key.get_meta_key()?,
        ))
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
    pub fn object_reader(&self) -> Result<AEADReader> {
        Ok(AEADReader::new(
            self.backend.clone(),
            self.master_key.get_object_key()?,
        ))
    }

    /// Return an immutable reference to the internal index.
    ///
    /// By design this is read-only, as the index fields
    /// should use internal mutability and be thread-safe
    /// individually.
    pub fn index(&self) -> impl Deref<Target = I> + '_ {
        self.index.read()
    }
}
