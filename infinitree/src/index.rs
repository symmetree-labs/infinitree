//! # Working with the index of an Infinitree.
//!
//! Infinitree recognizes two kinds of objects that appear on the
//! storage medium: index, and data. From the outside, they're
//! indistinguishible, but they work quite differently.
//!
//! Data objects are individually encrypted pieces of data with a
//! changing key. A [`ChunkPointer`](crate::ChunkPointer) uniquely
//! identifies a data chunk within the object pool, and you need to
//! track these somehow.
//!
//! Index objects are basically encrypted LZ4 streams layed out across
//! multiple blobs. These LZ4 streams are produced by serializing
//! collections that are tracked by a `struct` which implements the
//! [`Index`] trait.
//!
//! Having an `Index` for you Infinitree is essential, unless you plan
//! to track your data using other means.
//!
//! ## Efficient use of indexes
//!
//! An index can have multiple [fields](crate::fields), which are collections or other serializable data structures.
//!
//! ```
//! use infinitree::{
//!     Index,
//!     fields::{Serialized, VersionedMap},
//! };
//! use serde::{Serialize,Deserialize};
//!
//! #[derive(Serialize,Deserialize,Clone)]
//! struct BigStruct;
//!
//! #[derive(Index, Default, Clone)]
//! pub struct Measurements {
//!
//!     // Anything implementing `serde::Serialize` can be used
//!     // through a proxy, and stored either in the index, or in the
//!     // object pool through `SparseField`
//!     last_time: Serialized<usize>,
//!
//!     // only store the keys in the index, not the values
//!     #[infinitree(strategy = "infinitree::fields::SparseField")]
//!     measurements: VersionedMap<usize, BigStruct>,
//! }
//! ```
//!
//! A crucial detail in choosing the right indexing strategy is
//! exactly how much data do you want to store in index objects.
//!
//! It is possible to use a `SparseField` serialization strategy for
//! most collections provided in the base library. By storing large
//! data in the data object pool instead of index objects that are
//! linearly read and deserialized, you can achieve measurable
//! performance increase for certain use cases.

use crate::{
    fields::*,
    object::{AEADReader, BufferedSink, Pool, Stream, Writer},
    tree::CommitId,
};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) type Field = String;
pub(crate) type TransactionPointer = (CommitId, Field, Stream);

/// A list of transactions, represented in order, for versions and fields
pub(crate) type TransactionList = Vec<TransactionPointer>;

/// Marker trait for contiguous write operations.
pub trait Transaction: Send + Sync + std::io::Write {}
impl<T> Transaction for T where T: Send + Sync + std::io::Write {}

/// Any structure that is usable as an Index
///
/// The two mandatory functions, [`store_all`](Index::store_all) and
/// [`load_all`][Index::load_all] are automatically generated if the
/// [`derive@crate::Index`] macro is used to derive this trait.
///
/// Generally an index will allow you to work with its fields
/// independently and in-memory, and the functions of this trait will
/// only help accessing backing storage. The [`Intent`] instances wrap
/// each field in a way that an [`Infinitree`](crate::Infinitree) can work with.
pub trait Index: Send + Sync {
    /// Generate an [`Intent`] wrapper for each field in the `Index`.
    ///
    /// You should normally use the [`Index`](derive@crate::Index) derive macro to generate this.
    fn store_all(&mut self) -> anyhow::Result<Vec<Intent<Box<dyn Store>>>>;

    /// Generate an [`Intent`] wrapper for each field in the `Index`.
    ///
    /// You should normally use the [`Index`](derive@crate::Index) derive macro to generate this.
    fn load_all(&mut self) -> anyhow::Result<Vec<Intent<Box<dyn Load>>>>;
}

/// Allows serializing individual records of an infinite collection.
pub trait FieldWriter: Send {
    /// Write the next `obj` into the index
    fn write_next(&mut self, obj: impl Serialize + Send);
}

impl<T> FieldWriter for T
where
    T: std::io::Write + Send,
{
    fn write_next(&mut self, obj: impl Serialize + Send) {
        crate::serialize_to_writer(self, &obj).unwrap();
    }
}

/// Allows deserializing an infinite collection by reading records one by one.
pub trait FieldReader: Send {
    /// Read the next available record from storage.
    fn read_next<T: DeserializeOwned>(&mut self) -> anyhow::Result<T>;
}

impl<'a, R> FieldReader for crate::Deserializer<R>
where
    R: rmp_serde::decode::ReadSlice<'a> + Send,
{
    fn read_next<T: DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        Ok(T::deserialize(self)?)
    }
}

impl<T> IndexExt for T where T: Index {}

/// This is just a convenience layer to handle direct operations on an index
///
/// All of these functions are mirrored in [`Infinitree`] in a way
/// that's automatically handling reader/writer management & versions
///
/// In the future it may be worth exposing this more low-level interface
pub(crate) trait IndexExt: Index {
    fn load_all_from(
        &mut self,
        full_transaction_list: &TransactionList,
        pool: &Pool<AEADReader>,
    ) -> anyhow::Result<()> {
        // #accidentallyquadratic

        for action in self.load_all()?.iter_mut() {
            let commits_for_field = full_transaction_list
                .iter()
                .filter(|(_, name, _)| name == &action.name)
                .cloned()
                .collect::<Vec<_>>();

            self.load(commits_for_field, pool, action);
        }
        Ok(())
    }

    fn commit<W: Writer + Send + Sync>(
        &mut self,
        sink: &mut BufferedSink<W>,
        object: &mut dyn Writer,
        mut hashed_data: Vec<u8>,
        crypto: impl crate::crypto::ICryptoOps,
    ) -> anyhow::Result<(CommitId, Vec<(Field, Stream)>)> {
        let log = self
            .store_all()?
            .drain(..)
            .map(|mut action| (action.name.clone(), self.store(sink, object, &mut action)))
            .collect();
        hashed_data.extend(crate::serialize_to_vec(&log)?);

        let version = crypto.hash(&hashed_data);
        Ok((CommitId::from_bytes(version), log))
    }

    fn store<W: Writer + Send + Sync>(
        &self,
        index: &mut BufferedSink<W>,
        object: &mut dyn Writer,
        field: &mut Intent<Box<dyn Store>>,
    ) -> Stream {
        field.strategy.store(index, object);
        index.clear().unwrap()
    }

    fn load(
        &self,
        commits_for_field: TransactionList,
        pool: &Pool<AEADReader>,
        field: &mut Intent<Box<dyn Load>>,
    ) {
        field.strategy.load(pool.clone(), commits_for_field);
    }

    fn select<K>(
        &self,
        commits_for_field: TransactionList,
        pool: &Pool<AEADReader>,
        mut field: Intent<Box<impl Query<Key = K>>>,
        pred: impl Fn(&K) -> QueryAction,
    ) {
        field.strategy.select(pool.clone(), commits_for_field, pred);
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{crypto::Digest, fields::Strategy, index::*, ChunkPointer};

    #[macro_export]
    macro_rules! len_check_test {
        ( $t:ty, $strat:ty, $prep:expr, $len:expr ) => {
            paste::paste! {
                #[test]
                fn [<strategy_ $strat:snake>]() {
                    let store = $t::default();
                    let load = $t::default();
                    ($prep)(&store);

                    store_then_load($strat::for_field(&store), $strat::for_field(&load));

                    assert_eq!(($len)(load), ($len)(store));
                }
            }
        };
    }

    /// Will panic if the given argument can't be stored or loaded
    pub(crate) fn store_then_load<T: Send + Sync, S: Strategy<T> + Store + Load>(
        mut store: S,
        mut load: S,
    ) -> () {
        use crate::{backends, crypto, object::AEADWriter};
        use std::sync::Arc;

        let key = *b"abcdef1234567890abcdef1234567890";
        let crypto = crypto::symmetric08::ObjectOperations::chunks(key.into());
        let storage = Arc::new(backends::test::InMemoryBackend::default());

        let writer = || AEADWriter::new(storage.clone(), crypto::ChunkKey::new(crypto.clone()));
        let reader = {
            let storage = storage.clone();
            let crypto = crypto.clone();
            move || AEADReader::new(storage.clone(), crypto::ChunkKey::new(crypto.clone()))
        };

        let object = {
            let mut transaction = BufferedSink::new(writer());
            Store::store(&mut store, &mut transaction, &mut writer());
            transaction.finish().unwrap()
        };

        Load::load(
            &mut load,
            Pool::with_constructor(0, reader),
            vec![(CommitId::default(), "field name".into(), object)],
        );
    }

    #[test]
    fn can_deserialize_fields() {
        type ChunkMap = Map<Digest, ChunkPointer>;
        let store = ChunkMap::default();
        let load = ChunkMap::default();
        store.insert(Digest::default(), ChunkPointer::default());

        store_then_load(LocalField::for_field(&store), LocalField::for_field(&load));

        assert_eq!(load.len(), store.len());
    }
}
