//! Traits and implementations for working with index members.
//!
//! There are 3 ways to interact with an index field:
//!
//!  - [`Store`]: Store the field into the index.
//!  - [`Query`]: Query the field and load selected values into memory.
//!  - [`Load`]: Load all contents of the field into memory.
//!
//! To implement how a field is actually stored in the index, we
//! define an access [`Strategy`]. Currently 2 access strategies are
//! implemented in Infinitree, but the storage system is extensible.
//!
//!  - [`SparseField`]: Store the key in the index, but the value in
//!  the object store
//!  - [`LocalField`]: Store both the key and the value in the index.
//!
//! Additionally, `infinitree` can work with "snapshot" or
//! "incremental" fields. This [`depth`] of the field will determine its
//! behaviour during [`Load`] or [`Query`] operation.
//!
//! This is a detail that you need to be aware
//! of when designing your indexes, but the implementation details are
//! only relevant if you intend to write your own field type.
//!
//!  - [`Incremental`](depth::Incremental): The entire
//! commit list will be traversed, typically useful for incremental collection types.
//!  - [`Snapshot`](depth::Snapshot): Only the last commit is visited,
//! restoring a point-in-time snapshot of the contents.
//!
//! To learn more about index internals, see the module documentation
//! in the [`index`](super) module.

use crate::{
    index::{FieldReader, TransactionList},
    object::{self, AEADReader, Pool},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{cmp::Eq, hash::Hash, sync::Arc};

/// Marker trait for values that can be serialized and used as a
/// value for an index field
///
/// You should generally not implement this trait as a blanket
/// implementation will cover all types that conform.
pub trait Value: Serialize + DeserializeOwned + Send + Sync {}

/// Marker trait for value that can be used as a key in an index
///
/// You should generally not implement this trait as a blanket
/// implementation will cover all types that conform.
pub trait Key: Serialize + DeserializeOwned + Eq + Hash + Send + Sync {}

impl<T> Value for T where T: Serialize + DeserializeOwned + Send + Sync {}
impl<T> Key for T where T: Serialize + DeserializeOwned + Eq + Hash + Send + Sync {}

mod map;
pub use map::Map;

mod list;
pub use list::List;

// mod set;
// pub use set::Set;

mod query;
pub use query::*;

mod serialized;
pub use serialized::Serialized;

mod versioned;
pub use versioned::list::LinkedList;
pub use versioned::map::VersionedMap;

pub mod depth;
use depth::Depth;

pub mod strategy;
#[allow(unused)]
pub(crate) use strategy::Strategy;
pub use strategy::{LocalField, SparseField};

pub mod intent;
pub use intent::{Intent, Load, Query, Store};

/// Query an index field, but do not automatically load it into memory
///
/// To allow lazily loading data from e.g. a [`SparseField`] when
/// relevant, a predicate is taken that controls the iterator.
///
/// This trait should be implemented on a type that also implements
/// [`Strategy`], and _not_ on the field directly.
pub trait Collection {
    /// Use this strategy to load the collection.
    ///
    /// Typically this will be one of two types:
    ///
    ///  * `Incremental` if a collection requires
    ///     crawling the full transaction history for an accurate
    ///     representation after loading.
    ///  * `Snapshot` if the collection is not versioned and
    ///     therefore there's no need to resolve the full the
    ///     transaction list.
    type Depth: Depth;

    /// The key that the predicate will use to decide whether to pull
    /// more data into memory.
    type Key;

    /// The serialized record format. This type will typically
    /// implement [`serde::Serialize`]
    type Serialized: DeserializeOwned;

    /// This is equivalent to `Iterator::Item`, and should contain a
    /// full record that can be inserted into the in-memory store.
    type Item;

    /// Get the key based on the deserialized data. You want this to
    /// be a reference that's easy to derive from the serialized data.
    fn key(from: &Self::Serialized) -> &Self::Key;

    /// Load the full record, and return it
    fn load(from: Self::Serialized, object: &mut dyn object::Reader) -> Self::Item;

    /// Store the deserialized record in the collection
    fn insert(&mut self, record: Self::Item);
}

impl<T> Query for T
where
    T: Collection,
{
    type Key = T::Key;

    fn select(
        &mut self,
        pool: Pool<AEADReader>,
        transaction_list: TransactionList,
        predicate: impl Fn(&Self::Key) -> QueryAction,
    ) {
        let predicate = Arc::new(predicate);
        let mut reader = pool.lease().unwrap();
        for transaction in T::Depth::resolve(pool, transaction_list) {
            let iter = QueryIterator::new(transaction, &mut reader, predicate.clone(), self);
            for item in iter {
                self.insert(item);
            }
        }
    }
}
