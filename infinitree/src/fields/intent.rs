//! Intent to execute some operation on an [`Index`](crate::Index) field

use super::{query::QueryAction, LocalField};
use crate::{
    index::{Transaction, TransactionList},
    object::{self, AEADReader, Pool},
};

/// A wrapper to allow working with trait objects and `impl Trait`
/// types when accessing the index field.
#[non_exhaustive]
#[derive(Clone)]
pub struct Intent<T> {
    /// The stringy name of the field that's being accessed. This MUST
    /// be unique within the index.
    pub name: String,

    /// The strategy for the given access that's to be executed.
    pub strategy: T,
}

impl<T> Intent<T> {
    /// Create a new wrapper that binds a stringy field name to an
    /// access strategy
    #[inline(always)]
    pub fn new(name: impl AsRef<str>, strategy: T) -> Self {
        Intent {
            name: name.as_ref().to_string(),
            strategy,
        }
    }
}

impl<T: Store + 'static> From<Intent<Box<T>>> for Intent<Box<dyn Store>> {
    #[inline(always)]
    fn from(a: Intent<Box<T>>) -> Self {
        Intent {
            name: a.name,
            strategy: a.strategy,
        }
    }
}

impl<T: Load + 'static> From<Intent<Box<T>>> for Intent<Box<dyn Load>> {
    #[inline(always)]
    fn from(a: Intent<Box<T>>) -> Self {
        Intent {
            name: a.name,
            strategy: a.strategy,
        }
    }
}

/// Store data into the index.
///
/// This trait is usually implemented on a type that also implements
/// [`Strategy`](super::strategy::Strategy), and _not_ on the field directly.
pub trait Store {
    /// Store the contents of the field into the index. The field
    /// itself needs to track whether this should be a complete
    /// rewrite or an upsert.
    ///
    /// The `transaction` parameter is provided for strategies to
    /// store values in the index, while the `object` is to store
    /// values in the object pool.
    ///
    /// Typically, the [`ChunkPointer`][crate::ChunkPointer] values returned by `object`
    /// should be stored in the index.
    fn store(&mut self, transaction: &mut dyn Transaction, object: &mut dyn object::Writer);
}

impl<T: Store> Store for LocalField<T> {
    fn store(&mut self, transaction: &mut dyn Transaction, object: &mut dyn object::Writer) {
        self.field.store(transaction, object)
    }
}

/// Load all data from the index field into memory.
///
/// This trait is usually implemented on a type that also implements
/// [`Strategy`](super::strategy::Strategy), and _not_ on the field directly.
///
/// In addition, `Load` has a blanket implementation for all types
/// that implement [`Query`], so very likely you never have to
/// manually implement this yourself.
pub trait Load {
    /// Execute a load action.
    ///
    /// The `index` and `object` readers are provided to interact with
    /// the indexes and the object pool, respectively.
    ///
    /// `transaction_list` can contain any list of transactions that
    /// this loader should restore into memory.
    ///
    /// Note that this is decidedly not a type safe way to interact
    /// with a collection, and therefore it is recommended that
    /// `transaction_list` is prepared and sanitized for the field
    /// that's being restored.
    fn load(&mut self, pool: Pool<AEADReader>, transaction_list: TransactionList);
}

impl<K, T> Load for T
where
    T: Query<Key = K>,
{
    #[inline(always)]
    fn load(&mut self, pool: Pool<AEADReader>, transaction_list: TransactionList) {
        Query::select(self, pool, transaction_list, |_| QueryAction::Take)
    }
}

/// Load data into memory where a predicate indicates it's needed
///
/// This trait should be implemented on a type that also implements
/// [`Strategy`](super::strategy::Strategy), and _not_ on the field directly.
pub trait Query {
    /// The key that the predicate will use to decide whether to pull
    /// more data into memory.
    type Key;

    /// Load items into memory based on a predicate
    ///
    /// The `index` and `object` readers are provided to interact with
    /// the indexes and the object pool, respectively.
    ///
    /// `transaction_list` can contain any list of transactions that
    /// this loader should restore into memory.
    ///
    /// Note that this is decidedly not a type safe way to interact
    /// with a collection, and therefore it is recommended that
    /// `transaction_list` is prepared and sanitized for the field
    /// that's being restored.
    fn select(
        &mut self,
        pool: Pool<AEADReader>,
        transaction_list: TransactionList,
        predicate: impl Fn(&Self::Key) -> QueryAction,
    );
}
