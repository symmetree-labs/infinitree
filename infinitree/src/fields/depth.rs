//! Transaction depth resolvers for custom [`Collection`](super::Collection) types.
//!
//! An index field can store either a snapshot of the field during serialization, or incremental
//! changes.
//!
//! The query engine needs to know how deep to look in the commit
//! history to accurately load an index field. These types help encode
//! meaningful transaction walks.
//!
//! Note that during queries and loads, commits are walked in _reverse
//! order_, last one first.

use crate::index::TransactionList;
use crate::object::{AEADReader, DeserializeStream, Pool};

pub trait Depth: sealed::Sealed {
    fn resolve(
        index: Pool<AEADReader>,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = DeserializeStream> + Sync + Send>;
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Incremental {}
    impl Sealed for super::Snapshot {}
}

/// Walk through the full history in reverse order. Useful for incremental types.
pub struct Incremental;

/// Only load the first (peak) commit in the list. Useful for snapshot types.
pub struct Snapshot;

#[inline(always)]
fn full_history(
    pool: Pool<AEADReader>,
    transactions: TransactionList,
) -> impl Iterator<Item = DeserializeStream> {
    transactions
        .into_iter()
        .filter_map(move |(_gen, _field, stream)| {
            pool.lease()
                .ok()
                .map(|r| DeserializeStream::new(stream.open_reader(r)))
        })
}

impl Depth for Incremental {
    #[inline(always)]
    fn resolve(
        index: Pool<AEADReader>,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = DeserializeStream> + Sync + Send> {
        Box::new(full_history(index, transactions))
    }
}

impl Depth for Snapshot {
    #[inline(always)]
    fn resolve(
        index: Pool<AEADReader>,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = DeserializeStream> + Sync + Send> {
        Box::new(full_history(index, transactions).take(1))
    }
}
