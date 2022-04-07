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

use crate::index::{reader, TransactionList};

pub trait Depth: sealed::Sealed {
    fn resolve<'r, R: 'r + AsRef<reader::Reader>>(
        index: R,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = reader::Transaction> + 'r>;
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
fn full_history<'r>(
    index: impl AsRef<reader::Reader> + 'r,
    transactions: TransactionList,
) -> impl Iterator<Item = reader::Transaction> + 'r {
    transactions
        .into_iter()
        .filter_map(move |(_gen, field, objectid)| {
            index.as_ref().transaction(field, &objectid).ok()
        })
}

impl Depth for Incremental {
    #[inline(always)]
    fn resolve<'r, R: 'r + AsRef<reader::Reader>>(
        index: R,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = reader::Transaction> + 'r> {
        Box::new(full_history(index, transactions))
    }
}

impl Depth for Snapshot {
    #[inline(always)]
    fn resolve<'r, R: 'r + AsRef<reader::Reader>>(
        index: R,
        transactions: TransactionList,
    ) -> Box<dyn Iterator<Item = reader::Transaction> + 'r> {
        Box::new(full_history(index, transactions).take(1))
    }
}
