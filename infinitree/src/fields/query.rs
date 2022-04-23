use super::{Collection, FieldReader};
use crate::object;
use std::{marker::PhantomData, sync::Arc};

/// Result of a query predicate
pub enum QueryAction {
    /// Pull the current value into memory.
    Take,
    /// Skip the current value and deserialize the next one.
    Skip,
    /// Abort the query and _don't_ pull the current value to memory.
    Abort,
}

pub(crate) struct QueryIteratorOwned<T, Predicate, Reader, Transaction> {
    transaction: Transaction,
    object: Reader,
    predicate: Arc<Predicate>,
    _fieldtype: PhantomData<T>,
}

impl<T, K, R, F, FR> QueryIteratorOwned<T, F, R, FR>
where
    T: Collection<Key = K>,
    F: Fn(&K) -> QueryAction,
    FR: FieldReader,
    R: object::Reader,
{
    pub fn new(transaction: FR, object: R, predicate: Arc<F>, _field: &mut T) -> Self {
        Self {
            transaction,
            object,
            predicate,
            _fieldtype: PhantomData,
        }
    }
}

impl<T, K, R, F, FR> Iterator for QueryIteratorOwned<T, F, R, FR>
where
    T: Collection<Key = K>,
    F: Fn(&K) -> QueryAction,
    FR: FieldReader,
    R: object::Reader,
{
    type Item = <T as Collection>::Item;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(item) = self.transaction.read_next::<T::Serialized>() {
            use QueryAction::*;

            match (self.predicate)(T::key(&item)) {
                Take => return Some(T::load(item, &mut self.object)),
                Skip => continue,
                Abort => return None,
            }
        }

        None
    }
}

pub(crate) struct QueryIterator<'reader, T, Predicate, Transaction> {
    transaction: Transaction,
    object: &'reader mut dyn object::Reader,
    predicate: Arc<Predicate>,
    _fieldtype: PhantomData<T>,
}

impl<'reader, T, K, F, FR> QueryIterator<'reader, T, F, FR>
where
    T: Collection<Key = K>,
    F: Fn(&K) -> QueryAction,
    FR: FieldReader,
{
    pub fn new(
        transaction: FR,
        object: &'reader mut dyn object::Reader,
        predicate: Arc<F>,
        _field: &mut T,
    ) -> Self {
        Self {
            transaction,
            object,
            predicate,
            _fieldtype: PhantomData,
        }
    }
}

impl<'reader, T, K, F, FR> Iterator for QueryIterator<'reader, T, F, FR>
where
    T: Collection<Key = K>,
    F: Fn(&K) -> QueryAction,
    FR: FieldReader,
{
    type Item = <T as Collection>::Item;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(item) = self.transaction.read_next::<T::Serialized>() {
            use QueryAction::*;

            match (self.predicate)(T::key(&item)) {
                Take => return Some(T::load(item, self.object)),
                Skip => continue,
                Abort => return None,
            }
        }

        None
    }
}
