use super::{Collection, FieldReader};
use crate::object::{self, DeserializeStream};
use std::{marker::PhantomData, sync::Arc, hash::Hash};

/// Result of a query predicate
pub enum QueryAction {
    /// Pull the current value into memory.
    Take,
    /// Skip the current value and deserialize the next one.
    Skip,
    /// Abort the query and _don't_ pull the current value to memory.
    Abort,
}

pub(crate) struct KeyCachingIterator<T, K, Transactions, Predicate, Reader> where
    K: Eq + Hash,
{
    current: DeserializeStream,
    predicate: Arc<Predicate>,
    transactions: Transactions,
    reader: Reader,
    cache: scc::HashSet<K>,
    _fieldtype: PhantomData<T>,
}

impl<T, K, Transactions, Predicate, Reader> KeyCachingIterator<T, K, Transactions, Predicate, Reader>
where
    T: Collection<Key = K>,
    K: Eq + Hash,
    Transactions: Iterator<Item = DeserializeStream>,
    Predicate: Fn(&K) -> QueryAction,
    Reader: object::Reader,
{
    pub fn new(mut transactions: Transactions, reader: Reader, predicate: Predicate, _field: &mut T) -> Option<Self> {
	let current = transactions.next()?;
	
	Some(Self {
	    current,
	    transactions,
	    reader,
	    predicate: Arc::new(predicate),
	    cache: Default::default(),
	    _fieldtype: Default::default()
	})
    }
}

impl<T, O, K, Transactions, Predicate, Reader> Iterator for KeyCachingIterator<T, K, Transactions, Predicate, Reader>
where 
    T: Collection<Key = K, Item = O>,
    K: Eq + Hash + Clone,
    Transactions: Iterator<Item = DeserializeStream>,
    Predicate: Fn(&K) -> QueryAction,
    Reader: object::Reader,
{
    type Item = O;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
	loop {
	match self.current.read_next() {
	    Ok(item) => {
		use QueryAction::*;

		let key = T::key(&item);
		match (self.predicate)(key) {
                    Take => {
			if self.cache.contains(key) {
			    continue;
			} else {
				_ = self.cache.insert(key.clone());
				return Some(T::load(item, &mut self.reader))
			    }
		    },
                    Skip => continue,
                    Abort => return None,
		}
	    }
	    Err(_) => {
		match self.transactions.next() {
		    Some(next) => {
			self.current = next;
			continue;
		    },
		    None => {
			return None;
		    }
		}
	    }
	}
	}
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
