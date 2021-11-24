use super::{store, Action, RawAction};
use crate::{
    fields::{self, Collection, Key, LocalField, SparseField, Store, Value},
    index::{writer, FieldWriter},
    object::{self, serializer::SizedPointer, ObjectError},
};
use scc::HashMap;
use std::{borrow::Borrow, cell::Cell, hash::Hash, sync::Arc};

pub struct VersionedMap<K, V>
where
    K: Key + 'static,
    V: Value + 'static,
{
    current: Arc<HashMap<K, Action<V>>>,
    base: Arc<HashMap<K, Action<V>>>,
}

impl<K, V> Clone for VersionedMap<K, V>
where
    K: Key + 'static,
    V: Value + 'static,
{
    fn clone(&self) -> Self {
        VersionedMap {
            base: self.base.clone(),
            current: self.current.clone(),
        }
    }
}

impl<K, V> Default for VersionedMap<K, V>
where
    K: Key + 'static,
    V: Value + 'static,
{
    fn default() -> Self {
        VersionedMap {
            base: Arc::default(),
            current: Arc::default(),
        }
    }
}

impl<K, V> VersionedMap<K, V>
where
    K: Key + Clone,
    V: Value,
{
    /// Set `key` to `value`.
    ///
    /// `insert` never overwrites existing values.
    ///
    /// Returns either the existing value, or the newly inserted value.
    ///
    /// It is equivalent to calling `map.insert_with(key, move || value)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    /// assert_eq!(m.insert(1, "first".to_owned()), "first".to_owned().into());
    /// assert_eq!(m.insert(1, "second".to_owned()), "first".to_owned().into());
    /// ```
    #[inline(always)]
    pub fn insert(&self, key: K, value: impl Into<Arc<V>>) -> Arc<V> {
        self.insert_with(key, move || value)
    }

    /// Set `key` to the value returned by `new`.
    ///
    /// `insert` never overwrites existing values.
    ///
    /// Returns either the existing value, or the newly inserted value.
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    /// assert_eq!(m.insert_with(1, || "first".to_owned()), "first".to_owned().into());
    /// assert_eq!(m.insert_with(1, || "second".to_owned()), "first".to_owned().into());
    /// ```
    #[inline(always)]
    pub fn insert_with<T: Into<Arc<V>>, F: FnOnce() -> T>(&self, key: K, new: F) -> Arc<V> {
        match self.get(&key) {
            Some(v) => v,
            None => {
                let new = Arc::new(Cell::new(Some(new)));
                let result = Cell::new(None);

                self.current.upsert(
                    key,
                    || {
                        let val = store(new.take().unwrap()());
                        result.set(val.clone());
                        val
                    },
                    |_, v| {
                        v.get_or_insert_with(|| new.take().unwrap()().into());
                        result.set(v.clone());
                    },
                );

                // this will never panic, because callbacks guarantee it ends up being Some()
                result.into_inner().unwrap()
            }
        }
    }

    /// Update the value in `key` to the one returned by the `update` closure.
    ///
    /// `update_with` will never insert a new value to the map.
    ///
    /// Returns the update value, or None if `key` does not exist in the map.
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// assert_eq!(m.update_with(1, |_| "first".to_owned()), None);
    ///
    /// m.insert(1, "first".to_owned());
    ///
    /// assert_eq!(m.update_with(1, |_| "second".to_owned()), Some("second".to_owned().into()));
    /// ```
    #[inline(always)]
    pub fn update_with(&self, key: K, update: impl FnOnce(Arc<V>) -> V) -> Action<V> {
        match self.get(&key) {
            Some(existing) => {
                let result = Cell::new(None);
                let update = Arc::new(Cell::new(Some(update)));

                self.current.upsert(
                    key,
                    || {
                        let val = store(update.take().unwrap()(existing.clone()));
                        result.set(val.clone());
                        val
                    },
                    |_, v| {
                        *v = store(update.take().unwrap()(v.as_ref().unwrap().clone()));
                        result.set(v.clone())
                    },
                );

                // this will never panic, because callbacks guarantee it ends up being Some()
                result.into_inner()
            }
            None => None,
        }
    }

    /// Returns the stored value for a key, or `None`
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// assert_eq!(m.get(&1), None);
    ///
    /// m.insert(1, "first".to_owned());
    /// assert_eq!(m.get(&1), Some("first".to_owned().into()));
    /// ```
    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<Arc<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.current
            .read(key, |_, v| v.clone())
            .or_else(|| self.base.read(key, |_, v| v.clone()))
            .flatten()
    }

    /// Sets the key as removed in the map
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// m.insert(1, "first".to_owned());
    /// assert_eq!(m.get(&1), Some("first".to_owned().into()));
    ///
    /// m.remove(1);
    /// assert_eq!(m.get(&1), None);
    /// ```
    #[inline(always)]
    pub fn remove(&self, key: K) {
        if self.contains(&key) {
            self.current
                .upsert(key, || Action::None, |_, v| *v = Action::None)
        }
    }

    /// Returns `true` if there's an addition for the specified key
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// assert_eq!(m.contains(&1), false);
    /// m.insert(1, "first".to_owned());
    ///
    /// assert_eq!(m.contains(&1), true);
    /// ```
    #[inline(always)]
    pub fn contains(&self, key: &K) -> bool {
        let contained = self
            .current
            .read(key, |_, v| v.is_some())
            .or_else(|| self.base.read(key, |_, v| v.is_some()));

        contained.unwrap_or(false)
    }

    /// Call the function for all additive keys
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// m.insert(1, "first".to_owned());
    ///
    /// m.for_each(|k, v| {
    ///     assert_eq!(v, &"first".to_owned());
    /// });
    /// ```
    #[inline(always)]
    pub fn for_each(&self, mut callback: impl FnMut(&K, &V)) {
        // note: this is copy-pasta, because the closures have
        // different lifetimes.
        //
        // if you have a good idea how to avoid
        // using a macro and just do this, please send a PR

        self.base.for_each(|k, v: &mut Action<V>| {
            if let Some(value) = v {
                (callback)(k, Arc::as_ref(value));
            }
        });
        self.current.for_each(|k, v: &mut Action<V>| {
            if let Some(value) = v {
                (callback)(k, Arc::as_ref(value));
            }
        });
    }

    /// Clear out the current changeset, and commit all changes to history.
    ///
    /// This operation potentially helps free some memory, but more
    /// importantly any subsequent `Store` calls are going to be empty
    /// until further additions or removals.
    pub fn commit(&self) {
        self.current.retain(|k, v| {
            // if the base doesn't have the key, and we're not
            // removing it
            if self.base.remove_if(k, |_v_base| v.is_none()).is_none() {
                // then make sure we store the new value
                //
                // cloning the value is safe and cheap, because
                // it's always an Option<Arc<V>>
                self.base
                    .upsert(k.clone(), || v.clone(), |_, v| *v = v.clone());
            }

            false
        });
    }

    /// Returns the number of additive keys
    ///
    /// See [`VersionedMap::clear`] for example use.
    #[inline(always)]
    pub fn len(&self) -> usize {
        let mut stored = self.base.len();

        self.current.for_each(|_, v| {
            match v {
                Some(_) => stored += 1,

                // None implies it's Some() in `self.base` due to `remove()` semantics
                None => stored -= 1,
            }
        });

        stored
    }

    /// Returns the number of all keys, including deletions
    ///
    /// See [`VersionedMap::clear`] for example use.
    #[inline(always)]
    pub fn size(&self) -> usize {
        self.base.len() + self.current.len()
    }

    /// Return the size of all allocated items
    ///
    /// See [`VersionedMap::clear`] for example use.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.base.capacity() + self.current.capacity()
    }

    /// Free all items in the VersionedMap, _without_ tracking changes
    ///
    /// Returns the number of elements freed.
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::VersionedMap;
    ///
    /// let value = "first".to_owned();
    /// let m = VersionedMap::<usize, String>::default();
    ///
    /// assert_eq!(m.is_empty(), true);
    ///
    /// let _ = m.insert(1, value.clone());
    ///
    /// assert_eq!(m.len(), 1);
    /// assert_eq!(m.size(), 1);
    /// assert_eq!(m.is_empty(), false);
    ///
    /// m.commit();
    ///
    /// assert_eq!(m.contains(&1), true);
    ///
    /// assert_eq!(m.len(), 1);
    /// assert_eq!(m.size(), 1);
    /// assert_eq!(m.is_empty(), false);
    ///
    /// m.remove(1);
    ///
    /// assert_eq!(m.contains(&1), false);
    ///
    /// assert_eq!(m.len(), 0);
    /// assert_eq!(m.size(), 2);
    /// assert_eq!(m.is_empty(), true);
    ///
    /// // Call `clear()`
    /// assert_eq!(m.clear(), 2);
    ///
    /// assert_eq!(m.len(), 0);
    /// assert_eq!(m.size(), 0);
    /// assert_eq!(m.is_empty(), true);
    /// ```
    #[inline(always)]
    pub fn clear(&self) -> usize {
        self.base.clear() + self.current.clear()
    }

    /// True if the number of additions to the map is zero
    ///
    /// Since `VersionedMap` is tracking _changes_, `is_empty()` may
    /// return `true` even if a non-zero amount of memory is being
    /// used.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K, V> Collection for LocalField<VersionedMap<K, V>>
where
    K: Key,
    V: Value,
{
    type TransactionResolver = fields::FullHistory;
    type Key = K;
    type Serialized = (K, Action<V>);
    type Item = (K, Action<V>);

    #[inline(always)]
    fn key(from: &Self::Serialized) -> &Self::Key {
        &from.0
    }

    #[inline(always)]
    fn load(from: Self::Serialized, _object: &mut dyn crate::object::Reader) -> Self::Item {
        from
    }

    #[inline(always)]
    fn insert(&mut self, record: Self::Item) {
        debug_assert!(self.field.base.insert(record.0, record.1).is_ok());
    }
}

impl<K, V> Store for LocalField<VersionedMap<K, V>>
where
    K: Key + Clone,
    V: Value,
{
    #[inline(always)]
    fn store(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        _object: &mut dyn object::Writer,
    ) {
        self.field.current.for_each(|k, v| {
            transaction.write_next((k, v));
        });

        self.field.commit();
    }
}

impl<K, V> Collection for SparseField<VersionedMap<K, V>>
where
    K: Key,
    V: Value,
{
    type TransactionResolver = fields::FullHistory;
    type Key = K;
    type Serialized = (K, RawAction<SizedPointer>);
    type Item = (K, Action<V>);

    #[inline(always)]
    fn key(from: &Self::Serialized) -> &Self::Key {
        &from.0
    }

    #[inline(always)]
    fn load(from: Self::Serialized, object: &mut dyn object::Reader) -> Self::Item {
        let value = match from.1 {
            Some(ptr) => {
                let value: V = object::serializer::read(
                    object,
                    |x| {
                        crate::deserialize_from_slice(x).map_err(|e| ObjectError::Deserialize {
                            source: Box::new(e),
                        })
                    },
                    ptr,
                )
                .unwrap();

                store(value)
            }
            None => None,
        };

        (from.0, value)
    }

    #[inline(always)]
    fn insert(&mut self, record: Self::Item) {
        // we're optimizing for the case where the versions are
        // restored from top to bottom, in reverse order.
        // therefore:
        // 1. do not insert a key if it already exists
        // 2. do not restore a removed key
        if let value @ Some(..) = record.1 {
            let _ = self.field.base.insert(record.0, value);
        }
    }
}

impl<K, V> Store for SparseField<VersionedMap<K, V>>
where
    K: Key + Clone,
    V: Value,
{
    #[inline(always)]
    fn store(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        writer: &mut dyn object::Writer,
    ) {
        self.field.current.for_each(|key, value| {
            let ptr = value.as_ref().map(|stored| {
                object::serializer::write(
                    writer,
                    |x| {
                        crate::serialize_to_vec(&x).map_err(|e| ObjectError::Serialize {
                            source: Box::new(e),
                        })
                    },
                    stored,
                )
                .unwrap()
            });
            transaction.write_next((key, ptr));
        });

        self.field.commit();
    }
}

#[cfg(test)]
mod test {
    use super::VersionedMap;
    use crate::{
        fields::{LocalField, SparseField, Strategy},
        index::test::store_then_load,
    };

    #[test]
    fn duplicate_insert_is_noop() {
        let m = VersionedMap::<usize, String>::default();
        assert_eq!(m.insert(1, "first".to_owned()), "first".to_owned().into());
        assert_eq!(m.insert(1, "second".to_owned()), "first".to_owned().into());
    }

    #[test]
    fn updating_empty_is_noop() {
        let m = VersionedMap::<usize, String>::default();
        assert_eq!(m.update_with(1, |_| "first".to_owned()), None);
    }

    #[test]
    fn store_then_confirm_then_remove() {
        let m = VersionedMap::<usize, String>::default();
        let first = "first".to_owned();
        let updated = "updated".to_owned();
        let second = "second".to_owned();

        // insert
        assert_eq!(m.insert_with(1, || first.clone()), first.clone().into());
        assert_eq!(m.insert_with(2, || second.clone()), second.clone().into());

        // get first
        assert_eq!(m.get(&1), Some(first.into()));

        // contains
        assert_eq!(m.contains(&1), true);
        assert_eq!(m.contains(&2), true);

        // update
        assert_eq!(
            m.update_with(1, |_| updated.clone()),
            Some(updated.clone().into())
        );
        assert_eq!(m.get(&1), Some(updated.into()));

        // removed
        m.remove(1);
        assert_eq!(m.get(&1), None);

        // second still fine
        assert_eq!(m.get(&2), Some(second.into()));
    }

    #[test]
    fn commit_then_confirm_then_lengths() {
        let value = "first".to_owned();
        let m = VersionedMap::<usize, String>::default();

        assert_eq!(m.is_empty(), true);

        let _ = m.insert(1, value.clone());

        assert_eq!(m.len(), 1);
        assert_eq!(m.size(), 1);
        assert_eq!(m.is_empty(), false);

        m.commit();

        assert_eq!(m.get(&1), Some(value.into()));
        assert_eq!(m.contains(&1), true);

        m.remove(1);

        assert_eq!(m.get(&1), None);
        assert_eq!(m.contains(&1), false);

        assert_eq!(m.len(), 0);
        assert_eq!(m.size(), 2);
        assert_eq!(m.is_empty(), true);

        m.clear();

        assert_eq!(m.len(), 0);
        assert_eq!(m.size(), 0);
        assert_eq!(m.is_empty(), true);
    }

    type TestMap = VersionedMap<usize, String>;
    fn init_map(store: &TestMap) {
        store.insert(1, "one".to_owned());
        store.insert(2, "two".to_owned());
    }
    crate::len_check_test!(TestMap, LocalField, init_map, |m: TestMap| m.len());
    crate::len_check_test!(TestMap, SparseField, init_map, |m: TestMap| m.len());
}
