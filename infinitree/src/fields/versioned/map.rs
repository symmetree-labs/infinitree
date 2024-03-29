//! A concurrent, incremental HashMap implementation
use super::{store, Action, RawAction};
use crate::{
    fields::{
        depth::Incremental, Collection, Intent, Key, Load, LocalField, SparseField, Store,
        Strategy, Value,
    },
    index::{FieldWriter, Transaction},
    object::{self, serializer::SizedPointer, ObjectError},
};
use scc::HashMap;
use std::{borrow::Borrow, hash::Hash, sync::Arc};

/// HashMap that tracks incremental changes between commits
///
/// Calling [`clone()`](VersionedMap::clone) will create a reference to the
/// same instance, and can be easily shared between threads.
///
/// To write to disk the entire content of a hash map on every commit,
/// see [`Map`](crate::fields::Map)
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
            None => self
                .current
                .entry(key)
                .or_default()
                .get_mut()
                .get_or_insert_with(|| new().into())
                .clone(),
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
    pub fn update_with<T: Into<Arc<V>>>(
        &self,
        key: K,
        update: impl FnOnce(Arc<V>) -> T,
    ) -> Action<V> {
        match self.get(&key) {
            Some(existing) => {
                let mut entry = self.current.entry(key).or_default();
                let current = entry.get_mut();
                *current = Some(update(existing.clone()).into());
                current.clone()
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
            self.current.entry(key).or_default().insert(None);
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
        let mut current = self.base.first_entry();
        while let Some(entry) = current {
            let Some(v) = entry.get() else {
                current = entry.next();
                continue;
            };

            // This is either a deletion or a new value.
            // Either way, not interested in this round.
            if !self.current.contains(entry.key()) {
                (callback)(entry.key(), Arc::as_ref(v));
            }

            current = entry.next();
        }

        current = self.current.first_entry();
        while let Some(entry) = current {
            if let Some(value) = entry.get() {
                (callback)(entry.key(), Arc::as_ref(value));
            }
            current = entry.next();
        }
    }

    /// Mark values as deleted where `callback` returns `false`
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
    /// m.retain(|k, v| false);
    /// assert_eq!(m.contains(&1), false);
    /// ```
    #[inline(always)]
    pub fn retain(&self, mut callback: impl FnMut(&K, &V) -> bool) {
        let mut current = self.base.first_entry();
        while let Some(entry) = current {
            let Some(v) = entry.get() else {
                current = entry.next();
                continue;
            };
            let key = entry.key();

            // If the value is in the base, we'll need to modify
            // current anyway, so may as well decide here.
            let retain = if let Some(new_v) = self.current.get(key).and_then(|e| e.get().clone()) {
                (callback)(key, Arc::as_ref(&new_v))
            } else {
                (callback)(key, Arc::as_ref(v))
            };

            if !retain {
                *self.current.entry(key.clone()).or_default().get_mut() = None;
            }

            current = entry.next();
        }

        current = self.current.first_entry();
        while let Some(mut entry) = current {
            // the base loop would have visited this, so we can skip (or if deletion)
            if self.base.contains(entry.key()) || entry.get().is_none() {
                current = entry.next();
                continue;
            }

            if !(callback)(
                entry.key(),
                Arc::as_ref(entry.get().as_ref().expect("checked above")),
            ) {
                *entry.get_mut() = None;
            }

            current = entry.next();
        }
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
                *self.base.entry(k.clone()).or_default().get_mut() = v.clone();
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

        let mut current = self.current.first_entry();
        while let Some(e) = current {
            match e.get() {
                Some(_) => stored += 1,

                // None implies it's Some() in `self.base` due to `remove()` semantics
                None => stored -= 1,
            }

            current = e.next();
        }

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
    /// m.clear();
    ///
    /// assert_eq!(m.len(), 0);
    /// assert_eq!(m.size(), 0);
    /// assert_eq!(m.is_empty(), true);
    /// ```
    #[inline(always)]
    pub fn clear(&self) {
        self.base.clear();
        self.current.clear();
    }

    /// Roll back all modification since the last commit
    ///
    /// Calling `rollback` also frees up memory dynamically.
    ///
    /// # Examples
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
    /// m.rollback();
    ///
    /// assert_eq!(m.len(), 1);
    /// assert_eq!(m.size(), 1);
    /// assert_eq!(m.is_empty(), false);
    #[inline(always)]
    pub fn rollback(&self) {
        self.current.clear();
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

impl<K, V> Collection for VersionedMap<K, V>
where
    K: Key,
    V: Value,
{
    type Depth = Incremental;
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
        // we're optimizing for the case where the versions are
        // restored from top to bottom, in reverse order.
        // therefore:
        // 1. do not insert a key if it already exists
        // 2. do not restore a removed key
        let _ = self.base.insert(record.0, record.1);
    }
}

impl<K, V> Store for VersionedMap<K, V>
where
    K: Key + Clone,
    V: Value,
{
    #[inline(always)]
    fn store(&mut self, mut transaction: &mut dyn Transaction, _object: &mut dyn object::Writer) {
        let mut current = self.current.first_entry();
        while let Some(e) = current {
            transaction.write_next((e.key(), e.get()));
            current = e.next();
        }

        self.commit();
    }
}

impl<K, V> Collection for SparseField<VersionedMap<K, V>>
where
    K: Key,
    V: Value,
{
    type Depth = Incremental;
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
        let _ = self.field.base.insert(record.0, record.1);
    }
}

impl<K, V> Store for SparseField<VersionedMap<K, V>>
where
    K: Key + Clone,
    V: Value,
{
    #[inline(always)]
    fn store(&mut self, mut transaction: &mut dyn Transaction, writer: &mut dyn object::Writer) {
        let mut current = self.field.current.first_entry();
        while let Some(entry) = current {
            let key = entry.key();
            let value = entry.get();

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
            current = entry.next();
        }

        self.field.commit();
    }
}

impl<K, V> crate::Index for VersionedMap<K, V>
where
    K: Key + Clone,
    V: Value,
{
    fn store_all(&self) -> anyhow::Result<Vec<Intent<Box<dyn Store>>>> {
        Ok(vec![Intent::new(
            "root",
            Box::new(LocalField::for_field(self)),
        )])
    }

    fn load_all(&self) -> anyhow::Result<Vec<Intent<Box<dyn Load>>>> {
        Ok(vec![Intent::new(
            "root",
            Box::new(LocalField::for_field(self)),
        )])
    }
}

#[cfg(test)]
mod test {
    use super::VersionedMap;
    use crate::{
        crypto::UsernamePassword,
        fields::{LocalField, SparseField, Strategy},
        index::test::store_then_load,
        Infinitree,
    };

    #[test]
    fn bare_index_can_be_restored() {
        let key = || {
            UsernamePassword::with_credentials("bare_index_map".to_string(), "password".to_string())
                .unwrap()
        };
        let storage = crate::backends::test::InMemoryBackend::shared();

        {
            let tree =
                Infinitree::<VersionedMap<usize, usize>>::empty(storage.clone(), key()).unwrap();
            tree.index().insert(1000, 1000);
            tree.commit(None).unwrap();
            tree.index().clear();

            for i in 0..100 {
                tree.index().insert(i, i + 1);
            }

            tree.commit(None).unwrap();
        }

        let tree = Infinitree::<VersionedMap<usize, usize>>::open(storage, key()).unwrap();
        tree.load_all().unwrap();

        for i in 0..100 {
            assert_eq!(i + 1, *tree.index().get(&i).unwrap());
        }

        assert_eq!(tree.index().len(), 101);
    }

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
        assert!(m.contains(&1));
        assert!(m.contains(&2));

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

        assert!(m.is_empty());

        let _ = m.insert(1, value.clone());

        assert_eq!(m.len(), 1);
        assert_eq!(m.size(), 1);
        assert!(!m.is_empty());

        m.commit();

        assert_eq!(m.get(&1), Some(value.into()));
        assert!(m.contains(&1));

        m.remove(1);

        assert_eq!(m.get(&1), None);
        assert!(!m.contains(&1));

        assert_eq!(m.len(), 0);
        assert_eq!(m.size(), 2);
        assert!(m.is_empty());

        m.clear();

        assert_eq!(m.len(), 0);
        assert_eq!(m.size(), 0);
        assert!(m.is_empty());
    }

    type TestMap = VersionedMap<usize, String>;
    fn init_map(store: &TestMap) {
        store.insert(1, "one".to_owned());
        store.insert(2, "two".to_owned());
    }
    crate::len_check_test!(TestMap, LocalField, init_map, |m: TestMap| m.len());
    crate::len_check_test!(TestMap, SparseField, init_map, |m: TestMap| m.len());
}
