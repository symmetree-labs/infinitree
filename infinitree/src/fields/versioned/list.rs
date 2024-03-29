//! A concurrent, incremental linked list implementation
use crate::{
    fields::{
        depth::Incremental, Collection, Intent, Load, LocalField, SparseField, Store, Strategy,
        Value,
    },
    index::{FieldWriter, Transaction},
    object::{self, serializer::SizedPointer, ObjectError},
};
use scc::{
    ebr::{AtomicShared, Guard, Ptr, Shared, Tag},
    LinkedList as SCCLinkedList,
};
use std::{
    ops::Deref,
    sync::{atomic::Ordering, Arc},
};

#[derive(Clone, Default)]
pub struct Node<T: 'static>(AtomicShared<Node<T>>, T);
impl<T: 'static> SCCLinkedList for Node<T> {
    fn link_ref(&self) -> &AtomicShared<Node<T>> {
        &self.0
    }
}

#[allow(unused)]
impl<T: 'static> Node<T> {
    fn set_next(&self, next: Shared<Node<T>>, barrier: &Guard) {
        let _ = self.push_back(next, false, Ordering::Release, barrier);
    }

    fn insert(&self, value: impl Into<T>) {
        let barrier = Guard::new();
        self.set_next(
            Shared::new(Node(AtomicShared::null(), value.into())),
            &barrier,
        );
    }

    pub fn is_last(&self) -> bool {
        self.0.is_null(Ordering::Acquire)
    }

    fn next(&self) -> Option<Shared<Node<T>>> {
        let barrier = Guard::new();
        self.0.load(Ordering::Acquire, &barrier).get_shared()
    }
}

#[derive(Default)]
struct NodeIter<T: 'static> {
    current: Option<Shared<Node<Arc<T>>>>,
}

impl<T: 'static> Iterator for NodeIter<T> {
    type Item = Arc<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.current.as_ref().map(|node| node.1.clone());
        self.current = self.current.as_deref().and_then(Node::next);

        value
    }
}

impl<T: 'static> Deref for Node<Arc<T>> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.1.deref()
    }
}

struct LinkedListInner<T: 'static> {
    last: AtomicShared<Node<Arc<T>>>,
    commit_start: AtomicShared<Node<Arc<T>>>,
    previous_commit_last: AtomicShared<Node<Arc<T>>>,
    first: AtomicShared<Node<Arc<T>>>,
}

impl<T: 'static> Default for LinkedListInner<T> {
    fn default() -> Self {
        Self {
            last: AtomicShared::null(),
            commit_start: AtomicShared::null(),
            previous_commit_last: AtomicShared::null(),
            first: AtomicShared::null(),
        }
    }
}

/// Append-only linked list that only commits incremental changes
#[derive(Clone)]
pub struct LinkedList<T: 'static> {
    inner: Shared<LinkedListInner<T>>,
}

impl<T: 'static> Default for LinkedList<T> {
    fn default() -> Self {
        Self {
            inner: Shared::new(LinkedListInner::default()),
        }
    }
}

impl<T: 'static> LinkedList<T> {
    /// Add a new item to the list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    /// list.push(123456);
    ///
    /// assert_eq!(list.last(), Some(123456.into()))
    ///
    /// ```
    pub fn push(&self, value: impl Into<Arc<T>>) {
        let node = Shared::new(Node(AtomicShared::default(), value.into()));
        let barrier = Guard::new();

        let _ = self
            .inner
            .commit_start
            .compare_exchange(
                Ptr::null(),
                (Some(node.clone()), Tag::None),
                Ordering::SeqCst,
                Ordering::Relaxed,
                &barrier,
            )
            .and_then(|_| {
                self.inner.first.compare_exchange(
                    Ptr::null(),
                    (Some(node.clone()), Tag::None),
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    &barrier,
                )
            });

        let barrier = Guard::new();
        let ptr = self.inner.last.load(Ordering::Acquire, &barrier);
        self.inner
            .last
            .swap((Some(node.clone()), Tag::None), Ordering::Release);

        if let Some(ptr) = ptr.as_ref() {
            ptr.set_next(node, &barrier);
        }
    }

    /// Gets the first item of the current commit
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    ///
    /// list.push(123456);
    /// assert_eq!(list.first_in_commit(), Some(123456.into()));

    ///
    /// list.push(111111);
    /// assert_eq!(list.first_in_commit(), Some(123456.into()));
    ///
    /// list.commit();
    /// assert_eq!(list.first_in_commit(), None);
    ///
    /// list.push(654321);
    /// assert_eq!(list.first_in_commit(), Some(654321.into()));
    ///
    /// ```
    pub fn first_in_commit(&self) -> Option<Arc<T>> {
        let barrier = Guard::new();
        self.inner
            .commit_start
            .load(Ordering::Acquire, &barrier)
            .as_ref()
            .map(|node| node.1.clone())
    }

    /// Gets the first item of the linked list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    /// list.push(123456);
    ///
    /// assert_eq!(list.first(), Some(123456.into()));
    ///
    /// list.push(111111);
    ///
    /// assert_eq!(list.first(), Some(123456.into()));
    /// ```
    pub fn first(&self) -> Option<Arc<T>> {
        let barrier = Guard::new();
        self.inner
            .first
            .load(Ordering::Acquire, &barrier)
            .as_ref()
            .map(|node| node.1.clone())
    }

    /// Gets the last item of the linked list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    ///
    /// list.push(123456);
    /// assert_eq!(list.last(), Some(123456.into()));
    ///
    /// list.push(111111);
    /// assert_eq!(list.last(), Some(111111.into()));
    /// ```
    pub fn last(&self) -> Option<Arc<T>> {
        let barrier = Guard::new();
        self.inner
            .last
            .load(Ordering::Acquire, &barrier)
            .as_ref()
            .map(|node| node.1.clone())
    }

    /// Move the commit pointer to the last item in the list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    ///
    /// list.push(123456);
    /// assert_eq!(list.first_in_commit(), Some(123456.into()));
    ///
    /// list.push(111111);
    /// assert_eq!(list.first_in_commit(), Some(123456.into()));
    ///
    /// list.commit();
    /// assert_eq!(list.first_in_commit(), None);
    ///
    /// list.push(654321);
    /// assert_eq!(list.first_in_commit(), Some(654321.into()));
    /// ```
    pub fn commit(&self) {
        let barrier = Guard::new();
        let last = self
            .inner
            .last
            .load(Ordering::SeqCst, &barrier)
            .get_shared();
        self.inner
            .commit_start
            .swap((None, Tag::None), Ordering::SeqCst);
        self.inner
            .previous_commit_last
            .swap((last, Tag::None), Ordering::SeqCst);
    }

    /// Move the commit pointer to the last item in the list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    ///
    /// list.push(123456);
    /// list.push(111111);
    /// list.commit();
    /// list.push(654321);
    /// assert_eq!(list.first_in_commit(), Some(654321.into()));
    /// assert_eq!(list.last(), Some(654321.into()));
    /// assert_eq!(list.first(), Some(123456.into()));
    ///
    /// list.clear();
    /// assert_eq!(list.first_in_commit(), None);
    /// assert_eq!(list.first(),None);
    /// assert_eq!(list.last(), None);
    /// ```
    pub fn clear(&self) {
        self.inner.first.swap((None, Tag::None), Ordering::SeqCst);
        self.inner
            .commit_start
            .swap((None, Tag::None), Ordering::SeqCst);
        self.inner
            .previous_commit_last
            .swap((None, Tag::None), Ordering::SeqCst);
        self.inner.last.swap((None, Tag::None), Ordering::SeqCst);
    }

    /// Move the commit pointer to the last item in the list
    ///
    /// # Examples
    ///
    /// ```
    /// use infinitree::fields::LinkedList;
    ///
    /// let list = LinkedList::default();
    ///
    /// list.push(123456);
    /// list.push(111111);
    /// list.commit();
    /// list.push(654321);
    /// assert_eq!(list.first_in_commit(), Some(654321.into()));
    /// assert_eq!(list.last(), Some(654321.into()));
    /// assert_eq!(list.first(), Some(123456.into()));
    ///
    /// list.rollback();
    /// assert_eq!(list.first_in_commit(), None);
    /// assert_eq!(list.first(), Some(123456.into()));
    /// assert_eq!(list.last(), Some(111111.into()));
    /// ```
    pub fn rollback(&self) {
        let barrier = Guard::new();
        let last = self
            .inner
            .previous_commit_last
            .load(Ordering::SeqCst, &barrier)
            .get_shared();
        self.inner.last.swap((last, Tag::None), Ordering::SeqCst);
        self.inner
            .commit_start
            .swap((None, Tag::None), Ordering::SeqCst);
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<T>> {
        let barrier = Guard::new();
        NodeIter {
            current: self
                .inner
                .first
                .load(Ordering::Acquire, &barrier)
                .get_shared(),
        }
    }
}

impl<T> Store for LocalField<LinkedList<T>>
where
    T: Value,
{
    fn store(&mut self, mut transaction: &mut dyn Transaction, _object: &mut dyn object::Writer) {
        for v in self.field.iter() {
            transaction.write_next(v);
        }

        self.field.commit();
    }
}

impl<T> Collection for LocalField<LinkedList<T>>
where
    T: Value + Clone,
{
    type Depth = Incremental;
    type Key = T;
    type Serialized = T;
    type Item = T;

    fn key(from: &Self::Serialized) -> &Self::Key {
        from
    }

    fn load(from: Self::Serialized, _object: &mut dyn object::Reader) -> Self::Item {
        from
    }

    fn insert(&mut self, record: Self::Item) {
        self.field.push(record);
    }
}

impl<T> Store for SparseField<LinkedList<T>>
where
    T: Value,
{
    fn store(&mut self, mut transaction: &mut dyn Transaction, writer: &mut dyn object::Writer) {
        for v in self.field.iter() {
            let ptr = object::serializer::write(
                writer,
                |x| {
                    crate::serialize_to_vec(&x).map_err(|e| ObjectError::Serialize {
                        source: Box::new(e),
                    })
                },
                v,
            )
            .unwrap();

            transaction.write_next(ptr);
        }

        self.field.commit();
    }
}

impl<T> Collection for SparseField<LinkedList<T>>
where
    T: Value + Clone,
{
    type Depth = Incremental;
    type Key = SizedPointer;
    type Serialized = SizedPointer;
    type Item = T;

    fn key(from: &Self::Serialized) -> &Self::Key {
        from
    }

    fn load(from: Self::Serialized, object: &mut dyn object::Reader) -> Self::Item {
        object::serializer::read(
            object,
            |x| {
                crate::deserialize_from_slice(x).map_err(|e| ObjectError::Deserialize {
                    source: Box::new(e),
                })
            },
            from,
        )
        .unwrap()
    }

    fn insert(&mut self, record: Self::Item) {
        self.field.push(record);
    }
}

impl<T> crate::Index for LinkedList<T>
where
    T: 'static + Value + Clone,
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
    use super::LinkedList;
    use crate::{
        fields::{LocalField, SparseField, Strategy},
        index::test::store_then_load,
    };

    type TestList = LinkedList<usize>;
    fn init_list(store: &TestList) {
        store.push(123454321);
        store.push(123456791);
        store.commit();
        store.push(123456790);
        store.push(987654321);
        assert_eq!(store.iter().count(), 4);
    }

    crate::len_check_test!(TestList, LocalField, init_list, |l: TestList| {
        let mut x = 0;
        for _ in l.iter() {
            x += 1;
        }
        x
    });
    crate::len_check_test!(TestList, SparseField, init_list, |l: TestList| {
        let mut x = 0;
        for _ in l.iter() {
            x += 1;
        }
        x
    });
}
