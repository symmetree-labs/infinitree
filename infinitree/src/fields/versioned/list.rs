//! A concurrent, incremental linked list implementation
use crate::{
    fields::{self, Collection, LocalField, SparseField, Store, Value},
    index::{writer, FieldWriter},
    object::{self, serializer::SizedPointer, ObjectError},
};
use scc::{
    ebr::{Arc as SCCArc, AtomicArc, Barrier, Ptr, Tag},
    LinkedList as SCCLinkedList,
};
use std::{
    fmt::Display,
    ops::Deref,
    sync::{atomic::Ordering, Arc},
};

#[derive(Default)]
pub struct Node<T: 'static>(AtomicArc<Node<T>>, T);
impl<T: 'static> SCCLinkedList for Node<T> {
    fn link_ref(&self) -> &AtomicArc<Node<T>> {
        &self.0
    }
}

#[allow(unused)]
impl<T: 'static> Node<T> {
    fn set_next(&self, next: SCCArc<Node<T>>, barrier: &Barrier) {
        let _ = self.push_back(next, false, Ordering::Release, barrier);
    }

    fn insert(&self, value: impl Into<T>) {
        let barrier = Barrier::new();
        self.set_next(SCCArc::new(Node(AtomicArc::null(), value.into())), &barrier);
    }

    pub fn is_last(&self) -> bool {
        self.0.is_null(Ordering::Acquire)
    }

    fn next(&self) -> Option<SCCArc<Node<T>>> {
        let barrier = Barrier::new();
        self.0.load(Ordering::Acquire, &barrier).try_into_arc()
    }
}

#[derive(Default)]
struct NodeIter<T: 'static> {
    first: bool,
    current: Option<SCCArc<Node<Arc<T>>>>,
}

impl<T: 'static> Iterator for NodeIter<T> {
    type Item = Arc<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            return self.current.as_ref().map(|n| n.1.clone());
        }

        let next = self.current.as_ref().and_then(|n| n.next());
        match next {
            Some(ref node) => {
                self.current = next.clone();
                Some(node.1.clone())
            }
            None => None,
        }
    }
}

impl<T: 'static> Deref for Node<Arc<T>> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.1.deref()
    }
}

#[derive(Clone)]
pub struct LinkedList<T: 'static> {
    last: SCCArc<AtomicArc<Node<Arc<T>>>>,
    commit_start: SCCArc<AtomicArc<Node<Arc<T>>>>,
    previous_commit_last: SCCArc<AtomicArc<Node<Arc<T>>>>,
    first: SCCArc<AtomicArc<Node<Arc<T>>>>,
}

impl<T: 'static> Default for LinkedList<T> {
    fn default() -> Self {
        Self {
            last: SCCArc::new(AtomicArc::null()),
            commit_start: SCCArc::new(AtomicArc::null()),
            previous_commit_last: SCCArc::new(AtomicArc::null()),
            first: SCCArc::new(AtomicArc::null()),
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
        let node = SCCArc::new(Node(AtomicArc::default(), value.into()));

        let _ = self
            .commit_start
            .compare_exchange(
                Ptr::null(),
                (Some(node.clone()), Tag::None),
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .and_then(|_| {
                self.first.compare_exchange(
                    Ptr::null(),
                    (Some(node.clone()), Tag::None),
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
            });

        let barrier = Barrier::new();
        let ptr = self.last.load(Ordering::Acquire, &barrier);
        self.last
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
        let barrier = Barrier::new();
        self.commit_start
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
        let barrier = Barrier::new();
        self.first
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
        let barrier = Barrier::new();
        self.last
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
        let barrier = Barrier::new();
        let last = self.last.load(Ordering::SeqCst, &barrier).try_into_arc();
        self.commit_start.swap((None, Tag::None), Ordering::SeqCst);
        self.previous_commit_last
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
        self.first.swap((None, Tag::None), Ordering::SeqCst);
        self.commit_start.swap((None, Tag::None), Ordering::SeqCst);
        self.previous_commit_last
            .swap((None, Tag::None), Ordering::SeqCst);
        self.last.swap((None, Tag::None), Ordering::SeqCst);
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
        let barrier = Barrier::new();
        let last = self
            .previous_commit_last
            .load(Ordering::SeqCst, &barrier)
            .try_into_arc();
        self.last.swap((last, Tag::None), Ordering::SeqCst);
        self.commit_start.swap((None, Tag::None), Ordering::SeqCst);
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<T>> {
        let barrier = Barrier::new();
        NodeIter {
            first: true,
            current: self.first.load(Ordering::Acquire, &barrier).try_into_arc(),
        }
    }
}

impl<T> Store for LocalField<LinkedList<T>>
where
    T: Value,
{
    fn store(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        _object: &mut dyn object::Writer,
    ) {
        for v in self.field.iter() {
            transaction.write_next(v);
        }
    }
}

impl<T> Collection for LocalField<LinkedList<T>>
where
    T: Value + Clone,
{
    type TransactionResolver = fields::FullHistory;
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
    fn store(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        writer: &mut dyn object::Writer,
    ) {
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
    }
}

impl<T> Collection for SparseField<LinkedList<T>>
where
    T: Value + Clone,
{
    type TransactionResolver = fields::FullHistory;
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

#[cfg(test)]
mod test {
    use super::LinkedList;
    use crate::{
        fields::{LocalField, SparseField, Strategy},
        index::test::store_then_load,
    };

    type TestList = LinkedList<usize>;
    fn init_list(store: &TestList) {
        store.push(123456790);
        store.push(987654321);
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
