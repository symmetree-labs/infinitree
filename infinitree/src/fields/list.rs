use super::{
    depth::Snapshot, Collection, Intent, Load, LocalField, SparseField, Store, Strategy, Value,
};
use crate::{
    index::{FieldWriter, Transaction},
    object::{self, serializer::SizedPointer, ObjectError},
};
use std::sync::Arc;

/// Shortcut to `Arc<RwLock<Vec<T>>>`, that can be used in an [`Index`](crate::Index)
///
/// This type supports all Index operations, and can be used with both
/// [`LocalField`] and [`SparseField`] serialization strategies.
pub type List<T> = Arc<parking_lot::RwLock<Vec<T>>>;

impl<T> Store for LocalField<List<T>>
where
    T: Value,
{
    fn store(&mut self, mut transaction: &mut dyn Transaction, _object: &mut dyn object::Writer) {
        for v in self.field.read().iter() {
            transaction.write_next(v);
        }
    }
}

impl<T> Collection for LocalField<List<T>>
where
    T: Value + Clone,
{
    type Depth = Snapshot;
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
        self.field.write().push(record);
    }
}

impl<T> Store for SparseField<List<T>>
where
    T: Value,
{
    fn store(&mut self, mut transaction: &mut dyn Transaction, writer: &mut dyn object::Writer) {
        for v in self.field.read().iter() {
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

impl<T> Collection for SparseField<List<T>>
where
    T: Value + Clone,
{
    type Depth = Snapshot;
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
        self.field.write().push(record);
    }
}

impl<T> crate::Index for List<T>
where
    T: 'static + Value + Clone,
{
    fn store_all(&mut self) -> anyhow::Result<Vec<Intent<Box<dyn Store>>>> {
        Ok(vec![Intent::new(
            "root",
            Box::new(LocalField::for_field(self)),
        )])
    }

    fn load_all(&mut self) -> anyhow::Result<Vec<Intent<Box<dyn Load>>>> {
        Ok(vec![Intent::new(
            "root",
            Box::new(LocalField::for_field(self)),
        )])
    }
}

#[cfg(test)]
mod test {
    use super::List;
    use crate::{
        fields::{LocalField, SparseField, Strategy},
        index::test::store_then_load,
    };

    type TestList = List<usize>;
    fn init_list(store: &TestList) {
        store.write().push(123456790);
        store.write().push(987654321);
    }
    crate::len_check_test!(TestList, LocalField, init_list, |l: TestList| l
        .read()
        .len());
    crate::len_check_test!(TestList, SparseField, init_list, |l: TestList| l
        .read()
        .len());
}
