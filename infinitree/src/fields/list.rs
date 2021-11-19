use super::{Collection, FirstOnly, LocalField, Store, Value};
use crate::{
    index::{writer, FieldWriter},
    object,
};
use std::sync::Arc;

pub type List<T> = Arc<parking_lot::RwLock<Vec<T>>>;

impl<T> Store for LocalField<List<T>>
where
    T: Value,
{
    fn execute(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        _object: &mut dyn object::Writer,
    ) {
        for v in self.field.read().iter() {
            transaction.write_next(v);
        }
    }
}

impl<T> Collection for LocalField<List<T>>
where
    T: Value + Clone,
{
    type TransactionResolver = FirstOnly;

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
