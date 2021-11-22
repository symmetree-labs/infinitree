use super::{FirstOnly, Load, LocalField, Store, TransactionResolver};
use crate::{
    index::{reader, writer, FieldReader, FieldWriter},
    object,
};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// A wrapper type that allows using any type that's serializable
/// using serde to be used as a member of the index.
///
/// This implementation is super simplistic, and will not optimize for
/// best performance. If you want something fancy, you are very likely
/// to want to implement your own serialization.
#[derive(Default, Clone)]
pub struct Serialized<T>(Arc<RwLock<T>>);

impl<T> Serialized<T> {
    pub fn read(&self) -> impl Deref<Target = T> + '_ {
        self.0.read()
    }

    pub fn write(&self) -> impl DerefMut<Target = T> + '_ {
        self.0.write()
    }
}

impl<T> From<T> for Serialized<T>
where
    T: Serialize + DeserializeOwned + Sync,
{
    fn from(original: T) -> Self {
        Serialized(Arc::new(original.into()))
    }
}

impl<T> Store for LocalField<Serialized<T>>
where
    T: Serialize + Sync,
{
    #[inline(always)]
    fn store(
        &mut self,
        transaction: &mut writer::Transaction<'_>,
        _object: &mut dyn object::Writer,
    ) {
        transaction.write_next(&*self.field.read());
    }
}

impl<T> Load for LocalField<Serialized<T>>
where
    T: DeserializeOwned,
{
    fn load(
        &mut self,
        index: &reader::Reader,
        _object: &mut dyn object::Reader,
        transaction_list: crate::index::TransactionList,
    ) {
        for mut transaction in FirstOnly::resolve(index, transaction_list) {
            *self.field.write() = transaction.read_next().unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::Serialized;
    use crate::fields::{LocalField, Strategy};

    #[test]
    fn strategy_local_field() {
        let store = Serialized::from(123456789);
        let load = Serialized::default();

        crate::index::test::store_then_load(
            LocalField::for_field(&store),
            LocalField::for_field(&load),
        );

        assert_eq!(*store.read(), *load.read());
        assert_eq!(*load.read(), 123456789);
    }
}
