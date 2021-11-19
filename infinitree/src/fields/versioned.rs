use std::sync::Arc;

type RawAction<V> = Option<V>;
type Action<V> = Option<Arc<V>>;

fn store<V>(value: impl Into<Arc<V>>) -> Action<V> {
    Some(value.into())
}

fn store_if_none<V>(current: &mut Option<Arc<V>>, value: impl Into<Arc<V>>) {
    current.get_or_insert(value.into());
}

pub(crate) mod map;
