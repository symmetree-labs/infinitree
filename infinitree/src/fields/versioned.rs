use std::sync::Arc;

type RawAction<V> = Option<V>;
type Action<V> = Option<Arc<V>>;

fn store<V>(value: impl Into<Arc<V>>) -> Action<V> {
    Some(value.into())
}

pub(crate) mod map;
