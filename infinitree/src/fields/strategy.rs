//! Serialization strategies for index fields

/// Allows decoupling a storage strategy for index fields from the
/// in-memory representation.
pub trait Strategy<T: Send + Sync>: Send + Sync {
    /// Instantiate a new `Strategy`.
    fn for_field(field: &T) -> Self
    where
        Self: Sized;
}

/// Stores values in the object pool, while keeping
/// keys in the index
pub struct SparseField<Field> {
    pub field: Field,
}

impl<T: Send + Sync + Clone> Strategy<T> for SparseField<T> {
    #[inline(always)]
    fn for_field(field: &'_ T) -> Self {
        SparseField {
            field: field.clone(),
        }
    }
}

/// Store the entire field in the index
pub struct LocalField<Field> {
    pub field: Field,
}

impl<T: Send + Sync + Clone> Strategy<T> for LocalField<T> {
    #[inline(always)]
    fn for_field(field: &T) -> Self {
        LocalField {
            field: field.clone(),
        }
    }
}
