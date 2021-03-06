//! Backends work with underlying persistence layers.
//!
//! The `infinitree` crate only contains the bare minimum to implement
//! a filesystem-based tree.
//!
//! For more interesting backends, such as S3 and LRU caches, please
//! use the
//! [`infinitree-backends`](https://docs.rs/infinitree-backends)
//! crate.
use crate::object::{ObjectId, ReadObject, WriteObject};
use std::{io, sync::Arc};

mod directory;
pub use directory::Directory;

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("IO error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("No object found")]
    NotFound { id: ObjectId },
    #[error("Can't create object")]
    Create,
    #[error("Backend Error: {source}")]
    Generic {
        #[from]
        source: anyhow::Error,
    },
}

pub type Result<T> = std::result::Result<T, BackendError>;

pub trait Backend: Send + Sync {
    fn write_object(&self, object: &WriteObject) -> Result<()>;
    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>>;

    fn preload(&self, _objects: &[ObjectId]) -> Result<()> {
        Ok(())
    }

    fn delete(&self, _objects: &[ObjectId]) -> Result<()> {
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn read_fresh(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        self.read_object(id)
    }

    fn keep_warm(&self, _objects: &[ObjectId]) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(test, bench, feature = "test"))]
pub mod test {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Clone, Default)]
    pub struct InMemoryBackend(Arc<Mutex<HashMap<ObjectId, Arc<ReadObject>>>>);

    impl InMemoryBackend {
        pub fn new() -> Self {
            InMemoryBackend::default()
        }

        pub fn shared() -> Arc<Self> {
            Arc::new(InMemoryBackend::default())
        }
    }

    impl Backend for InMemoryBackend {
        fn write_object(&self, object: &WriteObject) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(*object.id(), Arc::new(object.into()));
            Ok(())
        }

        fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .ok_or(BackendError::NotFound { id: *id })
                .map(Arc::clone)
        }
    }

    #[derive(Clone, Default)]
    pub struct NullBackend(Arc<Mutex<usize>>);

    #[allow(clippy::len_without_is_empty)]
    impl NullBackend {
        pub fn len(&self) -> usize {
            *self.0.lock().unwrap()
        }
    }

    impl Backend for NullBackend {
        fn write_object(&self, _object: &WriteObject) -> Result<()> {
            *self.0.lock().unwrap() += 1;
            Ok(())
        }

        fn read_object(&self, _id: &ObjectId) -> Result<Arc<ReadObject>> {
            unimplemented!();
        }
    }
}
