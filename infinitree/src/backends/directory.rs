use super::{Backend, Result};
use crate::object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject};

use lru::LruCache;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(feature = "mmap")]
mod mmap {
    use super::Result;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, Ordering},
    };

    pub(super) struct MmappedFile {
        mmap: memmap2::Mmap,
        _file: std::fs::File,
        delete: LazyDrop,
    }

    impl MmappedFile {
        fn new(len: usize, path: impl AsRef<Path>) -> Result<Self> {
            let _file = fs::File::open(path.as_ref())?;
            let mmap = unsafe {
                memmap2::MmapOptions::new()
                    .len(len)
                    .populate()
                    .map(&_file)?
            };
            Ok(Self {
                mmap,
                _file,
                delete: LazyDrop::new(path.as_ref().to_owned()),
            })
        }

        #[allow(unused)]
        pub(super) fn mark_for_delete(&self) {
            self.delete.mark_for_delete();
        }
    }

    impl AsRef<[u8]> for MmappedFile {
        #[inline(always)]
        fn as_ref(&self) -> &[u8] {
            self.mmap.as_ref()
        }
    }

    struct LazyDrop {
        path: PathBuf,
        delete_on_drop: AtomicBool,
    }

    impl LazyDrop {
        fn new(path: PathBuf) -> Self {
            Self {
                path,
                delete_on_drop: false.into(),
            }
        }

        #[allow(unused)]
        fn mark_for_delete(&self) {
            self.delete_on_drop.store(true, Ordering::Relaxed);
        }
    }

    impl Drop for LazyDrop {
        fn drop(&mut self) {
            if self.delete_on_drop.load(Ordering::Relaxed) {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    #[inline(always)]
    pub(super) fn get_buf(filename: impl AsRef<Path>) -> Result<MmappedFile> {
        let mmap = MmappedFile::new(crate::BLOCK_SIZE, &filename)?;
        Ok(mmap)
    }
}

#[cfg(feature = "mmap")]
use mmap::get_buf;

#[cfg(not(feature = "mmap"))]
#[inline(always)]
fn get_buf(filename: impl AsRef<Path>) -> Result<ReadBuffer> {
    Ok(ReadBuffer::new(fs::read(&filename)?))
}

#[cfg(not(feature = "mmap"))]
type Buffer = ReadObject;

#[cfg(feature = "mmap")]
type Buffer = mmap::MmappedFile;

#[derive(Clone)]
pub struct Directory {
    target: PathBuf,
    read_lru: Arc<Mutex<LruCache<ObjectId, Arc<Buffer>>>>,
}

impl Directory {
    /// This is equivalent to `Directory::with_open_file_limit(target, 256)`
    pub fn new(target: impl AsRef<Path>) -> Result<Arc<Directory>> {
        Self::with_open_file_limit(target, 256)
    }

    pub fn with_open_file_limit(target: impl AsRef<Path>, limit: usize) -> Result<Arc<Directory>> {
        std::fs::create_dir_all(&target)?;
        Ok(Arc::new(Directory {
            target: target.as_ref().into(),
            read_lru: Arc::new(Mutex::new(LruCache::new(limit))),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.target
    }
}

impl Backend for Directory {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let filename = self.target.join(object.id().to_string());
        fs::write(filename, object.as_inner())?;
        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let lru = {
            let mut lock = self.read_lru.lock().unwrap();
            lock.get(id).cloned()
        };

        match lru {
            Some(handle) => Ok(Object::with_id(*id, ReadBuffer::with_inner(handle)).into()),
            None => {
                let path = self.target.join(id.to_string());
                let buffer = Arc::new(get_buf(&path)?);

                self.read_lru.lock().unwrap().put(*id, buffer.clone());
                Ok(Object::with_id(*id, ReadBuffer::with_inner(buffer)).into())
            }
        }
    }

    #[cfg(all(windows, feature = "mmap"))]
    fn delete(&self, objects: &[ObjectId]) -> Result<()> {
        use super::BackendError;

        for id in objects {
            self.read_lru
                .lock()
                .unwrap()
                .pop(id)
                .ok_or(BackendError::NotFound { id: *id })
                .and_then(|handle| Ok(handle.mark_for_delete()))
                .or_else(|_| fs::remove_file(self.target.join(id.to_string())))?;
        }

        Ok(())
    }

    #[cfg(not(all(windows, feature = "mmap")))]
    fn delete(&self, objects: &[ObjectId]) -> Result<()> {
        for id in objects {
            let _ = self.read_lru.lock().unwrap().pop(id);
            fs::remove_file(self.target.join(id.to_string()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        backends::{Backend, Directory},
        object::{Object, ReadBuffer, WriteObject},
        TEST_DATA_DIR,
    };
    use std::{
        env,
        path::{Path, PathBuf},
        sync::Arc,
    };

    #[test]
    #[cfg(all(windows, feature = "mmap"))]
    fn write_read_delete() {
        let (_obj_1_read_ref, test_filename) = write_object_get_ref_then_delete("dir-win-mmap");

        // if mmap'd, windows maintains a lock on the file
        assert_eq!(test_filename.exists(), true);
        drop(_obj_1_read_ref);
        assert_eq!(test_filename.exists(), false);
    }

    #[test]
    #[cfg(not(all(windows, feature = "mmap")))]
    fn write_read_delete() {
        let (_obj_1_read_ref, test_filename) = write_object_get_ref_then_delete("dir");

        // if not mmap'd, there should be no lock held on the file
        // posix allows deleting open files
        assert_eq!(test_filename.exists(), false);
        drop(_obj_1_read_ref);
        assert_eq!(test_filename.exists(), false);
    }

    fn write_object_get_ref_then_delete(
        dir_name: &'static str,
    ) -> (Arc<Object<ReadBuffer>>, PathBuf) {
        let mut object = WriteObject::default();
        let data_root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join(TEST_DATA_DIR)
            .join(dir_name);
        std::fs::create_dir_all(&data_root).unwrap();

        let backend = Directory::new(&data_root).unwrap();
        let id_1 = *object.id();

        object.set_id(id_1);
        backend.write_object(&object).unwrap();

        let obj_1_read_ref = backend.read_object(object.id()).unwrap();
        backend.delete(&[id_1]).unwrap();

        let test_filename = data_root.join(id_1.to_string());
        (obj_1_read_ref, test_filename)
    }
}
