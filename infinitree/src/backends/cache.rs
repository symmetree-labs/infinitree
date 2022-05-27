use super::{tokio::block_on, Backend, BackendError, Directory, Result};
use crate::object::{ObjectId, ReadObject, WriteObject};
use anyhow::Context;
use lru::LruCache;
use scc::HashSet;
use std::{
    convert::TryFrom,
    fs::{read_dir, DirEntry},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

#[derive(Clone)]
pub struct Cache {
    file_list: Arc<tokio::sync::RwLock<LruCache<ObjectId, FileAccess>>>,
    warm: Arc<HashSet<ObjectId>>,

    size_limit: usize,
    upstream: Arc<dyn Backend>,
    directory: Arc<Directory>,
}

impl Cache {
    pub fn new(
        local: impl AsRef<Path>,
        size_limit_b: NonZeroUsize,
        upstream: Arc<dyn Backend>,
    ) -> Result<Arc<Self>> {
        let size_limit = size_limit_b.get();
        if size_limit < crate::BLOCK_SIZE {
            return Err(BackendError::from(anyhow::anyhow!(
                "cache size needs to be at least 4MiB"
            )));
        }

        let local = PathBuf::from(local.as_ref());
        std::fs::create_dir_all(&local)?;

        let mut file_list = read_dir(&local)?
            .filter_map(|result| {
                result.ok().and_then(|entry| {
                    if let Ok(ftype) = entry.file_type() {
                        let is_hidden = {
                            let raw_name = entry.file_name();
                            let name = raw_name.to_string_lossy();
                            name.starts_with('.')
                        };

                        if ftype.is_file() && !is_hidden {
                            return Some(entry);
                        }
                    }
                    None
                })
            })
            .map(FileAccess::from)
            .collect::<Vec<_>>();

        // we want to insert files in access time order so that we can
        // always drop the least recently used from the cache.
        //
        // many filesystems will flat out ignore atime and we fall
        // back to ctime. we're rolling on a best effort basis here.
        //
        // this also makes sense since when an object gets used, it's
        // bumped in the lru, therefore it's not "old" anymore as far
        // as the running process is concerned.

        file_list.sort_by(|a, b| a.atime.cmp(&b.atime));

        let mut files = LruCache::unbounded();
        for file in file_list {
            files.put(file.id, file);
        }

        Ok(Self {
            upstream,
            size_limit: size_limit_b.get(),
            directory: Directory::new(local)?,
            warm: Arc::default(),
            file_list: Arc::new(tokio::sync::RwLock::new(files)),
        }
        .into())
    }

    async fn size(&self) -> usize {
        crate::BLOCK_SIZE * (self.warm.len() + self.file_list.read().await.len())
    }

    async fn make_space_for_object(&self) -> Result<Vec<ObjectId>> {
        let mut evicted = vec![];

        // due to the async-icity of this, we don't want to sit on a
        // read-lock for the entire scope of this function
        while self.size().await > self.size_limit - crate::BLOCK_SIZE {
            let file = self
                .file_list
                .write()
                .await
                .pop_lru()
                .context("cache is too small!")?;

            file.1.delete(&self.directory)?;
            evicted.push(file.0);
        }

        Ok(evicted)
    }

    async fn add_new_object(&self, obj: WriteObject) -> Result<Vec<ObjectId>> {
        let evicted = self.make_space_for_object().await?;

        let id = *obj.id();
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.directory.write_object(&obj))
            .await
            .expect("the task shouldn't be aborted")?;

        if !self.warm.contains(&id) {
            self.file_list
                .write()
                .await
                .put(id.clone(), FileAccess::new(id));
        }

        return Ok(evicted);
    }

    async fn read_upstream(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let id = *id;
        let cache = self.clone();
        let object = tokio::task::spawn_blocking(move || cache.upstream.read_object(&id))
            .await
            .expect("the task shouldn't be aborted");

        if let Ok(ref obj) = object {
            self.add_new_object(obj.clone().into()).await?;
        }

        object
    }

    async fn read_cache_or_upstream(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        if self.file_list.write().await.get(id).is_some()
            || self.warm.read_async(id, |_| true).await.is_some()
        {
            match self.directory.read_object(id) {
                ok @ Ok(_) => ok,
                Err(_) => self.read_upstream(id).await,
            }
        } else {
            self.read_upstream(id).await
        }
    }
}

impl Backend for Cache {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        self.upstream.write_object(&object)?;
        block_on(self.add_new_object(object.clone()))?;
        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        block_on(self.read_cache_or_upstream(id))
    }

    fn read_fresh(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        block_on(self.read_upstream(id))
    }

    fn keep_warm(&self, objects: &[ObjectId]) -> Result<()> {
        if objects.len() * crate::BLOCK_SIZE > self.size_limit {
            return Err(BackendError::from(anyhow::anyhow!(
                "keep-warm list is larger than cache size!"
            )));
        }

        block_on(async {
            self.warm.clear_async().await;

            let mut lru = self.file_list.write().await;
            for id in objects {
                // we don't care if it's in the cache already
                let _ = lru.pop(id);

                self.warm
                    .insert_async(*id)
                    .await
                    .expect("warm list is cleared above");
            }
        });

        Ok(())
    }

    fn preload(&self, objects: &[ObjectId]) -> Result<()> {
        let cache = self.clone();
        let objects = objects.to_vec();

        tokio::task::spawn_blocking(move || {
            for id in objects {
                let _ = cache.read_object(&id).unwrap();
            }
        });

        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.upstream.sync()
    }
}

struct FileAccess {
    atime: SystemTime,
    id: ObjectId,
}

impl FileAccess {
    fn new(id: ObjectId) -> Self {
        Self {
            id,
            atime: SystemTime::now(),
        }
    }

    fn delete(self, directory: &Directory) -> Result<()> {
        directory.delete(&[self.id])
    }
}

impl From<DirEntry> for FileAccess {
    fn from(direntry: DirEntry) -> Self {
        let atime = direntry.metadata().unwrap().accessed().unwrap();
        let path = direntry.path();
        let id = ObjectId::try_from(path.file_name().unwrap().to_str().unwrap()).unwrap();

        Self { atime, id }
    }
}

#[cfg(test)]
mod test {
    use super::Cache;
    use crate::{
        backends::test::{write_and_wait_for_commit, InMemoryBackend},
        object::WriteObject,
        Backend, ObjectId, TEST_DATA_DIR,
    };
    use std::{env, num::NonZeroUsize, path::Path};

    #[test]
    #[should_panic(expected = "cache size needs to be at least 4MiB")]
    fn cache_at_least_block_size() {
        Cache::new(
            "/whatever",
            NonZeroUsize::new(123).unwrap(),
            InMemoryBackend::shared(),
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_twice_and_evict() {
        let mut object = WriteObject::default();

        let data_root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join(TEST_DATA_DIR)
            .join("cache");
        std::fs::create_dir_all(&data_root).unwrap();

        let backend = Cache::new(
            &data_root,
            NonZeroUsize::new(1 * crate::BLOCK_SIZE).unwrap(),
            InMemoryBackend::shared(),
        )
        .unwrap();

        let id_1 = *object.id();
        let id_2 = ObjectId::from_bytes(b"1234567890abcdef1234567890abcdef");

        write_and_wait_for_commit(backend.as_ref(), &object);
        let _obj_1_read_ref = backend.read_object(object.id()).unwrap();

        object.set_id(id_2);
        write_and_wait_for_commit(backend.as_ref(), &object);

        let test_filename = data_root.join(id_1.to_string());
        // 1st one is evicted automatically, hence `unwrap_err()`
        // on windows/mmap feature set, the handle is locked, therefore it's error to delete
        std::fs::remove_file(test_filename).unwrap_err();

        let test_filename = data_root.join(id_2.to_string());
        // 2nd one still lingering, we clean that up manually
        std::fs::remove_file(test_filename).unwrap();
    }
}
