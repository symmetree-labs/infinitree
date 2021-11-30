use super::{Backend, BackendError, Context, Directory, Result};
use crate::object::{ObjectId, ReadObject, WriteObject};
use lru::LruCache;
use scc::HashMap;
use std::{
    convert::TryFrom,
    fs::{self, read_dir, DirEntry},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    runtime,
    task::{self, JoinHandle},
};

#[derive(Clone)]
pub struct Cache<Upstream> {
    file_list: Arc<tokio::sync::RwLock<LruCache<ObjectId, FileAccess>>>,
    in_flight: Arc<HashMap<ObjectId, JoinHandle<()>>>,

    size_limit: NonZeroUsize,
    upstream: Upstream,
    directory: Arc<Directory>,
}

impl<Upstream> Cache<Upstream> {
    pub fn new(
        local: impl AsRef<Path>,
        size_limit: NonZeroUsize,
        upstream: Upstream,
    ) -> Result<Self> {
        let local = PathBuf::from(local.as_ref());
        let mut file_list = read_dir(&local)?
            .filter_map(|result|
			result.ok().and_then(|entry| {
			    if let Ok(ftype) = entry.file_type() {
				let is_hidden = {
				    let raw_name = entry.file_name();
				    let name = raw_name.to_string_lossy();
				    name.starts_with('.')
				};

				if ftype.is_file() && !is_hidden {
				    return Some(entry)
				}}
			    None
			})
		// 	match de {
                // Ok(de) => match de.file_type().map(|ft| ft.is_file()) {
                //     Ok(true) => Some(de),
                //     _ => None,
                // },
                // _ => None,
            )
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
        //
        // to actually maintain a lru between processes would require
        // dumping the lru, which complicates the logic and
        // produces additional metadata in the local cache that may
        // make sense to be protected (?). idk, good enough.

        file_list.sort_by(|a, b| a.atime.cmp(&b.atime));

        let mut files = LruCache::unbounded();
        for file in file_list {
            files.put(file.id, file);
        }

        Ok(Self {
            upstream,
            size_limit,
            directory: Directory::new(local)?,
            in_flight: Arc::default(),
            file_list: Arc::new(tokio::sync::RwLock::new(files)),
        })
    }

    async fn make_space_for_object(&self) -> Result<Vec<ObjectId>> {
        let mut evicted = vec![];

        // due to the async-icity of this, we don't want to sit on a
        // read-lock for the entire scope of this function
        while self.file_list.read().await.len() * crate::BLOCK_SIZE >= self.size_limit.into() {
            // unwrap won't blow up, because if it is `None`, that
            // implies `files.len()` is 0, while `size_limit` is
            // non-zero, therefore we won't enter the loop
            let id = *self.file_list.read().await.peek_lru().unwrap().0;
            if let Some((_, future)) = self.in_flight.remove(&id) {
                // can't start deleting objects during a pending
                // up-stream transaction
                future.await.context("In-flight transaction failed")?;
            }

            let file = self.file_list.write().await.pop(&id).unwrap();

            file.delete();
            evicted.push(id);
        }

        Ok(evicted)
    }

    async fn add_new_object(&self, obj: &WriteObject) -> Result<Vec<ObjectId>> {
        if self.file_list.write().await.get(obj.id()).is_none() {
            let evicted = self.make_space_for_object().await?;

            self.directory.write_object(obj)?;

            self.file_list
                .write()
                .await
                .put(*obj.id(), FileAccess::new(*obj.id(), self.directory.path()));

            return Ok(evicted);
        }

        Ok(vec![])
    }
}

impl<Upstream: 'static + Backend + Clone> Backend for Cache<Upstream> {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let cache = self.clone();
        let object = object.clone();

        self.in_flight
            .insert(
                *object.id(),
                task::spawn(async move {
                    let _ = cache.add_new_object(&object).await;
                    cache.upstream.write_object(&object).unwrap();
                    cache.in_flight.remove(object.id());
                }),
            )
            .map_err(|_| BackendError::Create)?;

        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let cache = self.clone();

        task::block_in_place(move || {
            runtime::Handle::current().block_on(async move {
                let _ = &cache;
                match cache.file_list.write().await.get(id) {
                    Some(_) => cache.directory.read_object(id),
                    None => {
                        let object = cache.upstream.read_object(id);
                        if let Ok(ref obj) = object {
                            self.add_new_object(&obj.into()).await?;
                        }

                        object
                    }
                }
            })
        })
    }
}

struct FileAccess {
    atime: SystemTime,
    id: ObjectId,
    path: PathBuf,
}

impl FileAccess {
    fn new(id: ObjectId, path: impl AsRef<Path>) -> Self {
        let mut path = path.as_ref().to_owned();
        path.push(id.to_string());

        Self {
            id,
            path,
            atime: SystemTime::now(),
        }
    }

    fn delete(self) {
        fs::remove_file(self.path).unwrap();
    }
}

impl From<DirEntry> for FileAccess {
    fn from(direntry: DirEntry) -> Self {
        let atime = direntry.metadata().unwrap().accessed().unwrap();
        let path = direntry.path();
        let id = ObjectId::try_from(path.file_name().unwrap().to_str().unwrap()).unwrap();

        Self { atime, id, path }
    }
}

#[cfg(test)]
mod test {
    use super::Cache;
    use crate::{
        backends::{test::InMemoryBackend, Backend},
        object::{BlockBuffer, Object},
        ObjectId, TEST_DATA_DIR,
    };
    use std::num::NonZeroUsize;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_twice_and_evict() {
        let mut object = crate::object::WriteObject::default();
        let backend = Cache::new(
            TEST_DATA_DIR,
            NonZeroUsize::new(4).unwrap(),
            InMemoryBackend::new(),
        )
        .unwrap();

        let id_1 = *object.id();
        let id_2 = ObjectId::from_bytes(b"1234567890abcdef1234567890abcdef");

        write_and_wait_for_commit(&backend, &object);
        backend.read_object(object.id()).unwrap();

        object.set_id(id_2);
        write_and_wait_for_commit(&backend, &object);

        let test_filename = format!("{}/{}", TEST_DATA_DIR, id_1.to_string());
        // 1st one is evicted automatically, hence `unwrap_err()`
        std::fs::remove_file(test_filename).unwrap_err();

        let test_filename = format!("{}/{}", TEST_DATA_DIR, id_2.to_string());
        // 2nd one still lingering, we clean that up manually
        std::fs::remove_file(test_filename).unwrap();
    }

    fn write_and_wait_for_commit(backend: &Cache<InMemoryBackend>, object: &Object<BlockBuffer>) {
        backend.write_object(object).unwrap();
        while backend.in_flight.len() != 0 {
            std::thread::yield_now();
        }
    }
}
