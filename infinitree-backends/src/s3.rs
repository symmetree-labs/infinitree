use super::block_on;
use anyhow::Context;
use infinitree::{
    backends::{Backend, Result},
    object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject},
};
use reqwest::Client;
pub use rusty_s3::{Bucket, Credentials};
use rusty_s3::{S3Action, UrlStyle};
use scc::HashMap;
use std::{env, future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    task::{self, JoinError, JoinHandle},
};

mod region;
pub use region::Region;

struct InFlightTracker<TaskResult>
where
    TaskResult: 'static + Send,
{
    permits: Arc<Semaphore>,
    active: Arc<HashMap<ObjectId, Arc<Option<JoinHandle<TaskResult>>>>>,
}

impl<TaskResult> Default for InFlightTracker<TaskResult>
where
    TaskResult: 'static + Send,
{
    fn default() -> Self {
        Self {
            permits: Semaphore::new(std::thread::available_parallelism().unwrap().get()).into(),
            active: Arc::default(),
        }
    }
}

impl<TaskResult> Clone for InFlightTracker<TaskResult>
where
    TaskResult: 'static + Send,
{
    fn clone(&self) -> Self {
        Self {
            permits: self.permits.clone(),
            active: self.active.clone(),
        }
    }
}

impl<TaskResult> InFlightTracker<TaskResult>
where
    TaskResult: 'static + Send,
{
    pub fn complete_all(&self) -> std::result::Result<Vec<TaskResult>, JoinError> {
        block_on(async move {
            let mut handles = vec![];
            self.active
                .retain_async(|_, v| {
                    if let Some(handle) = std::mem::take(Arc::get_mut(v).unwrap()) {
                        handles.push(handle);
                    }

                    false
                })
                .await;

            futures::future::join_all(handles).await
        })
        .into_iter()
        .filter(|result| match result {
            Ok(_) => true,
            Err(e) => !e.is_cancelled(),
        })
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
    }

    pub fn add_task<F: 'static + Send + Future<Output = TaskResult>>(
        &self,
        key: ObjectId,
        task: F,
    ) {
        let permits = self.permits.clone();
        let active = self.active.clone();

        block_on(async {
            let permit = permits.acquire_owned().await;

            let handle = Arc::new(Some(task::spawn(async move {
                let _permit = permit;
                let result = task.await;
                active.remove_async(&key).await;
                result
            })));

            self.active
                .upsert_async(
                    key,
                    || handle.clone(),
                    |_, v| {
                        if let Some(handle) = v.as_ref() {
                            handle.abort();
                        }

                        *v = handle.clone();
                    },
                )
                .await;
        })
    }
}

#[derive(Clone)]
pub struct S3 {
    base_path: String,
    client: Client,
    bucket: Arc<Bucket>,
    credentials: Arc<Credentials>,
    in_flight: InFlightTracker<anyhow::Result<u16>>,
}

impl S3 {
    pub fn new(region: Region, bucket: impl AsRef<str>) -> Result<Arc<Self>> {
        let access_key = env::var("AWS_ACCESS_KEY_ID").context("Invalid credentials")?;
        let secret_key = env::var("AWS_SECRET_ACCESS_KEY").context("Invalid credentials")?;

        let creds = Credentials::new(access_key, secret_key);
        Self::with_credentials(region, bucket, creds)
    }

    pub fn with_credentials(
        region: Region,
        bucket: impl AsRef<str>,
        creds: Credentials,
    ) -> Result<Arc<Self>> {
        let (bucket_name, base_path) = match bucket.as_ref().split_once('/') {
            Some((bucket, "")) => (bucket.to_string(), "".to_string()),
            Some((bucket, path)) => (bucket.to_string(), format!("{}/", path)),
            None => (bucket.as_ref().to_string(), "".to_string()),
        };

        let bucket = Bucket::new(
            region.endpoint().parse().context("Invalid endpoint URL")?,
            if let Region::Custom { .. } = region {
                UrlStyle::Path
            } else {
                UrlStyle::VirtualHost
            },
            bucket_name,
            region.to_string(),
        )
        .context("Failed to connect to S3 bucket")?
        .into();

        Ok(Self {
            bucket,
            base_path,
            client: reqwest::Client::new(),
            credentials: creds.into(),
            in_flight: InFlightTracker::default(),
        }
        .into())
    }

    fn get_path(&self, id: &ObjectId) -> String {
        // note that `base_path` automatically has a "/" appended to the string
        format!("{}{}", &self.base_path, id.to_string())
    }
}

impl Backend for S3 {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let body = object.as_inner().to_vec();
        let key = self.get_path(object.id());
        let id = *object.id();

        let this = self.clone();
        self.in_flight.add_task(id, async move {
            let url = this
                .bucket
                .put_object(Some(&this.credentials), &key)
                .sign(Duration::from_secs(30));

            let resp = this
                .client
                .put(url)
                .body(body)
                .send()
                .await
                .expect("Server error");

            let status_code = resp.status().as_u16();
            let resp_body = resp.bytes().await.expect("Response error");
            if (200..300).contains(&status_code) {
                Ok(status_code)
            } else {
                panic!(
                    "Bad response: {}, {}",
                    status_code,
                    String::from_utf8_lossy(resp_body.as_ref())
                )
            }
        });

        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let this = self.clone();
        let object: Result<Vec<u8>> = {
            let key = self.get_path(id);

            block_on(async move {
                let url = this
                    .bucket
                    .get_object(Some(&this.credentials), &key)
                    .sign(Duration::from_secs(30));

                let resp = this.client.get(url).send().await.context("Query error")?;
                let status_code = resp.status().as_u16();
                let body = resp.bytes().await.context("Read error")?;

                if (200..300).contains(&status_code) {
                    Ok(body.to_vec())
                } else {
                    Err(anyhow::anyhow!(
                        "Bad response: {}, {}",
                        status_code,
                        String::from_utf8_lossy(body.as_ref())
                    )
                    .into())
                }
            })
        };

        Ok(Arc::new(Object::with_id(*id, ReadBuffer::new(object?))))
    }

    fn sync(&self) -> Result<()> {
        self.in_flight
            .complete_all()
            .context("Failed transactions with server")?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::S3;
    use crate::test::{write_and_wait_for_commit, TEST_DATA_DIR};
    use hyper::service::make_service_fn;
    use hyper::Server;
    use infinitree::{backends::Backend, object::WriteObject, ObjectId};
    use s3_server::{storages::fs::FileSystem, S3Service, SimpleAuth};
    use std::{
        future,
        net::{SocketAddr, TcpListener},
    };
    use tokio::task;

    const AWS_ACCESS_KEY_ID: &'static str = "MEEMIEW3EEKI8IEY1U";
    const AWS_SECRET_ACCESS_KEY_ID: &'static str = "noh8xah2thohv7laehei2lahBuno5FameiNi";

    const SERVER_ADDR_RW: ([u8; 4], u16) = ([127, 0, 0, 1], 12312);
    const SERVER_ADDR_RO: ([u8; 4], u16) = ([127, 0, 0, 1], 12313);

    fn setup_s3_server(addr: &SocketAddr) {
        let fs = FileSystem::new(TEST_DATA_DIR).unwrap();
        let mut service = S3Service::new(fs);
        let mut auth = SimpleAuth::new();

        std::env::set_var("AWS_ACCESS_KEY_ID", AWS_ACCESS_KEY_ID);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", AWS_SECRET_ACCESS_KEY_ID);
        auth.register(AWS_ACCESS_KEY_ID.into(), AWS_SECRET_ACCESS_KEY_ID.into());
        service.set_auth(auth);

        let server = {
            let service = service.into_shared();
            let listener = TcpListener::bind(&addr).unwrap();
            let make_service: _ =
                make_service_fn(move |_| future::ready(Ok::<_, anyhow::Error>(service.clone())));
            Server::from_tcp(listener).unwrap().serve(make_service)
        };

        let _server_handle = task::spawn(server);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn s3_write_read() {
        let addr = SocketAddr::from(SERVER_ADDR_RW);
        setup_s3_server(&addr);

        let backend = S3::new(
            format!("http://{}", addr.to_string()).parse().unwrap(),
            "bucket",
        )
        .unwrap();

        let mut object = WriteObject::default();
        let id_2 = ObjectId::from_bytes(b"1234567890abcdef1234567890abcdef");

        write_and_wait_for_commit(backend.as_ref(), &object);
        let _obj_1_read_ref = backend.read_object(object.id()).unwrap();

        object.set_id(id_2);
        write_and_wait_for_commit(backend.as_ref(), &object);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[should_panic(
        expected = r#"Generic { source: Bad response: 404, <?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error> }"#
    )]
    async fn s3_reading_nonexistent_object() {
        let addr = SocketAddr::from(SERVER_ADDR_RO);
        setup_s3_server(&addr);

        let backend = S3::new(
            format!("http://{}", addr.to_string()).parse().unwrap(),
            "bucket",
        )
        .unwrap();

        let id = ObjectId::from_bytes(b"2222222222abcdef1234567890abcdef");

        let _obj_1_read_ref = backend.read_object(&id).unwrap();
    }
}
