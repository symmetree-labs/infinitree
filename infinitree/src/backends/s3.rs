use super::{Backend, Result};
use crate::object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject};
use ::s3::Bucket;
pub use ::s3::{creds::Credentials, Region};
use anyhow::Context;
use scc::HashMap;
use std::sync::Arc;
use tokio::{
    runtime,
    task::{self, JoinHandle},
};

type TaskHandle = JoinHandle<anyhow::Result<u16>>;

#[derive(Clone)]
pub struct S3 {
    client: Bucket,
    in_flight: Arc<HashMap<ObjectId, Arc<Option<TaskHandle>>>>,
}

impl S3 {
    pub fn new(region: Region, bucket: impl AsRef<str>) -> Result<Arc<Self>> {
        let creds = Credentials::default().context("Failed to get S3 credentials")?;
        Self::with_credentials(region, bucket, creds)
    }

    pub fn with_credentials(
        region: Region,
        bucket: impl AsRef<str>,
        creds: Credentials,
    ) -> Result<Arc<Self>> {
        let client = Bucket::new(bucket.as_ref(), region, creds)
            .context("Failed to connect to S3 bucket")?
            .with_path_style();

        Ok(Self {
            client,
            in_flight: Arc::new(HashMap::default()),
        }
        .into())
    }
}

impl Backend for S3 {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let client = self.client.clone();
        let in_flight = self.in_flight.clone();

        let body = object.as_inner().to_vec();
        let key = object.id().to_string();
        let id = *object.id();

        let handle = Arc::new(Some(task::spawn(async move {
            let status_code = client.put_object_stream(&mut body.as_slice(), key).await?;
            in_flight.remove(&id);

            Ok(status_code)
        })));

        self.in_flight.upsert(
            id,
            || handle.clone(),
            |_, v| {
                if let Some(handle) = v.as_ref() {
                    handle.abort();
                }

                *v = handle.clone();
            },
        );

        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let object: Result<Vec<u8>> = {
            let client = self.client.clone();
            let key = id.to_string();

            task::block_in_place(move || {
                runtime::Handle::current().block_on(async move {
                    let (buf, _status_code) = client
                        .get_object(key)
                        .await
                        .context("Failed to fetch object")?;

                    Ok(buf)
                })
            })
        };

        Ok(Arc::new(Object::with_id(*id, ReadBuffer::new(object?))))
    }

    fn sync(&self) -> Result<()> {
        let handles = futures::stream::FuturesUnordered::new();
        self.in_flight.for_each(|_, v| {
            if let Some(handle) = std::mem::take(Arc::get_mut(v).unwrap()) {
                handles.push(handle);
            }
        });

        task::block_in_place(move || {
            runtime::Handle::current()
                .block_on(async move { futures::future::join_all(handles.into_iter()).await })
        })
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to upload objects")?
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        backends::{test::write_and_wait_for_commit, S3},
        object::WriteObject,
        Backend, ObjectId, TEST_DATA_DIR,
    };
    use hyper::service::make_service_fn;
    use hyper::Server;
    use s3_server::{storages::fs::FileSystem, S3Service, SimpleAuth};
    use std::{
        future,
        net::{SocketAddr, TcpListener},
    };
    use tokio::task;

    const AWS_ACCESS_KEY_ID: &'static str = "ANTN35UAENTS5UIAEATD";
    const AWS_SECRET_ACCESS_KEY_ID: &'static str = "TtnuieannGt2rGuie2t8Tt7urarg5nauedRndrur";

    const BIND_SERVER: ([u8; 4], u16) = ([127, 0, 0, 1], 12312);

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
        let addr = SocketAddr::from(BIND_SERVER);
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
    #[should_panic]
    async fn s3_reading_nonexistent_object() {
        let addr = SocketAddr::from(BIND_SERVER);
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
