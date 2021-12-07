use super::{Backend, BackendError, Result};
use crate::object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject};
use anyhow::Context;
pub use rusoto_core::Region;
use rusoto_s3::{GetObjectRequest, PutObjectOutput, PutObjectRequest, S3Client, S3};
use scc::HashMap;
use std::sync::Arc;
use tokio::{
    runtime,
    task::{self, JoinHandle},
};

type TaskHandle = JoinHandle<anyhow::Result<PutObjectOutput>>;

#[derive(Clone)]
pub struct InMemoryS3 {
    client: S3Client,
    bucket: String,
    in_flight: Arc<HashMap<ObjectId, Option<TaskHandle>>>,
}

impl InMemoryS3 {
    pub fn new(region: Region, bucket: String) -> Result<Self> {
        let client = S3Client::new(region);

        Ok(Self {
            client,
            bucket,
            in_flight: Arc::default(),
        })
    }
}

impl Backend for InMemoryS3 {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let in_flight = self.in_flight.clone();

        let body = Some(object.as_inner().to_vec().into());
        let key = object.id().to_string();
        let id = *object.id();

        self.in_flight
            .insert(
                id,
                Some(task::spawn(async move {
                    let handle = client
                        .put_object(PutObjectRequest {
                            bucket,
                            key,
                            body,
                            ..Default::default()
                        })
                        .await
                        .context("Failed to write object");
                    in_flight.remove(&id);
                    handle
                })),
            )
            .map_err(|_| BackendError::Create)?;

        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let object: std::result::Result<Vec<u8>, BackendError> = {
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let key = id.to_string();

            task::block_in_place(move || {
                runtime::Handle::current().block_on(async move {
                    let s3obj = client
                        .get_object(GetObjectRequest {
                            bucket,
                            key,
                            ..GetObjectRequest::default()
                        })
                        .await
                        .context("Failed to fetch object")?;

                    let mut buf = vec![];
                    tokio::io::copy(
                        &mut s3obj
                            .body
                            .context("No body for retrieved object")?
                            .into_async_read(),
                        &mut buf,
                    )
                    .await?;
                    Ok(buf)
                })
            })
        };

        Ok(Arc::new(Object::with_id(*id, ReadBuffer::new(object?))))
    }

    fn sync(&self) -> Result<()> {
        let mut handles = vec![];
        self.in_flight.for_each(|_, v| {
            if let Some(handle) = std::mem::take(v) {
                handles.push(handle);
            }
        });

        task::block_in_place(move || {
            runtime::Handle::current().block_on(async move {
                futures::future::join_all(handles.into_iter()).await;
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        backends::{test::write_and_wait_for_commit, InMemoryS3, Region},
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
        let backend = InMemoryS3::new(
            Region::Custom {
                name: "us-east-1".into(),
                endpoint: format!("http://{}", addr.to_string()),
            },
            "bucket".into(),
        )
        .unwrap();

        setup_s3_server(&addr);

        let mut object = WriteObject::default();
        let id_2 = ObjectId::from_bytes(b"1234567890abcdef1234567890abcdef");

        write_and_wait_for_commit(&backend, &object);
        let _obj_1_read_ref = backend.read_object(object.id()).unwrap();

        object.set_id(id_2);
        write_and_wait_for_commit(&backend, &object);
    }
}
