use super::{Backend, BackendError, Result};
use crate::object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject};
use anyhow::Context;
use rusoto_core::Region;
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
