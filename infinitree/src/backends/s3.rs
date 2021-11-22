use super::{Backend, BackendError, Context, Result};
use crate::object::{Object, ObjectId, ReadBuffer, ReadObject, WriteObject};
use parking_lot::RwLock;
use rusoto_core::Region;
use rusoto_s3::{GetObjectRequest, PutObjectOutput, PutObjectRequest, S3Client, S3};
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
    handles: Arc<RwLock<Vec<(ObjectId, TaskHandle)>>>,
}

impl InMemoryS3 {
    pub fn new(region: Region, bucket: String) -> Result<Self> {
        let client = S3Client::new(region);

        Ok(Self {
            client,
            bucket,
            handles: Arc::default(),
        })
    }
}

impl Backend for InMemoryS3 {
    fn write_object(&self, object: &WriteObject) -> Result<()> {
        let client = self.client.clone();
        let bucket = self.bucket.clone();

        let body = Some(object.as_inner().to_vec().into());
        let key = object.id().to_string();

        self.handles.write().push((
            *object.id(),
            task::spawn(async move {
                client
                    .put_object(PutObjectRequest {
                        bucket,
                        key,
                        body,
                        ..Default::default()
                    })
                    .await
                    .context("Failed to write object")
            }),
        ));

        Ok(())
    }

    fn read_object(&self, id: &ObjectId) -> Result<Arc<ReadObject>> {
        let object: std::result::Result<Vec<u8>, BackendError> = {
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let key = id.to_string();

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
        };

        Ok(Arc::new(Object::with_id(*id, ReadBuffer::new(object?))))
    }

    fn delete(&self, _objects: &[ObjectId]) -> Result<()> {
        Ok(())
    }
}
