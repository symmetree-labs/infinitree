use crate::{
    backends::{Backend, BackendError},
    crypto::{CleartextHeader, CryptoError, CryptoScheme, SealedHeader, HEADER_SIZE},
    deserialize_from_slice,
    index::{FieldReader, IndexExt, TransactionList},
    object::{
        AEADReader, AEADWriter, BlockBuffer, BufferedSink, DeserializeStream, ObjectId, Pool,
        PoolRef, Stream, Writer,
    },
    tree::RootIndex,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io,
    mem::{size_of, take},
    num::NonZeroUsize,
    sync::Arc,
};

// warning: this is not pretty
#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("IO error")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Crypto error")]
    Crypto {
        #[from]
        source: CryptoError,
    },
    #[error("Backend error: {source}")]
    Backend {
        #[from]
        source: BackendError,
    },
    #[error("Decoding error: {source}")]
    Decode {
        #[from]
        source: rmp_serde::decode::Error,
    },
    #[error("Encoding error: {source}")]
    Encode {
        #[from]
        source: rmp_serde::encode::Error,
    },
    #[error("Internal error: {source}")]
    Internal {
        #[from]
        source: crate::object::ObjectError,
    },
    #[error("anyhow")]
    Anyhow {
        #[from]
        source: anyhow::Error,
    },
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) fn open<CustomData>(
    mut buffer: BlockBuffer,
    backend: Arc<dyn Backend>,
    crypto: Arc<dyn CryptoScheme>,
) -> Result<RootIndex<CustomData>>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let root = crypto.root_object_id()?;
    let index_key = crypto.index_key()?;

    let pool = {
        let backend = backend.clone();
        Pool::with_constructor(1, move || {
            AEADReader::for_root(backend.clone(), index_key.clone())
        })
    };

    let object = backend.read_fresh(&root)?;
    let header = {
        let mut sealed_header = [0u8; size_of::<SealedHeader>()];
        sealed_header.copy_from_slice(object.head(size_of::<SealedHeader>()));
        crypto.open_root(sealed_header)?
    };

    let (shadow_root, objects, transaction_list) = {
        let (shadow_root, stream_ptr) =
            parse_transactions_stream(&header, object.as_inner(), &mut buffer, pool.lease()?)?;

        let stream_objects = stream_ptr.objects();

        // TODO
        //
        // This stream *might* be stale in the cache. Very likely,
        // though, it's tightly packed with the root object.
        //
        // It would be prudent to ensure that all objects of the
        // stream are up-to-date.
        //
        // If you encounter an unexplicable decryption bug when using
        // caches, you probably have a huge transaction log.
        //
        let mut stream = DeserializeStream::new(stream_ptr.open_with_buffer(pool.lease()?, buffer));

        (
            shadow_root,
            stream_objects,
            stream.read_next::<TransactionList>()?,
        )
    };

    let mut root = RootIndex::<CustomData>::new(shadow_root, objects, header.key);
    root.load_all_from(&transaction_list, &pool)?;

    let objects = root.objects();
    backend.preload(&objects)?;
    backend.keep_warm(&objects)?;

    Ok(root)
}

pub(crate) fn commit<CustomData>(
    index: &mut RootIndex<CustomData>,
    backend: Arc<dyn Backend>,
) -> Result<()>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let crypto = index.key.clone();
    let root = crypto.root_object_id()?;
    let index_key = crypto.index_key()?;

    let mut writer = Pool::new(
        NonZeroUsize::new(1).unwrap(),
        AEADWriter::for_root(
            backend.clone(),
            index_key.clone(),
            HEADER_SIZE as u64,
            take(&mut index.objects.write()),
        ),
    )?;

    let stream = {
        let mut sink = BufferedSink::new(writer.clone());

        let (commit_id, fields) = index.commit(&mut sink, &mut writer, vec![], index_key)?;
        let transactions = fields
            .into_iter()
            .map(|(field, stream)| (commit_id, field, stream))
            .collect::<TransactionList>();

        crate::serialize_to_writer(&mut sink, &transactions)?;
        sink.clear()?
    };

    let objects_written = stream.objects();
    backend.keep_warm(&objects_written)?;
    *index.objects.write() = objects_written;

    let stream_buf = crate::serialize_to_vec(&stream)?;
    let root_ptr = writer.write(&stream_buf)?.into_raw();
    *index.shadow_root.write() = root_ptr.file;

    let header = CleartextHeader {
        root_ptr,
        key: crypto.clone(),
    };

    // there's only 1 writer in the pool, so this is deterministic
    // this needs to change if saving indexes ever becomes multi-threaded
    Ok(writer
        .lease()?
        .flush_root_head(root, &crypto.seal_root(header)?)?)
}

fn parse_transactions_stream(
    header: &CleartextHeader,
    raw: &[u8],
    buffer: &mut [u8],
    mut reader: PoolRef<AEADReader>,
) -> Result<(ObjectId, Stream)> {
    let transactions_pointer = &header.root_ptr;
    let shadow_root = transactions_pointer.file;
    reader.override_root_id(shadow_root, header.key.root_object_id()?);

    let stream: Stream = deserialize_from_slice(reader.decrypt_decompress(
        buffer,
        raw,
        &transactions_pointer.clone().into(),
    )?)?;

    Ok((shadow_root, stream))
}
