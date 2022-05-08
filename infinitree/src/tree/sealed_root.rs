use crate::{
    backends::{Backend, BackendError},
    chunks::RawChunkPointer,
    crypto::{secure_hash, CryptoProvider, Digest, RootKey, Tag},
    deserialize_from_slice,
    index::{FieldReader, IndexExt, TransactionList},
    object::{
        AEADReader, AEADWriter, BlockBuffer, BufferedSink, DeserializeStream, ObjectId, Pool,
        PoolRef, Stream, Writer,
    },
    tree::RootIndex,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{io, mem::size_of, sync::Arc};

// Header size max 512b
const HEADER_SIZE: usize = 512;
const HEADER_PAYLOAD: usize = HEADER_SIZE - size_of::<Tag>();

// warning: this is not pretty
#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("IO error")]
    Io {
        #[from]
        source: io::Error,
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
    root: ObjectId,
    mut buffer: BlockBuffer,
    backend: Arc<dyn Backend>,
    crypto: RootKey,
) -> Result<RootIndex<CustomData>>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let pool = {
        let backend = backend.clone();
        let crypto = crypto.clone();
        Pool::with_constructor(1, move || {
            AEADReader::for_root(backend.clone(), crypto.clone())
        })
    };

    let transaction_list = {
        let object = backend.read_object(&root)?;
        let stream_ptr =
            parse_transactions_stream(root, crypto, object.as_inner(), &mut buffer, pool.lease()?)?;

        let mut stream = DeserializeStream::new(stream_ptr.open_with_buffer(pool.lease()?, buffer));
        stream.read_next::<TransactionList>()?
    };

    let mut root = RootIndex::default();
    root.load_all_from(&transaction_list, &pool)?;

    Ok(root)
}

// FIXME: this is gonna thrash pretty badly when the root index gets >1 block
//
// In theory we should at least attempt to _rewrite_ the existing
// objects, so no objects will be left unlinked.
//
// In an ideal world, we would garbage collect simultaneously here.
pub(crate) fn commit<CustomData>(
    index: &mut RootIndex<CustomData>,
    root: ObjectId,
    backend: Arc<dyn Backend>,
    crypto: RootKey,
) -> Result<()>
where
    CustomData: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let mut writer = Pool::new(
        1,
        AEADWriter::for_root(backend, crypto.clone(), HEADER_SIZE as u64),
    )?;

    let stream = {
        let mut sink = BufferedSink::new(writer.clone());

        let (commit_id, fields) = index.commit(&mut sink, &mut writer, vec![])?;
        let transactions = fields
            .into_iter()
            .map(|(field, stream)| (commit_id, field, stream))
            .collect::<TransactionList>();

        crate::serialize_to_writer(&mut sink, &transactions)?;
        sink.clear()?
    };

    let stream_buf = crate::serialize_to_vec(&stream)?;
    let mut head: [u8; HEADER_SIZE] = writer
        .write_chunk(&secure_hash(&stream_buf), &stream_buf)?
        .into_raw()
        .into();

    let pointer = crypto.encrypt_chunk(Some(root), &Digest::default(), &mut head[..HEADER_PAYLOAD]);
    head[HEADER_PAYLOAD..].copy_from_slice(&pointer.tag);

    // there's only 1 writer in the pool, so this is deterministic
    // this needs to change if saving indexes ever becomes multi-threaded
    Ok(writer.lease()?.flush_root_head(root, &head)?)
}

fn parse_transactions_stream(
    root: ObjectId,
    crypto: RootKey,
    raw: &[u8],
    buffer: &mut [u8],
    mut reader: PoolRef<AEADReader>,
) -> Result<Stream> {
    let tag = {
        let mut tag = Tag::default();
        tag.copy_from_slice(&raw[HEADER_PAYLOAD..HEADER_SIZE]);
        tag
    };

    let root_pointer = RawChunkPointer {
        offs: 0,
        size: HEADER_PAYLOAD as u32,

        file: root,

        // this field isn't verified, but is used for convergent encryption elsewhere
        // safe to use all zeroes, as `hash` is only used to derive a deterministic nonce value
        hash: Digest::default(),

        tag,
    };

    let transactions_pointer =
        RawChunkPointer::parse(crypto.decrypt_chunk(buffer, raw, Some(root), &root_pointer));

    reader.override_root_id(transactions_pointer.file, root);

    let stream: Stream = deserialize_from_slice(reader.decrypt_decompress(
        buffer,
        raw,
        &transactions_pointer.into(),
    )?)?;

    Ok(stream)
}