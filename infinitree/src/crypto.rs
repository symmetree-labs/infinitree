// enum KeySource {
//     /// Use the username and password combination to derive root
//     /// object id and encryption key
//     UserPass { user: String, password: String },

//     /// Use the given secret key to derive the root object id and root
//     /// encryption key
//     Symmetric { key: Secret<Vec<u8>> },

//     /// Symmetrically encrypt the index, but object contents can only
//     /// be decrypted if the secret key is supplied
//     CryptoBox {
//         user: String,
//         password: String,
//         public_key: Vec<u8>,
//         secret_key: Option<Vec<u8>>,
//     },

//     /// Yubikey challenge-response authentication
//     /// Derive the root object id from the username/password pair, and
//     /// mix the Yubikey HMAC response into the encryption key derivation.
//     ///
//     /// On every write the root encryption key will change, and the
//     /// 20-byte challenge is written to the root object header
//     /// unencrypted.
//     YubikeyCR { user: String, password: String },
// }

use crate::{chunks::RawChunkPointer, object::ObjectId};
pub use blake3::Hasher;
use ring::aead;
pub use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret, Zeroize};
use std::sync::Arc;
use thiserror::Error;

pub(crate) mod symmetric08;
pub use symmetric08::Key;

const CRYPTO_DIGEST_SIZE: usize = 32;
type Nonce = [u8; 12];
type RawKey = Secret<[u8; CRYPTO_DIGEST_SIZE]>;

// TODO: ideally this should be a tuple struct wrapping blake3::Hash,
// implementing Serialize & Deserialize and the rest.
//
// That way we get constant time equality checks for free, which is
// prudent to want, but I'm uncertain about a realistic side-channel
// based on this right now.
pub type Digest = [u8; CRYPTO_DIGEST_SIZE];
pub type Tag = [u8; 16];

pub trait KeySource: 'static + CryptoScheme + Send + Sync {}
impl<T> KeySource for T where T: 'static + CryptoScheme + Send + Sync {}

pub(crate) const HEADER_SIZE: usize = 512;

pub(crate) type CryptoOps = Arc<dyn CryptoProvider>;
pub(crate) type CryptoSchemeRef = Arc<dyn 'static + CryptoScheme + Send + Sync>;

pub(crate) type SealedHeader = [u8; HEADER_SIZE];
pub struct CleartextHeader {
    pub(crate) root_ptr: RawChunkPointer,
    pub(crate) key: CryptoSchemeRef,
}

pub trait CryptoScheme {
    fn root_object_id(&self) -> Result<ObjectId>;
    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<CleartextHeader>;
    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader>;

    fn chunk_key(&self) -> Result<ChunkKey>;
    fn index_key(&self) -> Result<IndexKey>;

    fn master_key(&self) -> Option<RawKey>;
}

pub(crate) trait CryptoProvider: Send + Sync {
    fn encrypt_chunk(
        &self,
        object_id: Option<ObjectId>,
        hash: &Digest,
        data: &mut [u8],
    ) -> RawChunkPointer;

    fn decrypt_chunk<'buf>(
        &self,
        target: &'buf mut [u8],
        source: &[u8],
        source_id: Option<ObjectId>,
        chunk: &RawChunkPointer,
    ) -> &'buf mut [u8];

    fn hash(&self, data: &[u8]) -> Digest;

    fn hasher(&self) -> Hasher;
}

macro_rules! key_type {
    ($name:ident) => {
        #[derive(Clone)]
        pub struct $name(CryptoOps);

        impl $name {
            pub(crate) fn new(ops: impl CryptoProvider + 'static) -> Self {
                Self(Arc::new(ops))
            }

            pub(crate) fn unwrap(self) -> CryptoOps {
                self.0
            }
        }

        impl CryptoProvider for $name {
            fn encrypt_chunk(
                &self,
                object_id: Option<ObjectId>,
                hash: &Digest,
                data: &mut [u8],
            ) -> RawChunkPointer {
                self.0.encrypt_chunk(object_id, hash, data)
            }

            fn decrypt_chunk<'buf>(
                &self,
                target: &'buf mut [u8],
                source: &[u8],
                source_id: Option<ObjectId>,
                chunk: &RawChunkPointer,
            ) -> &'buf mut [u8] {
                self.0.decrypt_chunk(target, source, source_id, chunk)
            }

            fn hash(&self, data: &[u8]) -> Digest {
                self.0.hash(data)
            }

            fn hasher(&self) -> Hasher {
                self.0.hasher()
            }
        }
    };
}

key_type!(IndexKey);
key_type!(ChunkKey);

#[inline]
fn get_aead(key: RawKey) -> aead::LessSafeKey {
    let key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.expose_secret()).expect("bad key");
    aead::LessSafeKey::new(key)
}

fn derive_argon2(salt_raw: &[u8], password: &[u8]) -> Result<RawKey> {
    let salt = blake3::hash(salt_raw);

    let mut result = argon2::hash_raw(
        password,
        salt.as_bytes(),
        &argon2::Config {
            hash_length: CRYPTO_DIGEST_SIZE as u32,
            variant: argon2::Variant::Argon2id,
            ..argon2::Config::default()
        },
    )?;

    let mut outbuf = [0; CRYPTO_DIGEST_SIZE];
    outbuf.copy_from_slice(&result);
    result.zeroize();

    Ok(Secret::new(outbuf))
}

fn derive_subkey(key: &RawKey, ctx: &str) -> Result<RawKey> {
    let outbuf = blake3::derive_key(ctx, key.expose_secret());
    Ok(Secret::new(outbuf))
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key error: {source}")]
    KeyError {
        #[from]
        source: argon2::Error,
    },
    #[error("Fatal error")]
    Fatal,
}
pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        CryptoError::Fatal
    }
}
