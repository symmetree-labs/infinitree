use crate::{chunks::RawChunkPointer, object::ObjectId};

pub use blake3::Hasher;
use getrandom::getrandom;
use ring::aead;
use secrecy::{ExposeSecret, Secret, Zeroize};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key error: {source}")]
    KeyError {
        #[from]
        source: argon2::Error,
    },
}
pub type Result<T> = std::result::Result<T, CryptoError>;

pub struct Key {
    master_key: RawKey,
}

pub trait Random {
    fn fill(&self, buf: &mut [u8]);
}

#[derive(Clone)]
pub struct ObjectOperations {
    key: RawKey,
}

pub type RootKey = ObjectOperations;
pub type ChunkKey = ObjectOperations;

pub(crate) trait CryptoProvider: Random + Send + Sync + Clone {
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

impl Key {
    pub fn from_credentials(username: impl AsRef<str>, password: impl AsRef<str>) -> Result<Key> {
        derive_argon2(username.as_ref().as_bytes(), password.as_ref().as_bytes())
            .map(|k| Key { master_key: k })
    }

    pub(crate) fn root_object_id(&self) -> Result<ObjectId> {
        derive_subkey(&self.master_key, "zerostash.com 2022 root object id")
            .map(|k| ObjectId::from_bytes(k.expose_secret()))
    }

    pub(crate) fn get_root_key(&self) -> Result<RootKey> {
        derive_subkey(&self.master_key, "zerostash.com 2022 metadata key")
            .map(ObjectOperations::new)
    }

    pub(crate) fn get_object_key(&self) -> Result<ChunkKey> {
        derive_subkey(&self.master_key, "zerostash.com 2022 object base key")
            .map(ObjectOperations::new)
    }
}

impl ObjectOperations {
    pub fn new(key: RawKey) -> ObjectOperations {
        ObjectOperations { key }
    }
}

impl Random for ObjectOperations {
    #[inline]
    fn fill(&self, buf: &mut [u8]) {
        getrandom(buf).unwrap()
    }
}

impl CryptoProvider for ObjectOperations {
    #[inline]
    fn encrypt_chunk(
        &self,
        object_id: Option<ObjectId>,
        hash: &Digest,
        data: &mut [u8],
    ) -> RawChunkPointer {
        // Since the keys are always rotating, it's generally safe to
        // provide a predictible nonce
        let nonce_base = object_id.unwrap_or_default();
        let aead = get_aead(derive_chunk_key(&self.key, hash));
        let ring_tag = aead
            .seal_in_place_separate_tag(
                get_chunk_nonce(&nonce_base, data.len() as u32),
                aead::Aad::empty(),
                data,
            )
            .unwrap();

        let mut tag = Tag::default();
        tag.copy_from_slice(ring_tag.as_ref());

        RawChunkPointer {
            offs: 0,
            size: data.len() as u32,
            file: nonce_base,
            hash: *hash,
            tag,
        }
    }

    #[inline]
    fn decrypt_chunk<'buf>(
        &self,
        target: &'buf mut [u8],
        source: &[u8],
        source_id: Option<ObjectId>,
        chunk: &RawChunkPointer,
    ) -> &'buf mut [u8] {
        let size = chunk.size as usize;
        let cyphertext_size = size + chunk.tag.len();
        let nonce_base = source_id.unwrap_or_default();

        assert!(target.len() >= cyphertext_size);

        let start = chunk.offs as usize;
        let end = start + size;

        target[..size].copy_from_slice(&source[start..end]);
        target[size..cyphertext_size].copy_from_slice(&chunk.tag);

        let aead = get_aead(derive_chunk_key(&self.key, &chunk.hash));
        aead.open_in_place(
            get_chunk_nonce(&nonce_base, chunk.size),
            aead::Aad::empty(),
            &mut target[..cyphertext_size],
        )
        .unwrap();

        &mut target[..size]
    }

    #[inline]
    fn hash(&self, content: &[u8]) -> Digest {
        let mut output = Digest::default();
        output.copy_from_slice(blake3::hash(content).as_bytes());

        output
    }

    fn hasher(&self) -> Hasher {
        blake3::Hasher::new()
    }
}

#[inline]
fn get_aead(key: RawKey) -> aead::LessSafeKey {
    let key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.expose_secret()).expect("bad key");
    aead::LessSafeKey::new(key)
}

#[inline]
fn derive_chunk_key(key_src: &RawKey, hash: &Digest) -> RawKey {
    let mut key = *key_src.expose_secret();
    for i in 0..key.len() {
        key[i] ^= hash[i];
    }
    Secret::new(key)
}

#[inline]
fn get_chunk_nonce(object_id: &ObjectId, data_size: u32) -> aead::Nonce {
    let mut nonce = Nonce::default();
    let len = nonce.len();
    nonce.copy_from_slice(&object_id.as_ref()[..len]);

    let size = data_size.to_le_bytes();
    for i in 0..size.len() {
        nonce[i] ^= size[i];
    }

    aead::Nonce::assume_unique_for_key(nonce)
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

#[cfg(test)]
mod test {
    #[test]
    fn test_chunk_encryption() {
        use super::{CryptoProvider, ObjectOperations};
        use crate::object::WriteObject;
        use secrecy::Secret;
        use std::io::Write;

        let key = Secret::new(*b"abcdef1234567890abcdef1234567890");
        let hash = b"1234567890abcdef1234567890abcdef";
        let cleartext = b"the quick brown fox jumps ";
        let size = cleartext.len();
        let crypto = ObjectOperations::new(key);
        let mut obj = WriteObject::default();

        let mut encrypted = cleartext.clone();
        let cp = crypto.encrypt_chunk(Some(*obj.id()), hash, &mut encrypted);
        obj.write(&encrypted).unwrap();

        let mut decrypted = vec![0; size + cp.tag.len()];
        crypto.decrypt_chunk(&mut decrypted, obj.as_ref(), Some(*obj.id()), &cp);

        assert_eq!(&decrypted[..size], cleartext.as_ref());
    }
}
