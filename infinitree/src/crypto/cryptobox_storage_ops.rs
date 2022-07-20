//! Asymmetric cryptography based encryption scheme for write-only
//! trees.
use super::{
    symmetric::{Argon2UserPass, Symmetric},
    *,
};
use crate::{
    chunks::{ChunkPointer, RawChunkPointer},
    ObjectId,
};
use libsodium_sys::{
    crypto_box_MACBYTES, crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES, crypto_box_detached, crypto_box_keypair, crypto_box_open_detached,
    sodium_memzero,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;

/// A key pair for crypto_box-based schemes.
pub struct Keypair {
    pub public_key: RawKey,
    pub secret_key: RawKey,
}

impl Keypair {
    /// Generate a new key pair.
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; crypto_box_PUBLICKEYBYTES as usize];
        let mut sk = [0u8; crypto_box_SECRETKEYBYTES as usize];

        let ok = unsafe { crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        if ok != 0 {
            Err(CryptoError::Fatal)
        } else {
            Ok(Keypair {
                public_key: pk.into(),
                secret_key: sk.into(),
            })
        }
    }
}

/// Asymmetric-key based encryption scheme to create archives with a
/// write-only storage segment.
///
/// A fully write-only archive in Infinitree requires server-side
/// support. However, we can get half-way there by storing any
/// user-managed data through libsodium's
/// [crypto_box](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
/// scheme.
///
/// To write data using cryptobox, acquire a writer handle through
/// [Infinitree::storage_writer](crate::Infinitree::storage_writer). The
/// index itself is still symmetric for all operations that are
/// defined on [`Infinitree`](crate::Infinitree).
///
/// Due to the fact that on changing the encryption scheme all
/// existing [`ChunkPointer`]s would be invalidated, and would need
/// re-encryption, converting to and from `CryptoBoxStorage` is not
/// supported.
pub type StorageOnly = KeyingScheme<Argon2UserPass, CryptoBoxStorage>;

pub struct CryptoBoxStorage {
    inner: Symmetric,
    storage: Arc<InstanceKeys>,
}
struct CryptoBoxOps(CryptoOps, Arc<InstanceKeys>);
struct InstanceKeys {
    pk: RawKey,
    sk: Option<RawKey>,
}

impl StorageOnly {
    /// Create a crypto backend that only allows encryption through
    /// [`Infinitree::storage_writer`](crate::Infinitree::storage_writer).
    ///
    /// # Panics
    ///
    /// The resulting encryption backend will panic if decryption
    /// operation is done through `Infinitree::storage_reader`.
    pub fn encrypt_only(
        username: impl Into<SecretString>,
        password: impl Into<SecretString>,
        public_key: RawKey,
    ) -> Result<Self> {
        Ok(KeyingScheme::new(
            Argon2UserPass::with_credentials(username.into(), password.into())?,
            CryptoBoxStorage {
                inner: Symmetric::random()?,
                storage: Arc::new(InstanceKeys {
                    pk: public_key,
                    sk: None,
                }),
            },
        ))
    }

    /// Create a crypto backend that allows encryption and decryption
    /// for writers and readers acquired through
    /// [`Infinitree::storage_writer`](crate::Infinitree::storage_writer)
    /// and
    /// [`Infinitree::storage_reader`](crate::Infinitree::storage_reader),
    /// respectively.
    pub fn encrypt_and_decrypt(
        username: SecretString,
        password: SecretString,
        public_key: RawKey,
        secret_key: RawKey,
    ) -> Result<Self> {
        Ok(KeyingScheme::new(
            Argon2UserPass::with_credentials(username, password)?,
            CryptoBoxStorage {
                inner: Symmetric::random()?,
                storage: Arc::new(InstanceKeys {
                    pk: public_key,
                    sk: Some(secret_key),
                }),
            },
        ))
    }
}

impl InternalScheme for CryptoBoxStorage {
    fn chunk_key(&self) -> Result<ChunkKey> {
        self.inner.chunk_key()
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.inner.index_key()
    }

    fn storage_key(&self) -> Result<StorageKey> {
        Ok(StorageKey(Arc::new(CryptoBoxOps(
            self.inner.storage_key()?.into_inner(),
            self.storage.clone(),
        ))))
    }

    fn read_key(&self, raw_head: &[u8]) -> InternalKey {
        // skipping mode detection
        let convergence_key = raw_head[1..].into();
        let inner = Symmetric { convergence_key };

        let pk: RawKey = raw_head[1 + KEY_SIZE..].into();
        assert_eq!(pk.expose_secret(), self.storage.pk.expose_secret());

        Arc::new(CryptoBoxStorage {
            inner,
            storage: self.storage.clone(),
        })
    }

    fn write_key(&self, raw_head: &mut [u8]) -> usize {
        let pos = self.inner.write_key(raw_head);
        pos + self.storage.pk.write_to(&mut raw_head[pos..])
    }
}

impl ICryptoOps for CryptoBoxOps {
    #[inline]
    fn encrypt_chunk(
        &self,
        object: ObjectId,
        offs: u32,
        _hash: &Digest,
        data: &mut [u8],
    ) -> ChunkPointer {
        let mut epk = [0u8; crypto_box_PUBLICKEYBYTES as usize];
        let mut esk = [0u8; crypto_box_SECRETKEYBYTES as usize];
        let mut tag = [0u8; crypto_box_MACBYTES as usize];

        let nonce = &object.as_ref()[..crypto_box_NONCEBYTES as usize];

        unsafe {
            assert!(crypto_box_keypair(epk.as_mut_ptr(), esk.as_mut_ptr()) == 0);
            assert!(
                crypto_box_detached(
                    data.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    data.as_ptr(),
                    data.len().try_into().unwrap(),
                    nonce.as_ptr(),
                    self.1.pk.expose_secret().as_ptr(),
                    esk.as_ptr()
                ) == 0
            );
            sodium_memzero(esk.as_mut_ptr().cast(), esk.len());
        }

        RawChunkPointer {
            object,
            offs,
            key: epk,
            size: data.len() as u32,
            tag,
        }
        .into()
    }

    #[inline]
    fn decrypt_chunk<'buf>(
        &self,
        target: &'buf mut [u8],
        source: &[u8],
        chunk_ptr: &ChunkPointer,
    ) -> &'buf mut [u8] {
        let sk = self
            .1
            .sk
            .as_ref()
            .expect("No private key specified, can't decrypt data!");
        let chunk = chunk_ptr.as_raw();
        let size = chunk.size as usize;

        let start = chunk.offs as usize;
        let end = start + size;

        let source = &source[start..end];
        let nonce = &chunk.object.as_ref()[..crypto_box_NONCEBYTES as usize];

        unsafe {
            assert!(
                crypto_box_open_detached(
                    target.as_mut_ptr(),
                    source.as_ptr(),
                    chunk.tag.as_ptr(),
                    size.try_into().unwrap(),
                    nonce.as_ptr(),
                    chunk.key.as_ptr(),
                    sk.expose_secret().as_ptr()
                ) == 0
            );
        }

        &mut target[..size]
    }

    #[inline]
    fn hash(&self, content: &[u8]) -> Digest {
        self.0.hash(content)
    }

    fn hasher(&self) -> Hasher {
        self.0.hasher()
    }
}

#[cfg(test)]
mod test {
    use crate::{crypto::*, keys::cryptobox::StorageOnly};
    use std::sync::Arc;

    use super::InstanceKeys;

    const SECRET_KEY: [u8; super::crypto_box_SECRETKEYBYTES as usize] = [
        170, 208, 130, 31, 146, 57, 220, 53, 221, 144, 235, 118, 173, 221, 77, 207, 9, 46, 71, 68,
        183, 205, 75, 80, 64, 36, 223, 5, 145, 112, 83, 189,
    ];
    const PUBLIC_KEY: [u8; super::crypto_box_PUBLICKEYBYTES as usize] = [
        43, 239, 146, 208, 248, 130, 189, 110, 29, 81, 146, 88, 170, 141, 173, 58, 165, 248, 108,
        198, 162, 156, 32, 210, 79, 197, 9, 19, 110, 60, 234, 17,
    ];
    const SYMMETRIC_KEY: [u8; 32] = *b"abcdef1234567890abcdef1234567890";
    const HASH: &[u8; 32] = b"1234567890abcdef1234567890abcdef";
    const SIZE: usize = 26;
    const CLEARTEXT: &[u8; SIZE] = b"the quick brown fox jumps ";

    #[test]
    fn encrypt_decrypt() {
        let key = || {
            Arc::new(
                StorageOnly::encrypt_only(
                    "test".to_string(),
                    "test".to_string(),
                    PUBLIC_KEY.into(),
                )
                .unwrap(),
            )
        };

        let header = key().seal_root(&Default::default()).unwrap();

        let open_key = key();
        let open_header = open_key.open_root(header).unwrap();
        assert_eq!(open_header.root_ptr, Default::default());
    }

    fn encrypt_decrypt_with_ops(crypto: CryptoOps) {
        use crate::object::WriteObject;
        use std::io::Write;

        let mut obj = WriteObject::default();
        let mut encrypted = CLEARTEXT.clone();

        let cp = crypto.encrypt_chunk(*obj.id(), 0, HASH, &mut encrypted);
        obj.write(&encrypted).unwrap();

        let mut decrypted = vec![0; SIZE];
        crypto.decrypt_chunk(&mut decrypted, obj.as_ref(), &cp);

        assert_eq!(&decrypted[..SIZE], CLEARTEXT);
    }

    fn encrypt_decrypt_with_instance(keys: InstanceKeys) {
        use super::{super::symmetric::SymmetricOps, CryptoBoxOps};

        let symmetric = SymmetricOps(SYMMETRIC_KEY.into());
        let crypto = CryptoBoxOps(Arc::new(symmetric), Arc::new(keys));

        encrypt_decrypt_with_ops(Arc::new(crypto));
    }

    #[test]
    fn test_chunk_encryption() {
        encrypt_decrypt_with_instance(InstanceKeys {
            pk: PUBLIC_KEY.into(),
            sk: Some(SECRET_KEY.into()),
        });
    }

    #[test]
    #[should_panic(expected = "No private key specified, can't decrypt data!")]
    fn without_secret_key_decrypt_panics() {
        encrypt_decrypt_with_instance(InstanceKeys {
            pk: PUBLIC_KEY.into(),
            sk: None,
        });
    }

    #[test]
    fn keysource_with_secret_key() {
        let scheme = super::StorageOnly::encrypt_and_decrypt(
            "user".to_string().into(),
            "pass".to_string().into(),
            PUBLIC_KEY.into(),
            SECRET_KEY.into(),
        )
        .unwrap();

        encrypt_decrypt_with_ops(Arc::new(scheme.storage_key().unwrap()));
    }

    #[test]
    #[should_panic(expected = "No private key specified, can't decrypt data!")]
    fn keysource_encrypt_only() {
        let scheme = super::StorageOnly::encrypt_only(
            "user".to_string(),
            "pass".to_string(),
            PUBLIC_KEY.into(),
        )
        .unwrap();

        encrypt_decrypt_with_ops(Arc::new(scheme.storage_key().unwrap()));
    }
}
