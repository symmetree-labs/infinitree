//! Use a username/password combination to locate and unlock trees.
//!
//! See the documentation for [`UsernamePassword`] for additional details.
use super::*;
use crate::{chunks::*, ObjectId};
use ring::aead;
use secrecy::{ExposeSecret, SecretString};
use std::{mem::size_of, sync::Arc};

type Nonce = [u8; 12];

// Header size max 512b
const HEADER_PAYLOAD: usize = size_of::<SealedHeader>() - size_of::<Tag>() - size_of::<Nonce>();
const HEADER_CYPHERTEXT: usize = size_of::<SealedHeader>() - size_of::<Nonce>();

/// Use a combination of username/password to locate and unlock a
/// tree.
///
/// Note that all keys that are directly used to secure the tree's
/// contents are derived from a convergence key, which is stored in
/// the encrypted header.
///
/// The username/password combination can be therefore changed
/// freely. Changing the username and/or password will always result
/// in a new root object id.
///
/// ## Implementation details
///
/// The 512-byte binary header layout looks like so:
///
/// ```text
/// encrypt(root[88] || mode[1] || convergence_key[32] || 0[..]) || mac[16] || nonce[12]
/// ```
pub type UsernamePassword = KeyingScheme<Argon2UserPass, Symmetric>;
impl UsernamePassword {
    pub fn generate_password() -> Result<String> {
        let rand = ring::rand::SystemRandom::new();
        let mut k = [0; 32];
        rand.fill(&mut k)?;
        Ok(hex::encode(k))
    }

    pub fn with_credentials(
        username: impl Into<SecretString>,
        password: impl Into<SecretString>,
    ) -> Result<Self> {
        Ok(KeyingScheme::new(
            Argon2UserPass::with_credentials(username.into(), password.into())?,
            Symmetric::random()?,
        ))
    }
}

pub(crate) use private::*;
mod private {
    use super::*;

    pub struct Argon2UserPass {
        pub master_key: RawKey,
        pub username: SecretString,
        pub password: SecretString,
    }

    impl Argon2UserPass {
        pub(crate) fn with_credentials(
            username: SecretString,
            password: SecretString,
        ) -> Result<Self> {
            let master_key = derive_argon2(
                b"",
                username.expose_secret().as_bytes(),
                password.expose_secret().as_bytes(),
            )?;
            Ok(Argon2UserPass {
                master_key,
                username,
                password,
            })
        }
    }

    impl HeaderScheme for Argon2UserPass {
        fn root_object_id(&self) -> Result<ObjectId> {
            root_object_id(&self.master_key)
        }

        fn open_root(&self, sealed: SealedHeader) -> Result<OpenHeader> {
            let mut buf = sealed.0;

            let aead = get_aead(root_key(&self.master_key)?);
            let nonce = {
                let mut buf = Nonce::default();
                buf.copy_from_slice(&sealed[HEADER_CYPHERTEXT..]);
                aead::Nonce::assume_unique_for_key(buf)
            };

            let _ = aead
                .open_in_place(nonce, aead::Aad::empty(), &mut buf[..HEADER_CYPHERTEXT])
                .map_err(CryptoError::from)?;

            Ok(OpenHeader(buf))
        }

        fn open_header<IS: InternalScheme>(
            self: Arc<Self>,
            header: SealedHeader,
            internal: &IS,
        ) -> Result<(RawChunkPointer, KeyingScheme<Self, InternalKey>)>
        where
            Self: Sized + 'static,
        {
            let open = self.open_root(header.clone())?;
            let (pos, root_ptr) = RawChunkPointer::parse(&open);
            let convergence = internal.read_key(&open[pos..]);

            Ok((
                root_ptr,
                KeyingScheme {
                    header: self,
                    convergence,
                },
            ))
        }

        fn seal_root(&self, open: OpenHeader) -> Result<SealedHeader> {
            seal_header(&self.master_key, open)
        }
    }

    pub struct Symmetric {
        convergence_key: RawKey,
    }

    impl Symmetric {
        pub fn new(convergence_key: RawKey) -> Self {
            Self { convergence_key }
        }

        pub fn random() -> Result<Self> {
            let random = SystemRandom::new();

            Ok(Self {
                convergence_key: generate_key(&random)?,
            })
        }
    }

    impl InternalScheme for Symmetric {
        fn chunk_key(&self) -> Result<ChunkKey> {
            Ok(ChunkKey::new(SymmetricOps(derive_subkey(
                &self.convergence_key,
                "zerostash.com 2022 chunk key",
            )?)))
        }

        fn index_key(&self) -> Result<IndexKey> {
            Ok(IndexKey::new(SymmetricOps(derive_subkey(
                &self.convergence_key,
                "zerostash.com 2022 index key",
            )?)))
        }

        fn storage_key(&self) -> Result<StorageKey> {
            Ok(StorageKey::new(SymmetricOps(derive_subkey(
                &self.convergence_key,
                "zerostash.com 2022 storage key",
            )?)))
        }

        fn read_key(&self, raw_head: &[u8]) -> InternalKey {
            Mode::read_with_mode(raw_head)
        }

        fn write_key(&self, raw_head: &mut [u8]) -> usize {
            let output = Mode::Symmetric.write_to(raw_head);
            1 + self.convergence_key.write_to(output)
        }
    }

    #[derive(Copy, Clone)]
    pub(super) enum Mode {
        Symmetric = 1,
    }

    impl TryFrom<u8> for Mode {
        type Error = CryptoError;

        fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
            use Mode::*;

            match value {
                1 => Ok(Symmetric),
                _ => Err(CryptoError::Fatal),
            }
        }
    }

    impl Mode {
        pub(super) fn read_with_mode(header: &[u8]) -> InternalKey {
            let mode = Self::try_from(header[0]).unwrap();
            let k: RawKey = header[1..].into();

            match mode {
                Mode::Symmetric => Arc::new(Symmetric::new(k)),
            }
        }

        pub(super) fn write_to<'buf>(&self, output: &'buf mut [u8]) -> &'buf mut [u8] {
            output[0] = *self as u8;
            &mut output[1..]
        }
    }

    pub struct SymmetricOps(pub RawKey);

    impl ICryptoOps for SymmetricOps {
        #[inline]
        fn encrypt_chunk(
            &self,
            object: ObjectId,
            offs: u32,
            key: &Digest,
            data: &mut [u8],
        ) -> ChunkPointer {
            let aead = get_aead((*key).into());

            let ring_tag = aead
                .seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(Nonce::default()),
                    aead::Aad::from(&object),
                    data,
                )
                .unwrap();

            let mut tag = Tag::default();
            tag.copy_from_slice(ring_tag.as_ref());

            RawChunkPointer {
                size: data.len() as u32,
                key: *key,
                offs,
                object,
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
            let chunk = chunk_ptr.as_raw();
            let size = chunk.size as usize;
            let cyphertext_size = size + chunk.tag.len();

            assert!(target.len() >= cyphertext_size);

            let start = chunk.offs as usize;
            let end = start + size;

            target[..size].copy_from_slice(&source[start..end]);
            target[size..cyphertext_size].copy_from_slice(&chunk.tag);

            let aead = get_aead(chunk.key.into());
            aead.open_in_place(
                aead::Nonce::assume_unique_for_key(Nonce::default()),
                aead::Aad::from(&chunk.object),
                &mut target[..cyphertext_size],
            )
            .unwrap();

            &mut target[..size]
        }

        #[inline]
        fn hash(&self, content: &[u8]) -> Digest {
            let mut output = Digest::default();
            output.copy_from_slice(blake3::keyed_hash(self.0.expose_secret(), content).as_bytes());

            output
        }

        fn hasher(&self) -> Hasher {
            blake3::Hasher::new_keyed(self.0.expose_secret())
        }
    }
}

fn root_key(master_key: &RawKey) -> Result<RawKey> {
    derive_subkey(master_key, "zerostash.com 2022 root key")
}

pub(super) fn root_object_id(master_key: &RawKey) -> Result<ObjectId> {
    derive_subkey(master_key, "zerostash.com 2022 root object id")
        .map(|k| ObjectId::from_bytes(k.expose_secret()))
}

fn seal_header(master_key: &RawKey, open: OpenHeader) -> Result<SealedHeader> {
    let mut output = open.0;
    let random = SystemRandom::new();
    let nonce = {
        let mut buf = Nonce::default();
        random.fill(&mut buf)?;
        aead::Nonce::assume_unique_for_key(buf)
    };

    // Copy the n-once before it gets eaten by the aead.
    output[HEADER_CYPHERTEXT..].copy_from_slice(nonce.as_ref());

    let aead = get_aead(root_key(master_key)?);
    let tag =
        aead.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut output[..HEADER_PAYLOAD])?;
    output[HEADER_PAYLOAD..HEADER_PAYLOAD + size_of::<Tag>()].copy_from_slice(tag.as_ref());

    Ok(SealedHeader(output))
}
#[cfg(test)]
mod test {
    use super::*;

    const MASTER_KEY: [u8; CRYPTO_DIGEST_SIZE] = *b"abcdef1234567890abcdef1234567890";
    const TEST_SEALED_HEADER: SealedHeader = SealedHeader([
        66, 46, 17, 165, 56, 68, 174, 17, 116, 192, 220, 247, 147, 212, 53, 24, 24, 9, 70, 49, 6,
        91, 233, 98, 81, 247, 43, 60, 49, 167, 107, 79, 206, 72, 100, 235, 236, 136, 56, 185, 32,
        111, 20, 126, 202, 196, 243, 120, 239, 159, 93, 62, 172, 31, 75, 209, 253, 20, 218, 61,
        108, 88, 71, 21, 182, 224, 88, 158, 1, 193, 2, 33, 209, 108, 240, 232, 49, 117, 104, 229,
        196, 20, 242, 86, 187, 78, 39, 111, 97, 80, 121, 27, 255, 57, 79, 222, 127, 234, 62, 27,
        139, 124, 87, 44, 204, 18, 31, 213, 161, 195, 216, 210, 180, 207, 168, 17, 50, 16, 72, 41,
        229, 50, 209, 222, 25, 239, 229, 138, 42, 31, 197, 30, 139, 218, 35, 163, 86, 49, 199, 244,
        64, 212, 27, 239, 255, 149, 127, 235, 160, 188, 219, 198, 192, 95, 250, 60, 115, 148, 240,
        243, 66, 74, 70, 44, 0, 34, 225, 135, 253, 50, 136, 141, 190, 48, 187, 197, 48, 123, 34,
        176, 223, 238, 184, 224, 190, 43, 137, 246, 77, 179, 108, 234, 49, 185, 175, 34, 108, 90,
        64, 22, 146, 90, 212, 233, 127, 61, 225, 73, 177, 106, 190, 127, 49, 128, 26, 141, 20, 124,
        182, 56, 250, 127, 183, 44, 191, 221, 235, 179, 42, 70, 8, 113, 163, 210, 24, 41, 32, 227,
        243, 200, 22, 20, 214, 174, 106, 210, 115, 168, 85, 66, 120, 145, 108, 9, 246, 150, 140,
        178, 185, 86, 148, 245, 76, 167, 78, 250, 217, 44, 97, 216, 228, 77, 109, 10, 210, 134, 82,
        28, 237, 79, 126, 107, 250, 195, 180, 250, 226, 55, 195, 119, 119, 170, 160, 77, 238, 237,
        71, 189, 248, 164, 47, 60, 45, 198, 191, 70, 211, 24, 191, 37, 255, 171, 65, 148, 225, 52,
        11, 111, 89, 68, 195, 160, 178, 167, 177, 255, 233, 146, 50, 217, 176, 117, 66, 233, 74,
        107, 159, 227, 134, 153, 96, 34, 159, 78, 227, 246, 112, 57, 129, 71, 97, 144, 186, 166, 6,
        244, 20, 10, 151, 253, 139, 107, 44, 202, 144, 21, 51, 126, 137, 27, 61, 126, 205, 238, 37,
        182, 208, 189, 164, 231, 250, 42, 236, 169, 225, 50, 255, 73, 210, 223, 139, 19, 23, 1,
        148, 226, 214, 241, 16, 15, 148, 207, 204, 25, 102, 46, 141, 75, 176, 175, 127, 105, 2, 94,
        40, 70, 10, 11, 73, 167, 57, 218, 141, 6, 40, 23, 83, 80, 158, 20, 208, 252, 136, 209, 81,
        240, 124, 63, 29, 112, 7, 67, 129, 33, 129, 247, 167, 240, 252, 20, 213, 230, 103, 62, 250,
        64, 1, 200, 102, 235, 23, 43, 209, 155, 142, 173, 48, 117, 251, 244, 187, 210, 118, 135,
        22, 70, 104, 177, 187, 67, 203, 204, 143, 149, 169, 77, 126, 173, 52, 108, 213, 102, 137,
        102, 239, 75, 241, 142, 84, 207, 165, 180, 189, 8, 153, 36, 10, 215, 185, 199, 104, 58,
    ]);

    #[test]
    fn symmetric_decrypt_header() {
        let key = Argon2UserPass {
            master_key: MASTER_KEY.into(),
            username: "".to_string().into(),
            password: "".to_string().into(),
        };

        let _ = key.open_root(TEST_SEALED_HEADER).unwrap();
    }

    #[test]
    fn symmetric_encrypt_header() {
        let key = || Argon2UserPass {
            master_key: MASTER_KEY.into(),
            username: "".to_string().into(),
            password: "".to_string().into(),
        };

        let header = key().seal_root(Default::default()).unwrap();

        // Since the nonce is random, the encrypted buffer is not
        // predictible.
        let _ = key().open_root(header).unwrap();
    }

    #[test]
    fn userpass_encrypt_decrypt() {
        let key =
            || UsernamePassword::with_credentials("test".to_string(), "test".to_string()).unwrap();
        let header = key().header.seal_root(Default::default()).unwrap();
        let _ = key().header.open_root(header).unwrap();
    }

    #[test]
    fn test_chunk_encryption() {
        use super::{ICryptoOps, SymmetricOps};
        use crate::object::WriteObject;
        use std::io::Write;

        let key = *b"abcdef1234567890abcdef1234567890";
        let hash = b"1234567890abcdef1234567890abcdef";
        let cleartext = b"the quick brown fox jumps ";
        let size = cleartext.len();
        let crypto = SymmetricOps(key.into());
        let mut obj = WriteObject::default();

        let mut encrypted = *cleartext;
        let cp = crypto.encrypt_chunk(*obj.id(), 0, hash, &mut encrypted);
        obj.write(&encrypted).unwrap();

        let mut decrypted = vec![0; size + cp.as_raw().tag.len()];
        crypto.decrypt_chunk(&mut decrypted, obj.as_ref(), &cp);

        assert_eq!(&decrypted[..size], cleartext.as_ref());
    }
}
