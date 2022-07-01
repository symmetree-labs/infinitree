//! Use a username/password combination to locate and unlock trees.
//!
//! See the documentation for [`UsernamePassword`] for additional details.
use super::*;
use crate::{chunks::*, ObjectId};
use ring::aead;
use secrecy::{ExposeSecret, SecretString};
use std::{mem::size_of, sync::Arc};

type Nonce = [u8; 12];

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
pub struct UsernamePassword {
    inner: Symmetric,
    username: SecretString,
    password: SecretString,
}

pub struct Symmetric {
    pub(super) master_key: RawKey,
    pub(super) convergence_key: RawKey,
}

pub struct MixedScheme {
    master_key: RawKey,
    ops: KeySource,
}

// Header size max 512b
const HEADER_PAYLOAD: usize = size_of::<SealedHeader>() - size_of::<Tag>() - size_of::<Nonce>();
const HEADER_CYPHERTEXT: usize = size_of::<SealedHeader>() - size_of::<Nonce>();

#[derive(Copy, Clone)]
pub(super) enum Mode {
    Mixed08 = 0,
    Symmetric = 1,
}

impl TryFrom<u8> for Mode {
    type Error = CryptoError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        use Mode::*;

        match value {
            0 => Ok(Mixed08),
            1 => Ok(Symmetric),
            _ => Err(CryptoError::Fatal),
        }
    }
}

impl Mode {
    pub(super) fn keysource(&self, master_key: RawKey, convergence_key: RawKey) -> KeySource {
        match self {
            Mode::Symmetric => Arc::new(Symmetric {
                master_key,
                convergence_key,
            }),
            Mode::Mixed08 => Arc::new(MixedScheme {
                master_key,
                ops: super::symmetric08::Key::with_key(convergence_key),
            }),
        }
    }

    pub(super) fn encode_root_to(
        &self,
        output: &mut SealedHeader,
        header: &CleartextHeader,
    ) -> Result<usize> {
        let mut pos = header.root_ptr.write_to(output);

        //
        // mark the mode to be New Symmetric.
        output[pos] = *self as u8;
        pos += 1;

        //
        // write out the convergence key
        let convergence_key = header
            .key
            .expose_convergence_key()
            .ok_or(CryptoError::Fatal)?;

        let key = convergence_key.expose_secret();
        output[pos..pos + key.len()].copy_from_slice(key);
        pos += key.len();
        Ok(pos)
    }
}

impl UsernamePassword {
    pub fn with_credentials(username: SecretString, password: SecretString) -> Result<KeySource> {
        let random = SystemRandom::new();
        let master_key = derive_argon2(
            b"",
            username.expose_secret().as_bytes(),
            password.expose_secret().as_bytes(),
        )?;

        Ok(Arc::new(UsernamePassword {
            inner: Symmetric {
                master_key,
                convergence_key: generate_key(&random)?,
            },
            username,
            password,
        }))
    }

    pub fn generate_password() -> Result<String> {
        let rand = ring::rand::SystemRandom::new();
        let mut k = [0; 64];
        rand.fill(&mut k)?;
        Ok(hex::encode(&k))
    }
}

fn root_key(master_key: &RawKey) -> Result<RawKey> {
    derive_subkey(master_key, "zerostash.com 2022 root key")
}

fn root_object_id(master_key: &RawKey) -> Result<ObjectId> {
    derive_subkey(master_key, "zerostash.com 2022 root object id")
        .map(|k| ObjectId::from_bytes(k.expose_secret()))
}

fn seal_header(master_key: &RawKey, mode: Mode, header: CleartextHeader) -> Result<SealedHeader> {
    let mut output = SealedHeader::default();
    let random = SystemRandom::new();
    let nonce = {
        let mut buf = Nonce::default();
        random.fill(&mut buf)?;
        aead::Nonce::assume_unique_for_key(buf)
    };

    let pos = mode.encode_root_to(&mut output, &header)?;
    debug_assert!(pos <= HEADER_CYPHERTEXT);

    // Copy the n-once before it gets eaten by the aead.
    output[HEADER_CYPHERTEXT..].copy_from_slice(nonce.as_ref());

    let aead = get_aead(root_key(master_key)?);
    let tag =
        aead.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut output[..HEADER_PAYLOAD])?;
    output[HEADER_PAYLOAD..HEADER_PAYLOAD + size_of::<Tag>()].copy_from_slice(tag.as_ref());

    Ok(output)
}

fn open_header(master_key: &RawKey, mut sealed: SealedHeader) -> Result<CleartextHeader> {
    let aead = get_aead(root_key(master_key)?);
    let nonce = {
        let mut buf = Nonce::default();
        buf.copy_from_slice(&sealed[HEADER_CYPHERTEXT..]);
        aead::Nonce::assume_unique_for_key(buf)
    };

    let header = aead
        .open_in_place(nonce, aead::Aad::empty(), &mut sealed[..HEADER_CYPHERTEXT])
        .map_err(CryptoError::from)?;

    let (mut pos, root_ptr) = RawChunkPointer::parse(&header);
    let mode = header[pos];
    pos += 1;

    let convergence_key = {
        let mut buf = [0; CRYPTO_DIGEST_SIZE];
        buf.copy_from_slice(&header[pos..pos + CRYPTO_DIGEST_SIZE]);
        RawKey::new(buf)
    };

    let key: KeySource = Mode::try_from(mode)?.keysource(master_key.clone(), convergence_key);
    Ok(CleartextHeader { root_ptr, key })
}

impl CryptoScheme for UsernamePassword {
    fn root_object_id(&self) -> Result<ObjectId> {
        self.inner.root_object_id()
    }

    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<CleartextHeader> {
        open_header(&self.inner.master_key, header.clone()).or_else(|_| {
            // open and transparently upgrade unsafe header format to this

            let old_header = super::symmetric08::Key::from_credentials(
                self.username.clone(),
                self.password.clone(),
            )?
            .open_root(header)?;

            Ok(CleartextHeader {
                root_ptr: old_header.root_ptr,
                key: Arc::new(MixedScheme {
                    master_key: self.inner.master_key.clone(),
                    ops: old_header.key,
                }),
            })
        })
    }

    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader> {
        self.inner.seal_root(header)
    }

    fn chunk_key(&self) -> Result<ChunkKey> {
        self.inner.chunk_key()
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.inner.index_key()
    }

    fn storage_key(&self) -> Result<StorageKey> {
        self.inner.storage_key()
    }

    fn expose_convergence_key(&self) -> Option<RawKey> {
        self.inner.expose_convergence_key()
    }
}

impl CryptoScheme for Symmetric {
    fn root_object_id(&self) -> Result<ObjectId> {
        root_object_id(&self.master_key)
    }

    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<CleartextHeader> {
        open_header(&self.master_key, header)
    }

    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader> {
        seal_header(&self.master_key, Mode::Symmetric, header)
    }

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

    fn expose_convergence_key(&self) -> Option<RawKey> {
        Some(self.convergence_key.clone())
    }
}

impl CryptoScheme for MixedScheme {
    fn root_object_id(&self) -> Result<ObjectId> {
        root_object_id(&self.master_key)
    }

    fn open_root(self: Arc<Self>, _header: SealedHeader) -> Result<CleartextHeader> {
        unreachable!()
    }

    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader> {
        seal_header(&self.master_key, Mode::Mixed08, header)
    }

    fn chunk_key(&self) -> Result<ChunkKey> {
        self.ops.chunk_key()
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.ops.index_key()
    }

    fn storage_key(&self) -> Result<StorageKey> {
        self.chunk_key().map(|ck| StorageKey(ck.0))
    }

    fn expose_convergence_key(&self) -> Option<RawKey> {
        self.ops.expose_convergence_key()
    }
}

#[derive(Clone)]
pub struct SymmetricOps(pub(crate) RawKey);

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

#[cfg(test)]
mod test {
    use super::*;

    const MASTER_KEY: [u8; CRYPTO_DIGEST_SIZE] = *b"abcdef1234567890abcdef1234567890";
    const CONVERGENCE_KEY: [u8; CRYPTO_DIGEST_SIZE] = *b"1234567890abcdef1234567890abcdef";
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
        let key = Arc::new(Symmetric {
            master_key: MASTER_KEY.into(),
            convergence_key: CONVERGENCE_KEY.into(),
        });

        let header = key.open_root(TEST_SEALED_HEADER).unwrap();
        assert_eq!(header.root_ptr, RawChunkPointer::default());
        assert_eq!(
            header.key.expose_convergence_key().unwrap().expose_secret(),
            &CONVERGENCE_KEY
        );
    }

    #[test]
    fn symmetric_encrypt_header() {
        let key = Arc::new(Symmetric {
            master_key: MASTER_KEY.into(),
            convergence_key: CONVERGENCE_KEY.into(),
        });

        let ct = CleartextHeader {
            root_ptr: Default::default(),
            key,
        };
        let header = ct.key.clone().seal_root(ct.clone()).unwrap();

        // Since the nonce is random, the encrypted buffer is not
        // predictible.
        let header = ct.key.clone().open_root(header).unwrap();
        assert_eq!(header.root_ptr, RawChunkPointer::default());
        assert_eq!(
            header.key.expose_convergence_key().unwrap().expose_secret(),
            &CONVERGENCE_KEY
        );
    }

    #[test]
    fn userpass_encrypt_decrypt() {
        let seal_key = UsernamePassword::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();
        let convergence_key = seal_key.expose_convergence_key().unwrap();

        let ct = CleartextHeader {
            root_ptr: Default::default(),
            key: seal_key,
        };
        let header = ct.key.clone().seal_root(ct.clone()).unwrap();

        let open_key = UsernamePassword::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();

        let open_header = open_key.open_root(header).unwrap();
        assert_eq!(open_header.root_ptr, RawChunkPointer::default());
        assert_eq!(
            open_header
                .key
                .expose_convergence_key()
                .unwrap()
                .expose_secret(),
            convergence_key.expose_secret()
        );
    }

    #[test]
    fn userpass_backwards_compat_root_address() {
        let userpass = UsernamePassword::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();

        let symmetric08 = super::super::symmetric08::Key::from_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();

        assert_eq!(
            userpass.root_object_id().unwrap(),
            symmetric08.root_object_id().unwrap()
        );
    }

    #[test]
    fn backwards_compat_upgrade() {
        const TEST_08_SEALED_HEADER: SealedHeader = SealedHeader([
            83, 42, 179, 250, 134, 126, 214, 14, 39, 162, 145, 87, 120, 248, 159, 68, 178, 171, 21,
            15, 7, 148, 78, 146, 120, 76, 159, 242, 15, 117, 239, 112, 131, 229, 143, 152, 5, 232,
            155, 176, 128, 17, 74, 135, 50, 103, 177, 96, 96, 143, 252, 148, 253, 220, 82, 232,
            250, 234, 193, 73, 79, 72, 244, 254, 226, 205, 106, 142, 111, 131, 98, 246, 175, 134,
            170, 160, 9, 235, 88, 9, 204, 61, 26, 54, 62, 232, 8, 30, 255, 46, 144, 54, 185, 126,
            188, 95, 37, 185, 90, 161, 76, 141, 32, 30, 214, 44, 218, 86, 152, 185, 139, 223, 243,
            32, 122, 105, 96, 161, 197, 97, 220, 228, 38, 198, 180, 137, 205, 86, 51, 13, 147, 157,
            151, 53, 49, 255, 66, 168, 74, 119, 146, 207, 114, 227, 91, 133, 131, 201, 122, 29,
            106, 114, 237, 6, 159, 204, 110, 251, 15, 248, 80, 170, 101, 116, 208, 215, 163, 135,
            28, 219, 13, 225, 48, 184, 41, 145, 31, 46, 134, 48, 133, 235, 176, 217, 195, 200, 94,
            147, 55, 230, 155, 45, 252, 59, 131, 139, 117, 64, 244, 34, 49, 252, 37, 28, 99, 86,
            50, 161, 242, 48, 32, 222, 231, 254, 93, 23, 44, 142, 5, 53, 219, 129, 96, 78, 122, 44,
            14, 121, 89, 86, 47, 55, 2, 76, 220, 216, 135, 141, 127, 230, 226, 206, 125, 3, 3, 139,
            50, 122, 139, 8, 54, 22, 126, 184, 200, 209, 26, 55, 46, 214, 4, 78, 84, 52, 152, 172,
            193, 56, 114, 231, 222, 91, 218, 2, 254, 213, 98, 252, 40, 135, 24, 231, 207, 195, 244,
            56, 85, 252, 170, 20, 109, 175, 220, 82, 104, 117, 181, 108, 119, 61, 199, 85, 141, 47,
            1, 228, 139, 214, 95, 89, 96, 130, 228, 153, 133, 133, 155, 201, 105, 38, 183, 126,
            189, 88, 26, 131, 226, 242, 255, 96, 169, 118, 150, 239, 164, 66, 109, 72, 18, 204,
            177, 253, 43, 99, 26, 241, 214, 168, 171, 208, 116, 127, 1, 223, 73, 3, 49, 180, 44,
            214, 64, 42, 138, 232, 71, 151, 22, 157, 247, 228, 104, 190, 80, 79, 229, 164, 205,
            144, 153, 26, 65, 143, 80, 34, 243, 172, 250, 115, 212, 52, 7, 237, 175, 198, 106, 134,
            240, 100, 232, 42, 23, 165, 60, 42, 4, 236, 154, 235, 255, 224, 223, 57, 192, 147, 242,
            39, 82, 234, 111, 74, 171, 84, 9, 38, 40, 150, 212, 38, 213, 44, 175, 126, 72, 112,
            142, 89, 99, 170, 81, 168, 87, 132, 176, 50, 5, 45, 179, 32, 161, 131, 130, 89, 46,
            149, 156, 44, 203, 147, 110, 209, 108, 127, 228, 240, 66, 179, 102, 141, 157, 4, 184,
            98, 116, 201, 142, 57, 46, 132, 36, 228, 86, 120, 50, 44, 192, 175, 170, 164, 206, 230,
            235, 161, 41, 86, 220, 54, 46, 167, 162, 52, 252, 218, 186, 171, 60, 43, 0, 26, 89, 32,
            8, 198,
        ]);

        let open_key = UsernamePassword::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();

        let open_header = open_key.open_root(TEST_08_SEALED_HEADER.clone()).unwrap();
        let sealed = open_header
            .key
            .clone()
            .seal_root(open_header.clone())
            .unwrap();

        // `symmetric08` will always produce the same header for the same data,
        // we want to avoid re-using the same algo on sealing
        assert_ne!(sealed, TEST_08_SEALED_HEADER);

        let open_key = UsernamePassword::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
        )
        .unwrap();

        // make sure we can also re-open this
        open_key.open_root(sealed).unwrap();
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

        let mut encrypted = cleartext.clone();
        let cp = crypto.encrypt_chunk(*obj.id(), 0, hash, &mut encrypted);
        obj.write(&encrypted).unwrap();

        let mut decrypted = vec![0; size + cp.as_raw().tag.len()];
        crypto.decrypt_chunk(&mut decrypted, obj.as_ref(), &cp);

        assert_eq!(&decrypted[..size], cleartext.as_ref());
    }
}
