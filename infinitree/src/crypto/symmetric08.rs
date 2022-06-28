use super::*;
use crate::{chunks::RawChunkPointer, ObjectId};
use ring::aead;
use secrecy::{ExposeSecret, SecretString};
use std::{mem::size_of, sync::Arc};

type Nonce = [u8; 12];

pub struct Key {
    master_key: RawKey,
}

// Header size max 512b
const HEADER_PAYLOAD: usize = size_of::<SealedHeader>() - size_of::<Tag>();

impl Key {
    pub(crate) fn from_credentials(
        username: SecretString,
        password: SecretString,
    ) -> Result<KeySource> {
        let master_key = derive_argon2(
            b"",
            username.expose_secret().as_bytes(),
            password.expose_secret().as_bytes(),
        )?;

        Ok(Arc::new(Key { master_key }))
    }

    pub(crate) fn with_key(master_key: RawKey) -> KeySource {
        Arc::new(Self { master_key })
    }

    fn raw_index_key(&self) -> Result<RawKey> {
        derive_subkey(&self.master_key, "zerostash.com 2022 metadata key")
    }
}

impl CryptoScheme for Key {
    fn root_object_id(&self) -> Result<ObjectId> {
        derive_subkey(&self.master_key, "zerostash.com 2022 root object id")
            .map(|k| ObjectId::from_bytes(k.expose_secret()))
    }

    fn open_root(self: Arc<Self>, mut header: SealedHeader) -> Result<CleartextHeader> {
        let aead = get_aead(self.raw_index_key()?);
        let nonce = get_chunk_nonce(&self.root_object_id()?, HEADER_PAYLOAD as u32);
        aead.open_in_place(nonce, aead::Aad::empty(), header.as_mut())?;

        Ok(CleartextHeader {
            root_ptr: RawChunkPointer::parse(&header).1,
            key: self,
        })
    }

    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader> {
        let aead = get_aead(self.raw_index_key()?);
        let nonce = get_chunk_nonce(&self.root_object_id()?, HEADER_PAYLOAD as u32);

        let mut sealed = SealedHeader::default();
        header.root_ptr.write_to(&mut sealed);
        let tag = aead.seal_in_place_separate_tag(
            nonce,
            aead::Aad::empty(),
            &mut sealed[..HEADER_PAYLOAD],
        )?;
        sealed[HEADER_PAYLOAD..].copy_from_slice(tag.as_ref());

        Ok(sealed)
    }

    fn chunk_key(&self) -> Result<ChunkKey> {
        derive_subkey(&self.master_key, "zerostash.com 2022 object base key")
            .map(ObjectOperations::chunks)
            .map(super::ChunkKey::new)
    }

    fn index_key(&self) -> Result<IndexKey> {
        self.raw_index_key()
            .map(ObjectOperations::index)
            .map(super::IndexKey::new)
    }

    fn expose_convergence_key(&self) -> Option<RawKey> {
        Some(self.master_key.clone())
    }
}

#[derive(Clone)]
pub struct ObjectOperations {
    key: RawKey,
    is_index: bool,
}

impl ObjectOperations {
    pub(crate) fn chunks(key: RawKey) -> ObjectOperations {
        ObjectOperations {
            key,
            is_index: false,
        }
    }

    pub(crate) fn index(key: RawKey) -> ObjectOperations {
        ObjectOperations {
            key,
            is_index: true,
        }
    }
}

impl ICryptoOps for ObjectOperations {
    #[inline]
    fn encrypt_chunk(
        &self,
        file: ObjectId,
        offs: u32,
        hash: &Digest,
        data: &mut [u8],
    ) -> ChunkPointer {
        // Since the keys are always rotating, it's generally safe to
        // provide a predictible nonce
        let nonce_base = if self.is_index {
            ObjectId::default()
        } else {
            file
        };

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
            size: data.len() as u32,
            key: *hash,
            object: file,
            offs,
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
        let nonce_base = if self.is_index {
            ObjectId::default()
        } else {
            chunk.object
        };

        assert!(target.len() >= cyphertext_size);

        let start = chunk.offs as usize;
        let end = start + size;

        target[..size].copy_from_slice(&source[start..end]);
        target[size..cyphertext_size].copy_from_slice(&chunk.tag);

        let aead = get_aead(derive_chunk_key(&self.key, &chunk.key));
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
fn derive_chunk_key(key_src: &RawKey, hash: &Digest) -> RawKey {
    let mut key = *key_src.expose_secret();
    for i in 0..key.len() {
        key[i] ^= hash[i];
    }
    RawKey::new(key)
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

#[cfg(test)]
mod test {
    use crate::crypto::SealedHeader;

    const TEST_SEALED_HEADER: SealedHeader = SealedHeader([
        83, 42, 179, 250, 134, 126, 214, 14, 39, 162, 145, 87, 120, 248, 159, 68, 178, 171, 21, 15,
        7, 148, 78, 146, 120, 76, 159, 242, 15, 117, 239, 112, 131, 229, 143, 152, 5, 232, 155,
        176, 128, 17, 74, 135, 50, 103, 177, 96, 96, 143, 252, 148, 253, 220, 82, 232, 250, 234,
        193, 73, 79, 72, 244, 254, 226, 205, 106, 142, 111, 131, 98, 246, 175, 134, 170, 160, 9,
        235, 88, 9, 204, 61, 26, 54, 62, 232, 8, 30, 255, 46, 144, 54, 185, 126, 188, 95, 37, 185,
        90, 161, 76, 141, 32, 30, 214, 44, 218, 86, 152, 185, 139, 223, 243, 32, 122, 105, 96, 161,
        197, 97, 220, 228, 38, 198, 180, 137, 205, 86, 51, 13, 147, 157, 151, 53, 49, 255, 66, 168,
        74, 119, 146, 207, 114, 227, 91, 133, 131, 201, 122, 29, 106, 114, 237, 6, 159, 204, 110,
        251, 15, 248, 80, 170, 101, 116, 208, 215, 163, 135, 28, 219, 13, 225, 48, 184, 41, 145,
        31, 46, 134, 48, 133, 235, 176, 217, 195, 200, 94, 147, 55, 230, 155, 45, 252, 59, 131,
        139, 117, 64, 244, 34, 49, 252, 37, 28, 99, 86, 50, 161, 242, 48, 32, 222, 231, 254, 93,
        23, 44, 142, 5, 53, 219, 129, 96, 78, 122, 44, 14, 121, 89, 86, 47, 55, 2, 76, 220, 216,
        135, 141, 127, 230, 226, 206, 125, 3, 3, 139, 50, 122, 139, 8, 54, 22, 126, 184, 200, 209,
        26, 55, 46, 214, 4, 78, 84, 52, 152, 172, 193, 56, 114, 231, 222, 91, 218, 2, 254, 213, 98,
        252, 40, 135, 24, 231, 207, 195, 244, 56, 85, 252, 170, 20, 109, 175, 220, 82, 104, 117,
        181, 108, 119, 61, 199, 85, 141, 47, 1, 228, 139, 214, 95, 89, 96, 130, 228, 153, 133, 133,
        155, 201, 105, 38, 183, 126, 189, 88, 26, 131, 226, 242, 255, 96, 169, 118, 150, 239, 164,
        66, 109, 72, 18, 204, 177, 253, 43, 99, 26, 241, 214, 168, 171, 208, 116, 127, 1, 223, 73,
        3, 49, 180, 44, 214, 64, 42, 138, 232, 71, 151, 22, 157, 247, 228, 104, 190, 80, 79, 229,
        164, 205, 144, 153, 26, 65, 143, 80, 34, 243, 172, 250, 115, 212, 52, 7, 237, 175, 198,
        106, 134, 240, 100, 232, 42, 23, 165, 60, 42, 4, 236, 154, 235, 255, 224, 223, 57, 192,
        147, 242, 39, 82, 234, 111, 74, 171, 84, 9, 38, 40, 150, 212, 38, 213, 44, 175, 126, 72,
        112, 142, 89, 99, 170, 81, 168, 87, 132, 176, 50, 5, 45, 179, 32, 161, 131, 130, 89, 46,
        149, 156, 44, 203, 147, 110, 209, 108, 127, 228, 240, 66, 179, 102, 141, 157, 4, 184, 98,
        116, 201, 142, 57, 46, 132, 36, 228, 86, 120, 50, 44, 192, 175, 170, 164, 206, 230, 235,
        161, 41, 86, 220, 54, 46, 167, 162, 52, 252, 218, 186, 171, 60, 43, 0, 26, 89, 32, 8, 198,
    ]);

    #[test]
    fn can_decrypt_header() {
        use super::*;
        let key =
            Key::from_credentials("test".to_string().into(), "test".to_string().into()).unwrap();
        let header = key.open_root(TEST_SEALED_HEADER).unwrap();

        assert_eq!(header.root_ptr, RawChunkPointer::default());
    }

    #[test]
    fn can_encrypt_header() {
        use super::*;
        let key =
            Key::from_credentials("test".to_string().into(), "test".to_string().into()).unwrap();

        let ct = CleartextHeader {
            root_ptr: Default::default(),
            key,
        };

        let header = ct.key.clone().seal_root(ct).unwrap();

        assert_eq!(header, TEST_SEALED_HEADER);
    }

    #[test]
    fn test_chunk_encryption() {
        use super::{ICryptoOps, ObjectOperations};
        use crate::object::WriteObject;
        use std::io::Write;

        let key = *b"abcdef1234567890abcdef1234567890";
        let hash = b"1234567890abcdef1234567890abcdef";
        let cleartext = b"the quick brown fox jumps ";
        let size = cleartext.len();
        let crypto = ObjectOperations::chunks(key.into());
        let mut obj = WriteObject::default();

        let mut encrypted = cleartext.clone();
        let cp = crypto.encrypt_chunk(*obj.id(), 0, hash, &mut encrypted);
        obj.write(&encrypted).unwrap();

        let mut decrypted = vec![0; size + cp.as_raw().tag.len()];
        crypto.decrypt_chunk(&mut decrypted, obj.as_ref(), &cp);

        assert_eq!(&decrypted[..size], cleartext.as_ref());
    }
}
