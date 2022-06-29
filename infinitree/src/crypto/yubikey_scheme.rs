use super::{
    symmetric::{Mode, Symmetric},
    *,
};
use crate::{chunks::*, ObjectId};
use ring::aead;
use secrecy::{ExposeSecret, SecretString};
use std::{mem::size_of, sync::Arc};
pub use yubico_manager;
use yubico_manager::Yubico;

type Nonce = [u8; 12];
type Challenge = [u8; 64];
type Response = [u8; 20];

const HEADER_PAYLOAD: usize =
    size_of::<SealedHeader>() - size_of::<Tag>() - size_of::<Nonce>() - size_of::<Challenge>();
const HEADER_CYPHERTEXT: usize =
    size_of::<SealedHeader>() - size_of::<Nonce>() - size_of::<Challenge>();

pub struct YubikeyCR {
    inner: KeySource,
    master_key: RawKey,
    mode: Mode,
    ykconfig: yubico_manager::config::Config,
}

/// blake3_kdf(ctx, master_key || yk_hmac_response(challenge))
fn header_key(
    master_key: &RawKey,
    challenge: Challenge,
    config: yubico_manager::config::Config,
) -> Result<RawKey> {
    let mut k = [0; KEY_SIZE + size_of::<Response>()];

    let mut yk = Yubico::new();
    let resp = yk
        .challenge_response_hmac(&challenge, config)
        .map_err(|_| CryptoError::Fatal)?
        .0;

    k[..KEY_SIZE].copy_from_slice(master_key.expose_secret());
    k[KEY_SIZE..].copy_from_slice(&resp);

    Ok(blake3::derive_key("zerostash.com 2022 yubikey challenge-response", &k).into())
}

fn seal_header(
    master_key: &RawKey,
    mode: Mode,
    header: CleartextHeader,
    ykconfig: yubico_manager::config::Config,
) -> Result<SealedHeader> {
    let random = SystemRandom::new();
    let nonce = {
        let mut buf = Nonce::default();
        random.fill(&mut buf)?;
        aead::Nonce::assume_unique_for_key(buf)
    };

    let challenge = {
        let mut buf = [0; size_of::<Challenge>()];
        random.fill(&mut buf)?;
        buf
    };

    let mut output = SealedHeader::default();
    let mut pos = header.root_ptr.write_to(&mut output);

    //
    // mark the mode
    output[pos] = mode as u8;
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
    debug_assert!(pos <= HEADER_CYPHERTEXT);

    //
    // Copy the n-once before it gets eaten by the aead.
    output[HEADER_CYPHERTEXT..HEADER_CYPHERTEXT + size_of::<Nonce>()]
        .copy_from_slice(nonce.as_ref());

    let aead = get_aead(header_key(master_key, challenge, ykconfig)?);
    let tag =
        aead.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut output[..HEADER_PAYLOAD])?;

    //
    // Dump tag and challenge
    output[HEADER_PAYLOAD..HEADER_PAYLOAD + size_of::<Tag>()].copy_from_slice(tag.as_ref());
    output[HEADER_CYPHERTEXT + size_of::<Nonce>()..].copy_from_slice(&challenge);

    Ok(output)
}

fn open_header(
    master_key: RawKey,
    mut sealed: SealedHeader,
    ykconfig: yubico_manager::config::Config,
) -> Result<CleartextHeader> {
    let mut challenge = [0; size_of::<Challenge>()];
    challenge.copy_from_slice(&sealed[HEADER_CYPHERTEXT + size_of::<Nonce>()..]);

    let aead = get_aead(header_key(&master_key, challenge, ykconfig.clone())?);
    let nonce = {
        let mut buf = Nonce::default();
        buf.copy_from_slice(&sealed[HEADER_CYPHERTEXT..HEADER_CYPHERTEXT + size_of::<Nonce>()]);
        aead::Nonce::assume_unique_for_key(buf)
    };

    let header = aead
        .open_in_place(nonce, aead::Aad::empty(), &mut sealed[..HEADER_CYPHERTEXT])
        .map_err(CryptoError::from)?;

    let (mut pos, root_ptr) = RawChunkPointer::parse(&header);
    let mode = header[pos];
    pos += 1;

    let convergence_key = {
        let mut buf = [0; KEY_SIZE];
        buf.copy_from_slice(&header[pos..pos + KEY_SIZE]);
        RawKey::new(buf)
    };

    let mode = Mode::try_from(mode)?;
    let inner: KeySource = mode.keysource(master_key.clone(), convergence_key);

    let key: KeySource = Arc::new(YubikeyCR {
        inner,
        mode,
        ykconfig,
        master_key,
    });

    Ok(CleartextHeader { root_ptr, key })
}

impl YubikeyCR {
    pub fn with_credentials(
        username: SecretString,
        password: SecretString,
        ykconfig: yubico_manager::config::Config,
    ) -> Result<Arc<Self>> {
        let random = SystemRandom::new();
        derive_argon2(
            b"",
            username.expose_secret().as_bytes(),
            password.expose_secret().as_bytes(),
        )
        .and_then(|master_key| {
            Ok(YubikeyCR {
                inner: Arc::new(Symmetric {
                    master_key: master_key.clone(),
                    convergence_key: generate_key(&random)?,
                }),
                master_key,
                mode: Mode::Symmetric,
                ykconfig,
            }
            .into())
        })
    }
}

impl CryptoScheme for YubikeyCR {
    fn root_object_id(&self) -> Result<ObjectId> {
        self.inner.root_object_id()
    }

    fn open_root(self: Arc<Self>, header: SealedHeader) -> Result<CleartextHeader> {
        open_header(self.master_key.clone(), header, self.ykconfig.clone())
    }

    fn seal_root(&self, header: CleartextHeader) -> Result<SealedHeader> {
        seal_header(&self.master_key, self.mode, header, self.ykconfig.clone())
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

#[cfg(test)]
mod test {
    #[test]
    #[ignore]
    fn userpass_encrypt_decrypt() {
        use super::{CleartextHeader, CryptoScheme, ExposeSecret, RawChunkPointer, YubikeyCR};
        use yubico_manager::{
            config::{Command, Config},
            Yubico,
        };

        let mut yubi = Yubico::new();
        let ykconfig = if let Ok(device) = yubi.find_yubikey() {
            Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_command(Command::Configuration1)
        } else {
            panic!("No Yubikey")
        };

        let seal_key = YubikeyCR::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
            ykconfig.clone(),
        )
        .unwrap();
        let convergence_key = seal_key.expose_convergence_key().unwrap();

        let ct = CleartextHeader {
            root_ptr: Default::default(),
            key: seal_key,
        };
        let header = ct.key.clone().seal_root(ct.clone()).unwrap();

        let open_key = YubikeyCR::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
            ykconfig,
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
}
