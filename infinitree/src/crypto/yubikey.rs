//! Use a Yubikey to secure trees.
//!
//! This module re-exports the [`yubico_manager`] library, which
//! provides all the utilities to program a Yubikey.
//!
//! See the documentation for [`YubikeyCR`] for additional details.
use super::{symmetric::Symmetric, *};
use crate::ObjectId;
use ring::aead;
use secrecy::{ExposeSecret, SecretString};
use std::mem::size_of;
pub use yubico_manager;
use yubico_manager::Yubico;

type Nonce = [u8; 12];
type Challenge = [u8; 64];
type Response = [u8; 20];

const HEADER_PAYLOAD: usize =
    size_of::<SealedHeader>() - size_of::<Tag>() - size_of::<Nonce>() - size_of::<Challenge>();
const HEADER_CYPHERTEXT: usize =
    size_of::<SealedHeader>() - size_of::<Nonce>() - size_of::<Challenge>();

/// This mode's behaviour is equivalent to the
/// [`UsernamePassword`](crate::crypto::UsernamePassword) `KeySource`, but
/// adds a second factor.
///
/// ## Touch-to-sign configuration
///
/// In case you configure your Yubikey to
/// require a touch authorization for HMAC operations, you will need
/// to touch the Yubikey on both decrypt *and* encrypt operations.
///
/// If you are looking to secure a long-running job, or a background
/// process that periodically commits changes, this will probably not
/// be an optimal configuration for you.
///
/// ## Implementation details
///
/// The 512-byte binary header layout looks like so:
///
/// ```text
/// encrypt(root[88] || mode[1] || convergence_key[32] || 0[..]) || mac[16] || nonce[12] || yubikey_challenge[64]
/// ```
pub type YubikeyCR = KeyingScheme<YubikeyHeader, Symmetric>;
impl YubikeyCR {
    pub fn with_credentials(
        username: SecretString,
        password: SecretString,
        ykconfig: yubico_manager::config::Config,
    ) -> Result<Self> {
        let master_key = derive_argon2(
            b"zerostash.com yubikey cr master key",
            username.expose_secret().as_bytes(),
            password.expose_secret().as_bytes(),
        )?;

        Ok(Self::new(
            YubikeyHeader {
                master_key,
                ykconfig,
            },
            Symmetric::random()?,
        ))
    }
}

pub(crate) use private::*;
mod private {
    use super::*;

    pub struct YubikeyHeader {
        pub(super) master_key: RawKey,
        pub(super) ykconfig: yubico_manager::config::Config,
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

    impl HeaderScheme for YubikeyHeader {
        fn open_root(&self, header: SealedHeader) -> Result<OpenHeader> {
            let mut sealed = header.0;

            let mut challenge = [0; size_of::<Challenge>()];
            challenge.copy_from_slice(&sealed[HEADER_CYPHERTEXT + size_of::<Nonce>()..]);

            let aead = get_aead(header_key(
                &self.master_key,
                challenge,
                self.ykconfig.clone(),
            )?);
            let nonce = {
                let mut buf = Nonce::default();
                buf.copy_from_slice(
                    &sealed[HEADER_CYPHERTEXT..HEADER_CYPHERTEXT + size_of::<Nonce>()],
                );
                aead::Nonce::assume_unique_for_key(buf)
            };

            let _ = aead
                .open_in_place(nonce, aead::Aad::empty(), &mut sealed[..HEADER_CYPHERTEXT])
                .map_err(CryptoError::from)?;

            Ok(OpenHeader(sealed))
        }

        fn seal_root(&self, header: OpenHeader) -> Result<SealedHeader> {
            let mut output = header.0;
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

            //
            // Copy the n-once before it gets eaten by the aead.
            output[HEADER_CYPHERTEXT..HEADER_CYPHERTEXT + size_of::<Nonce>()]
                .copy_from_slice(nonce.as_ref());

            let aead = get_aead(header_key(
                &self.master_key,
                challenge,
                self.ykconfig.clone(),
            )?);
            let tag = aead.seal_in_place_separate_tag(
                nonce,
                aead::Aad::empty(),
                &mut output[..HEADER_PAYLOAD],
            )?;

            //
            // Dump tag and challenge
            output[HEADER_PAYLOAD..HEADER_PAYLOAD + size_of::<Tag>()].copy_from_slice(tag.as_ref());
            output[HEADER_CYPHERTEXT + size_of::<Nonce>()..].copy_from_slice(&challenge);

            Ok(SealedHeader(output))
        }

        fn root_object_id(&self) -> Result<ObjectId> {
            super::symmetric::root_object_id(&self.master_key)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::Scheme;
    use std::sync::Arc;

    #[test]
    #[ignore]
    fn userpass_encrypt_decrypt() {
        use super::YubikeyCR;
        use crate::chunks::RawChunkPointer;
        use yubico_manager::{config::Config, Yubico};

        let mut yubi = Yubico::new();
        let ykconfig = if let Ok(device) = yubi.find_yubikey() {
            Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
        } else {
            panic!("No Yubikey")
        };

        let seal_key = YubikeyCR::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
            ykconfig.clone(),
        )
        .unwrap();

        let header = seal_key.seal_root(&Default::default()).unwrap();
        let open_key = YubikeyCR::with_credentials(
            "test".to_string().into(),
            "test".to_string().into(),
            ykconfig,
        )
        .unwrap();

        let open_header = Arc::new(open_key).open_root(header).unwrap();
        assert_eq!(open_header.root_ptr, RawChunkPointer::default());
    }
}
