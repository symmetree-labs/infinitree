//! Encryption key management and secure hashing
//!
//! The modules exported are all optional keying schemes that can be
//! toggled with Cargo features.
//!
//! # The default symmetric scheme
//!
//! Trees in the simplest case will use the [`UsernamePassword`]
//! keying scheme, which provides a symmetric encryption mechanism.
//!
//! # Asymmetric schemes
//!
//! To create a split key that allows differentiating between reader
//! and writer keys, enable the `cryptobox` Cargo feature. This will
//! allow you to use an asymmetric scheme to encrypt data in the
//! `storage` segments of your tree, but keep the indexes
//! symmetrically encrypted.
//!
//! # Hardware-bound encryption
//!
//! Infinitree has native support for using a Yubikey's
//! Challenge-Response HMAC-SHA1 mode to encrypt the header of the
//! tree, enabled by the `yubikey` Cargo feature.
//!
//! To allow for configuring the Yubikey, the `yubico_manager` crate
//! is re-exported.
//!
//! # Changing keys
//!
//! Changing of the header key is supported through by creating a
//! special key through [`ChangeHeaderKey::swap_on_seal`] constructor.
//!
//! Because changing the internal keys might potentially require
//! re-encrypting the entire archive in a way that's not possible to
//! do with the Infinitree library, the implementation of such a
//! change is up to your specific use case.
//!
//! For instance, let's assume you crate a symmetrically keyed tree,
//! then write data into the `storage` segment of it.
//!
//! ```no_run
//! use infinitree::{*,
//!                  crypto::*,
//!                  object::Writer, fields::VersionedMap, backends::Directory};
//!
//! let key = UsernamePassword::with_credentials("username".to_string(),
//!                                              "old_password".to_string()).unwrap();
//!
//! let mut tree = Infinitree::<VersionedMap<String, ChunkPointer>>::open(
//!     Directory::new("/storage").unwrap(),
//!     key
//! ).unwrap();
//!
//! // get access to the custom `storage` segment of the tree
//! let mut writer = tree.storage_writer().unwrap();
//!
//! // use the writer to write data
//! let ptr = writer.write(b"my precious secret").unwrap();
//!
//! // then store it in the index
//! tree.index().insert("Gollum?".into(), ptr);
//!
//! tree.commit("My first shenanigans");
//! ```
//!
//! Changing the internal key at this point to
//! e.g. `cryptobox::StorageOnly` would mean that all existing data in
//! the stash, referenced only through [`ChunkPointer`](crate::ChunkPointer)s is now
//! inaccessible.
//!
//! For the sake of straightforward use and space efficiency of chunk
//! references, this is not permitted.
pub use blake3::Hasher;
use ring::aead;
pub(crate) use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, zeroize::Zeroize};

mod error;
mod header;
mod ops;
mod rawkey;
mod scheme;

pub(crate) mod symmetric;
pub(crate) use error::*;
pub(crate) use header::*;
pub(crate) use ops::*;
pub use rawkey::*;
pub use scheme::*;
pub use symmetric::UsernamePassword;

#[cfg(feature = "cryptobox")]
pub mod cryptobox;

#[cfg(feature = "yubikey")]
pub mod yubikey;

const CRYPTO_DIGEST_SIZE: usize = 32;

// TODO: ideally this should be a tuple struct wrapping blake3::Hash,
// implementing Serialize & Deserialize and the rest.
//
// That way we get constant time equality checks for free, which is
// prudent to want, but I'm uncertain about a realistic side-channel
// based on this right now.
/// A cryptographic hash of some data
pub type Digest = [u8; CRYPTO_DIGEST_SIZE];

/// HMAC generated by an AEAD scheme
pub type Tag = [u8; 16];

#[inline]
fn get_aead(key: RawKey) -> aead::LessSafeKey {
    let key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.expose_secret()).expect("bad key");
    aead::LessSafeKey::new(key)
}

fn derive_argon2(secret: &[u8], salt_raw: &[u8], password: &[u8]) -> Result<RawKey> {
    let salt = blake3::hash(salt_raw);

    let mut result = argon2::hash_raw(
        password,
        salt.as_bytes(),
        &argon2::Config {
            hash_length: CRYPTO_DIGEST_SIZE as u32,
            variant: argon2::Variant::Argon2id,
            secret,
            ..argon2::Config::default()
        },
    )?;

    let mut outbuf = [0; CRYPTO_DIGEST_SIZE];
    outbuf.copy_from_slice(&result);
    result.zeroize();

    Ok(outbuf.into())
}

fn derive_subkey(key: &RawKey, ctx: &str) -> Result<RawKey> {
    let outbuf = blake3::derive_key(ctx, key.expose_secret());
    Ok(outbuf.into())
}

fn generate_key(rand: &impl SecureRandom) -> Result<RawKey> {
    let mut buf = [0; KEY_SIZE];
    rand.fill(&mut buf)?;
    Ok(buf.into())
}
