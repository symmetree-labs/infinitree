//! Infinitree is a versioned, embedded database that uses uniform,
//! encrypted blobs to store data.
//!
//! It works best for use cases with independent writer processes, as
//! multiple writer processes on a single tree are not supported.
//!
//! ## Features
//!
//!  * Thread-safe by default
//!  * Transparently handle hot/warm/cold storage tiers; currently S3-compatible backends is supported
//!  * Versioned data structures that can be queried using the `Iterator` trait without loading in full
//!  * Encrypt all on-disk data, and only decrypt it on use
//!  * Focus on performance and flexible choice of performance/memory use tradeoffs
//!  * Extensible for custom data types and storage strategies
//!  * Easy to integrate with cloud workers & KMS for access control
//!
//! ## Core concepts
//! ### Infinitree
//!
//! [`Infinitree`] provides high-level versioning, querying, and key
//! and memory management operations for working with the different
//! [`fields`] in the [`Index`].
//!
//!
//!
//!

#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    unused_crate_dependencies,
    unused_lifetimes,
    unused_qualifications
)]
#![deny(clippy::all)]
#![allow(clippy::ptr_arg)]

#[macro_use]
extern crate serde_derive;

pub mod backends;
mod chunks;
mod compress;
mod crypto;
pub mod fields;
pub mod index;
pub mod object;
mod tree;

pub use backends::Backend;
pub use chunks::ChunkPointer;
pub use crypto::{secure_hash, Digest, Key};
pub use index::Index;
pub use object::ObjectId;
pub use tree::Infinitree;

pub use anyhow;
pub use infinitree_macros::Index;

use rmp_serde::decode::from_read_ref as deserialize_from_slice;
use rmp_serde::to_vec as serialize_to_vec;
use rmp_serde::Deserializer;

// Use block size of 4MiB for now
const BLOCK_SIZE: usize = 4 * 1024 * 1024;
