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
