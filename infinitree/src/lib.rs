//! Infinitree is a versioned, embedded database that uses uniform,
//! encrypted blobs to store data.
//!
//! Infinitree is based on a set of lockless and locking data
//! structures that you can use in your application as a regular map
//! or list.
//!
//! Data structures:
//!
//!  * [`fields::VersionedMap`]: A lockless HashMap that tracks incremental changes
//!  * [`fields::Map`]: A lockless HashMap
//!  * [`fields::LinkedList`]: Linked list that tracks incremental changes
//!  * [`fields::List`]: A simple `RwLock<Vec<_>>` alias
//!  * [`fields::Serialized`]: Any type that implements [`serde::Serialize`]
//!
//! Tight control over resources allows you to use it in situations
//! where memory is scarce, and fall back to querying from slower
//! storage.
//!
//! Additionally, Infinitree is useful for securely storing and sharing
//! any [`serde`](https://docs.rs/serde) serializable application
//! state, or dumping and loading application state changes through
//! commits. This is similar to [Git](https://git-scm.com).
//!
//! In case you're looking to store large amounts of binary blobs, you
//! can open a [`BufferedSink`][object::BufferedSink], which supports
//! `std::io::Write`, and store arbitrary byte streams in the tree.
//!
//! ## Features
//!
//!  * Encrypt all on-disk data, and only decrypt on use
//!  * Transparently handle hot/warm/cold storage tiers; currently S3-compatible backends are supported
//!  * Versioned data structures allow you to save/load/fork application state safely
//!  * Thread-safe by default
//!  * Iterate over random segments of data without loading to memory in full
//!  * Focus on performance and fine-grained control of memory use
//!  * Extensible for custom data types, storage backends, and serialization
//!
//! ## Example use
//!
//! ```
//! use infinitree::{
//!     Infinitree,
//!     Index,
//!     Key,
//!     anyhow,
//!     backends::Directory,
//!     fields::{VersionedMap},
//! };
//! use serde::{Serialize, Deserialize};
//!
//! fn main() -> anyhow::Result<()> {
//!     let mut tree = Infinitree::<VersionedMap<String, usize>>::empty(
//!         Directory::new("test_data")?,
//!         Key::from_credentials("username", "password")?
//!     ).unwrap();
//!
//!     tree.index().insert("sample_size".into(), 1234);
//!
//!     tree.commit("first measurement! yay!");
//!     Ok(())
//! }
//! ```
//!
//! ## Core concepts
//!
//! [`Infinitree`] provides is the first entry point to the
//! library. It creates, saves, and queries various versions of your
//! [`Index`].
//!
//! There are 2 types of interactions with an infinitree: one that's
//! happening through an [`Index`], and one that's directly accessing
//! the [`object`] structure.
//!
//! Any data stored in infinitree objects will receive a `ChunkPointer`,
//! which _must_ be stored somewhere to retrieve the data. Hence the
//! need for an index.
//!
//! An index can be any struct that implements the [`Index`]
//! trait. There's also a helpful [derive macro](derive@Index) that
//! helps you do this. An index will consist of various fields, which
//! act like regular old Rust types, but need to implement a few
//! traits to help serialization.
//!
//! ### Index
//!
//! You can think about your `Index` as a schema. Or just application
//! state on steroids.
//!
//! In a more abstract sense, the [`Index`] trait and corresponding
//! [derive macro](derive@Index) represent a view into a single
//! version of your database. Using an [`Infinitree`] you can swap
//! between, and mix-and-match data from, various versions of an
//! `Index` state.
//!
//! ### Fields
//!
//! An `Index` contains serializable fields. These are thread-safe
//! data structures with internal mutation, which support some kind of
//! serialization [`Strategy`].
//!
//! You can use any type that implements [`serde::Serialize`] as a
//! field through the `fields::Serialized` wrapper type, but there are
//! [incremental hash map][fields::VersionedMap] and
//! [list-like][fields::LinkedList] types available for you to use to
//! track and only save changes between versions of your data.
//!
//! Persisting and loading fields is done using an [`Intent`].  If you
//! use the [`Index`][derive@Index] macro, it will automatically
//! create accessor functions for each field in an index, and return
//! an `Intent` wrapped strategy.
//!
//! Intents elide the specific types of the field and allow doing
//! batch operations, e.g. when calling [`Infinitree::commit`] using a
//! different strategy for each field in an index.
//!
//! ### Strategy
//!
//! To tell Infinitree how to serialize a field, you can use different
//! strategies. A [`Strategy`] has full control over how a data structure
//! is serialized in the object system.
//!
//! Every strategy receives an `Index` transaction, and an
//! [`object::Reader`] or [`object::Writer`]. It is the responsibility
//! of the strategy to store [references](ChunkPointer) so you can
//! load back the data once persisted.
//!
//! There are 2 strategies in the base library:
//!
//!  * [`LocalField`]: Serialize all data in a single stream.
//!  * [`SparseField`]: Serialize keys and values of a Map in separate
//!  streams. Useful for quickly iterating over key indexes when
//!  querying. Currently only supports values smaller than 4MB.
//!
//! Deciding which strategy is best for your use case may mean you
//! have to run some experiments and benchmarks.
//!
//! See the documentation for the [`Index`][derive@Index] macro to see how to
//! use strategies.
//!
//! [`Intent`]: fields::Intent
//! [`Strategy`]: fields::Strategy
//! [`Load`]: fields::Load
//! [`Store`]: fields::Store
//! [`LocalField`]: fields::LocalField
//! [`SparseField`]: fields::SparseField
//!
//! ## Cryptographic design
//!
//! To read more about how the object system keeps your data safe,
//! please look at
//! [DESIGN.md](https://github.com/symmetree-labs/infinitree/blob/main/DESIGN.md)
//! file in the main repository.

#![deny(
    arithmetic_overflow,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    unused_crate_dependencies,
    unused_lifetimes,
    unused_qualifications,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::private_intra_doc_links
)]
#![deny(clippy::all)]
#![allow(clippy::ptr_arg)]

#[cfg(any(test, doctest, bench))]
use criterion as _;

#[cfg(all(any(test, doctest, bench), not(feature = "s3")))]
use s3_server as _;

#[cfg(all(any(test, doctest, bench), not(feature = "s3")))]
use hyper as _;

#[macro_use]
extern crate serde_derive;

pub mod backends;
mod chunks;
mod compress;
mod crypto;
pub mod fields;
mod id;
pub mod index;
pub mod object;
pub mod tree;

pub use backends::Backend;
pub use chunks::ChunkPointer;
pub use crypto::{secure_hash, Digest, Key};
pub use id::Id;
pub use index::Index;
pub use object::ObjectId;
pub use tree::Infinitree;

pub use anyhow;

pub use infinitree_macros::Index;

use rmp_serde::decode::from_slice as deserialize_from_slice;
use rmp_serde::encode::write as serialize_to_writer;
use rmp_serde::to_vec as serialize_to_vec;
use rmp_serde::Deserializer;

// Use block size of 4MiB for now
const BLOCK_SIZE: usize = 4 * 1024 * 1024;

#[cfg(test)]
const TEST_DATA_DIR: &'static str = "test_data";
