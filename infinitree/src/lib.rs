//! Infinitree is a versioned, embedded database that uses uniform,
//! encrypted blobs to store data.
//!
//! Multiple writers can use the same storage, but not the same tree
//! safely at the same time.
//!
//! Calling Infinitree a database may be generous, as all
//! persistence-related operations are explicit.
//!
//! ## Features
//!
//!  * Thread-safe by default
//!  * Transparently handle hot/warm/cold storage tiers; currently S3-compatible backends is supported
//!  * Versioned data structures that can be queried using the `Iterator` trait without loading in full
//!  * Encrypt all on-disk data, and only decrypt it on use
//!  * Focus on performance and control over memory use
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
//!     );
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
//! [`Infinitree`] is a versioned data store interface that is the
//! first point of contact with the library. It provides convenience
//! functions to work on different versions of the database index, and
//! access random access data using pointers.
//!
//! There are 2 types of interactions with an infinitree: one that's
//! happening through an index, and one that's directly exposing
//! random access data.
//!
//! Any data stored outside of an index will receive a `ChunkPointer`,
//! which _must_ be stored somewhere to retrieve the data. Hence the
//! need for an index.
//!
//! Indexes can be any struct that implement the [`Index`]
//! trait. There's also a helpful [derive macro](derive@Index) that
//! helps you do this. An index will consist of various fields, which
//! act like regular old Rust types, but need to implement a few
//! traits to help serialization.
//!
//! ### Infinitree
//!
//! [`Infinitree`] provides high-level versioning, querying, and key
//! and memory management operations for working with the different
//! [`fields`] in the [`Index`].
//!
//! An Infinitree instance is mainly acting as a context for all
//! operations on the tree, and will be your first entry point when
//! working with trees and persisting them.
//!
//! Here you can select different versions for the index to interact
//! with, and create new commits.
//!
//! ### Index
//!
//! You can think about your `Index` as a schema. Or really just the
//! central struct definition for your data.
//!
//! In a more abstract sense, the [`Index`] trait and corresponding
//! [derive macro](derive@Index) represent a view into a single
//! version of your database. Using an [`Infinitree`] you can swap
//! between the various versions and mix-and-match data from various
//! versions into a single `Index` instance.
//!
//! Interaction with `Index` member fields is straightforward. The
//! [derive macro](derive@Index) will generate functions that produce
//! an [`Intent`] for any operation that touches the persistence
//! layer, such as [`Store`] and [`Load`].
//!
//! ### Fields
//!
//! An `Index` contains serializable fields. These are thread-safe
//! data structures with internal mutation, which support some kind of
//! serialization [`Strategy`].
//!
//! You can use any type that implements [`serde::Serialize`] as a
//! field through the `fields::Serialized` wrapper type, but there are
//! incremental hash map and list-like types available for you to use
//! to track and only save changes between versions of your data.
//!
//! Persisting and loading fields is done using an [`Intent`]
//! wrapper. If you use the [`Index`][derive@Index] macro, this will
//! automatically create accessor functions for each field in an
//! index, that return an `Intent` wrapped strategy.
//!
//! Intents elide the specific types of the field and allow doing
//! batch operations, e.g. when calling [`Infinitree::commit`] using a
//! different strategy for each field in an `Index`.
//!
//! ### Strategy
//!
//! To tell Infinitree how to serialize a field, you can use different
//! strategies. A strategy has full control over the field and the
//! serializers/loader transactions for it, which means you can
//! control the placement of pieces of data.
//!
//! Every strategy receives an `Index` transaction, and a
//! [`object::Reader`] or [`object::Writer`]. It is the responsibility
//! of the strategy to store [references](ChunkPointer) so you can
//! load back the data once persisted.
//!
//! There are 2 strategies in the base library:
//!
//!  * [`LocalField`]: Store all of the data in the index. This is the
//!  default.
//!  * [`SparseField`]: Store values in a Map outside of the
//!  index. Best suited for large structs as values.
//!
//! Deciding which strategy is best for your use case may mean you
//! have to run some experiments and benchmarks. A `SparseField` is
//! generally useful for indexing large structs that you want to query
//! rather than load all at once.
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

#![deny(
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
pub mod index;
pub mod object;
pub mod tree;

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

#[cfg(test)]
const TEST_DATA_DIR: &'static str = "test_data";
