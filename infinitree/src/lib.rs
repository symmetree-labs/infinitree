//! Infinitree is a versioned, embedded database that uses uniform,
//! encrypted blobs to store data.
//!
//! It works best for use cases with independent writer processes, as
//! multiple writer processes on a single tree are not supported.
//!
//! In fact, calling Infinitree a database may be generous, as all
//! persistence-related operations are explicit. Under the hood, it's
//! using `serde` for flexibility and interoperability with the most
//! libraries out of the box.
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
//! ## Example use
//!
//! ```no_run
//! use infinitree::{
//!     Infinitree,
//!     Index,
//!     Key,
//!     anyhow,
//!     backends::Directory,
//!     fields::{Serialized, VersionedMap, LocalField},
//! };
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct PlantHealth {
//!     id: usize,
//!     air_humidity: usize,
//!     soil_humidity: usize,
//!     temperature: f32
//! }
//!
//! #[derive(Index, Default, Clone)]
//! pub struct Measurements {
//!     // rename the field when serializing
//!     #[infinitree(name = "last_time")]
//!     _old_last_time: Serialized<String>,
//!
//!     #[infinitree(name = "last_time2")]
//!     last_time: Serialized<usize>,
//!
//!     // only store the keys in the index, not the values
//!     #[infinitree(strategy = "infinitree::fields::SparseField")]
//!     measurements: VersionedMap<usize, PlantHealth>,
//!
//!     // skip the next field when loading & serializing
//!     #[infinitree(skip)]
//!     current_time: usize,
//! }
//!
//! fn main() -> anyhow::Result<()> {
//!     let mut tree = Infinitree::<Measurements>::empty(
//!         Directory::new("/storage")?,
//!         Key::from_credentials("username", "password")?
//!     );
//!
//!     tree.index().measurements.insert(1, PlantHealth {
//!         id: 0,
//!         air_humidity: 50,
//!         soil_humidity: 60,
//!         temperature: 23.3,
//!     });
//!
//!     *tree.index().last_time.write() = 1;
//!     tree.commit("first measurement! yay!");
//!     Ok(())
//! }
//! ```
//!
//! ## Core concepts
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
//! Persisting any [field](#fields-1) in an [Index](#index) will require
//! an [`Intent`] to ensure the right
//! [`Strategy`] is being used for
//! persistence.
//!
//! ### Index
//!
//! In the most simplistic case, you can think about your Index as a
//! schema for a tree.
//!
//! In a more complicated setup, the [`Index`] trait and
//! corresponding [derive macro](derive@Index) represent an view into
//! a single version of your data. Using an [`Infinitree`] you can
//! swap between the various versions and mix-and-match data from
//! various versions into a single Index instance.
//!
//! Interaction with Index member fields is straightforward. However,
//! the [derive macro](derive@Index) will generate functions that
//! produce an [`Intent`] for any operation that touches the
//! persistence layer, such as [`Store`] and [`Load`].
//!
//! ### Fields
//!
//! An Index consists of fields. These are thread-safe data structures
//! with internal mutation, which support some kind of serialization
//! [`Strategy`].
//!
//! You can use any type that implements [`serde::Serialize`] as a
//! field, through the `fields::Serialized` wrapper type.
//!
//! Persisting and loading fields is done using an [`Intent`]
//! wrapper. If you use the [`Index`][derive@Index] macro, this will
//! automatically create accessor functions for each field in an
//! index, that return an `Intent` wrapped strategy.
//!
//! This is to elide the specific types and allow doing batch
//! operations, e.g. when calling [`Infinitree::commit`] using a
//! different strategy for each field in an Index.
//!
//! ### Strategy
//!
//! To tell Infinitree how to serialize an field, you can use different
//! strategies. A strategy has full control over the field and the
//! serializers/loader transactions for it, which means you can
//! control the performance and placement of pieces of data.
//!
//! Every strategy receives an Index transaction, and a Object
//! reader/writer. It is the responsibility of the strategy to store
//! references so you can load back the data once persisted.
//!
//! There are 2 strategies in the base library:
//!
//!  * [`LocalField`]: Store all of the data in the index. This is the
//!  default.
//!  * [`SparseField`]: Store values in a Map outside of the
//!  index. Best suited for large structs as values.
//!
//! Deciding which strategy is best for your use case may mean you
//! have to run some experiments. A `SparseField` is generally useful
//! for indexing large structs that you want to query rather than load
//! at once.
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

#[cfg(not(feature = "tokio"))]
use futures as _;

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

#[cfg(test)]
const TEST_DATA_DIR: &'static str = "test_data";
