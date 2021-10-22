Infinitree
----------

[![Crates.io][crates-badge]][crates-url]
[![docs.rs][docs-badge]][docs-url]
[![Build Status][actions-badge]][actions-url]
[![MIT licensed][mit-badge]][mit-url]
[![Apache2 licensed][apache2-badge]][apache2-url]

[crates-badge]: https://img.shields.io/crates/v/infinitree.svg
[crates-url]: https://crates.io/crates/infinitree
[docs-badge]: https://docs.rs/infinitree/badge.svg
[docs-url]: https://docs.rs/infinitree
[actions-badge]: https://github.com/symmetree-labs/infinitree/workflows/CI/badge.svg
[actions-url]: https://github.com/symmetree-labs/infinitree/actions?query=workflow%3ACI+branch%3Amaster
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache2-badge]: https://img.shields.io/badge/license-Apache2-red.svg

Infinitree is a versioned, embedded database that uses uniform,
encrypted blobs to store data.

It works best for use cases with independent writer processes, as
multiple writer processes on a single tree are not supported.

In fact, calling Infinitree a database may be generous, as all
persistence-related operations are explicit. Under the hood, it's
using `serde` for flexibility and interoperability with the most
libraries out of the box.

## Features

 * Thread-safe by default
 * Transparently handle hot/warm/cold storage tiers; currently S3-compatible backends is supported
 * Versioned data structures that can be queried using the `Iterator` trait without loading in full
 * Encrypt all on-disk data, and only decrypt it on use
 * Focus on performance and flexible choice of performance/memory use tradeoffs
 * Extensible for custom data types and storage strategies
 * Easy to integrate with cloud workers & KMS for access control

## Example use

```rust
use infinitree::{
    Infinitree,
    Index,
    Key,
    anyhow,
    backends::Directory,
    fields::{Serialized, VersionedMap, LocalField},
};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PlantHealth {
    id: usize,
    air_humidity: usize,
    soil_humidity: usize,
    temperature: f32
}

#[derive(Index, Default, Clone)]
pub struct Measurements {
    // rename the field when serializing
    #[infinitree(name = "last_time")]
    _old_last_time: Serialized<String>,

    #[infinitree(name = "last_time2")]
    last_time: Serialized<usize>,

    // only store the keys in the index, not the values
    #[infinitree(strategy = "infinitree::fields::SparseField")]
    measurements: VersionedMap<usize, PlantHealth>,

    // skip the next field when loading & serializing
    #[infinitree(skip)]
    current_time: usize,
}

fn main() -> anyhow::Result<()> {
    let mut tree = Infinitree::<Measurements>::empty(
        Directory::new("/storage")?,
        Key::from_credentials("username", "password")?
    );

    tree.index().measurements.insert(1, PlantHealth {
        id: 0,
        air_humidity: 50,
        soil_humidity: 60,
        temperature: 23.3,
    });

    *tree.index().last_time.write() = 1;
    tree.commit("first measurement! yay!");
    Ok(())
}
```

## Versioning

Infinitree supports versioning data sets, similarly to Git does with files.

While some index fields work as snapshots (eg. `Serialized<T>`), and
serialize the entire content on each commit, it is possible to use
eg. `VersionedMap<K, V>` as an incremental HashMap.

Versioned types only store differences from the currently loaded state.

It also possible to restore state selectively, or create completely
disparate branches of data for each commit, depending on the use case.

## Caching

Data is always moved as part of objects. 

This mechanism allows for indexing hundreds of terrabytes of data that
span multiple disks and cloud storage platforms, while only
synchronizing and loading into memory a small proportion of that.

Application developers can use fine-grained control of cache layers
using simple strategies, eg. Least-Recently-Used, where recently
queried objects can be stored in a local directory, while the rest is
in an S3 bucket.

## Object system

The core of Infinitree is an object system that stores all data in
uniform 4MiB blobs, encrypted. Objects are named using 256 bit random
identifiers, which have _no_ correlation to the content. Indexing data
and overlaying it on the physical objects is an interesting problem.

There are 2 types of objects in the Infinitree storage model, which
are indistinguishable to the storage layer.

 * **Indexes** are encrypted as a 4MB unit, and support versioning of
     serializable data structures.
 * **Storage Objects** stores and encrypts chunks of data
     independently, located by a `ChunkPointer`.

In both cases, knowledge of the master, symmetric encryption key is
necessary to access the stored data.

To establish a root of trust, a username/password combination is used
to derive an passphrase using Argon 2. The Argon 2 output locates the
so called **root object**, which is the root of the versioned index
tree.

Since the system requires _some_ objects to have a deterministic
identifier, all objects IDs are uncorrelated with the data they
store.

Ensuring integrity of data is done using an ChaCha20-Poly1305
AEAD. The `ChunkPointer` stores the tags for all data encrypted in
_storage objects_, while the tags are appended to the end of all
_index objects_.

Note that while the master key is necessary to access the root object,
there are multiple subkeys used internally, which means layering other
(e.g. public key) encryption methods onto data stored in indexes is
safe.

For a more in-depth overview of the security and attacker model of the
object system, please see the [DESIGN.md] document.

## Warning

This is an unreviewed piece of experimental security software.

**DO NOT USE FOR CRITICAL WORKLOADS OR APPLICATIONS.**

## License

Released under the [MIT][mit-url] and [Apache 2][apache2-url] licenses.

## Support

If you are interested in using Infinitree in your application, and
would like to work with Symmetree Research Labs on features or
implementation, [get in touch](mailto:hello@symmetree.dev).

[mit-url]: https://github.com/symmetree-labs/infinitree/blob/master/LICENSE
[apache2-url]: https://github.com/symmetree-labs/infinitree/blob/master/LICENSE-APACHE2
[DESIGN.md]: https://github.com/symmetree-labs/infinitree/blob/master/DESIGN.md
