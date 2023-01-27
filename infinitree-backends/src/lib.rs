//! Additional backends to be used with
//! [Infinitree](https://github.com/symmetree-labs/infinitree).
//!
#![forbid(unsafe_code)]
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

#[macro_use]
extern crate serde_derive;

mod cache;
pub use cache::*;

mod s3;
pub use s3::*;

use std::future::Future;
use tokio::{runtime, task};

pub(crate) fn block_on<O>(fut: impl Future<Output = O>) -> O {
    task::block_in_place(move || runtime::Handle::current().block_on(fut))
}

#[cfg(test)]
mod test {
    use infinitree::{backends::Backend, object::WriteObject};

    pub(crate) const TEST_DATA_DIR: &str = "../test_data";

    pub(crate) fn write_and_wait_for_commit(backend: &impl Backend, object: &WriteObject) {
        backend.write_object(object).unwrap();
        backend.sync().unwrap();
    }
}
