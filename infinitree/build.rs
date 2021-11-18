fn main() {
    println!("cargo:rustflags=-Ctarget-feature=+aes,+ssse3");

    // NB: bench and doctest don't quite make sense, you MUST manually
    // enable the `_test` feature
    if cfg!(any(bench, doctest, test, feature = "_test")) {
        println!("cargo:rustc-cfg=infinitest");
    }
}
