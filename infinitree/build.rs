fn main() {
    if cfg!(all(feature = "rustls", feature = "native-tls")) {
        println!("cargo:warning=Features `rustls` and `native-tls` are mutually exclusive!");
        std::process::exit(1);
    }

    println!("cargo:rustflags=-Ctarget-feature=+aes,+ssse3");
}
