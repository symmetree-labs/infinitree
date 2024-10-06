{
  inputs = rec {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    utils = { url = "github:numtide/flake-utils"; };
  };

  outputs = { self, nixpkgs, utils, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        overlays = [ ];
        pkgs = import nixpkgs { inherit system overlays; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs;
            [
              iconv
              cargo-edit
              clippy
              cargo
              rustc
              rust-analyzer
              rustfmt
              cargo-workspaces
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              macfuse-stubs
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
              darwin.apple_sdk.frameworks.CoreServices
            ];
          RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
          SODIUM_LIB_DIR = "${pkgs.pkgsStatic.libsodium}/lib";
        };

        formatter = pkgs.nixfmt;
      });
}
