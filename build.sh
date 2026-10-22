#!/bin/sh
# Rebuilds workers_tls.wasm. Needs rustup (rust-toolchain.toml pins Rust and
# the wasm32-wasip1 target) and clang 18 with a wasm backend for ring's C.
# Paths are remapped so the module is byte-for-byte the same on any machine
# with the same toolchain: CI rebuilds it and compares.
set -eu
cd "$(dirname "$0")"
target="${CARGO_TARGET_DIR:-target}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$(pwd)=/workers-tls" \
  cargo build --release --locked --target wasm32-wasip1
cp "$target/wasm32-wasip1/release/workers_tls.wasm" workers_tls.wasm
ls -l workers_tls.wasm
