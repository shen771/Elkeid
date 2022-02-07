#!/bin/bash
set -e
BUILD_VERSION="1.7.0.1"

mkdir -p output
RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-musl --release
cp target/x86_64-unknown-linux-musl/release/driver output/driver-linux-amd64-${BUILD_VERSION}.plg
