#!/bin/bash
set -ex

# Setup shortcuts.
ROOT=`pwd`

# Clone nginx read-only git repository.
git clone https://github.com/nginx/nginx.git

# Build nginx + filter module.
cd $ROOT/nginx
./auto/configure --prefix=$ROOT/script/test --add-module=$ROOT
make

# Build brotli CLI.
cd $ROOT/deps/brotli
mkdir out
cd out
cmake ..
make brotli

# Restore status-quo.
cd $ROOT
