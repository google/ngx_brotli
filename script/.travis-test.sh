#!/bin/bash
set -ex

# Setup shortcuts.
ROOT=`pwd`
NGINX=$ROOT/nginx/objs/nginx
BROTLI=$ROOT/deps/brotli/out/brotli
SERVER=http://localhost:8080
FILES=$ROOT/script/test

# Start server.
$NGINX -c $ROOT/script/test.conf

# Download long file with rate limit; ~5 sec.
curl -H 'Accept-encoding: br' -o ./war-and-peace.br --limit-rate 300K $SERVER/war-and-peace.txt
$BROTLI -dfk ./war-and-peace.br
cmp war-and-peace $FILES/war-and-peace.txt

# 404 response (compare against vanilla version).
curl -H 'Accept-encoding: br' -o ./notfound.br $SERVER/notfound
$BROTLI -dfk ./notfound.br
curl -o ./notfound.txt $SERVER/notfound
cmp notfound notfound.txt

# Stop server.
$NGINX -c $ROOT/script/test.conf -s stop

# Restore status-quo.
cd $ROOT
