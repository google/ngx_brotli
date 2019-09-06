#!/bin/bash
set -ex

# Setup shortcuts.
ROOT=`pwd`
FILES=$ROOT/script/test

# Setup directory structure.
cd $ROOT/script
mkdir test
cd test
mkdir logs

# Download sample texts.
curl --compressed -o $FILES/war-and-peace.txt http://www.gutenberg.org/files/2600/2600-0.txt
echo "Kot lomom kolol slona!" > $FILES/small.txt

# Restore status-quo.
cd $ROOT
