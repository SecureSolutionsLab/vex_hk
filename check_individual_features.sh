#!/bin/bash

# Checks for errors in individual feature compilations
# (sadly this often triggers a full recompilation)
echo "Compiling \"alienvault\""
RUSTFLAGS=-Awarnings cargo check --lib --no-default-features --features "alienvault"
echo

echo "Compiling \"exploitdb\""
RUSTFLAGS=-Awarnings cargo check --lib --no-default-features --features "exploitdb"
echo

echo "Compiling \"nvd\""
RUSTFLAGS=-Awarnings cargo check --lib --no-default-features --features "nvd"
echo

echo "Compiling \"osv\""
RUSTFLAGS=-Awarnings cargo check --lib --no-default-features --features "osv"
