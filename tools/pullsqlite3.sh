#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/../vendor"

# Remove existing sqlite3 vendor directory to ensure no stale files remain
rm -rf "$VENDOR_DIR/sqlite3"

wget https://www.sqlite.org/2026/sqlite-amalgamation-3510300.zip
unzip sqlite-amalgamation-3510300.zip
mv sqlite-amalgamation-3510300 "$VENDOR_DIR/sqlite3"
rm sqlite-amalgamation-3510300.zip
