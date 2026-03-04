#!/bin/bash
# Vaultwarden local development with hot-reload
# Usage: ./dev.sh [cargo-watch args]

export PKG_CONFIG_PATH="/opt/homebrew/opt/postgresql@14/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig"
export LIBRARY_PATH="/opt/homebrew/opt/postgresql@14/lib:/opt/homebrew/opt/openssl@3/lib"

exec cargo watch -x 'run --features postgresql' -w src/ "$@"
