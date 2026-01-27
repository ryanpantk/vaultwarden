#!/bin/bash

# Start postgres if not running
cd /Users/jon/CsProjects/script && docker compose up -d db

# Run vaultwarden with hot-reload
# .env file in the project root is automatically loaded by vaultwarden at runtime
cd /Users/jon/CsProjects/vaultwarden && cargo watch -x 'run --features "postgresql"'
