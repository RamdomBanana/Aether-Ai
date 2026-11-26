#!/usr/bin/env sh
# Vendor every crates.io dependency into ./vendor so that all later builds are offline.
# Run ONCE on a machine with network access, then commit vendor/ and .cargo/config.toml.
# Re-run only when a dependency is added or bumped.
set -eu
cd "$(dirname "$0")/.."

# A previous offline config would block `cargo vendor` from reaching the registry.
rm -f .cargo/config.toml
mkdir -p .cargo

cargo vendor --versioned-dirs vendor > .cargo/config.toml
cat >> .cargo/config.toml <<'CFG'

[net]
offline = true
CFG

echo "vendored $(ls vendor | wc -l) crates; builds are now offline (.cargo/config.toml written)"
