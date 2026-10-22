# justfile for evomi-proxy-bridge (Tauri + Rust core)
# Local Linux note: ayatana-appindicator3 has no dev package here (no sudo),
# so a shimmed .pc lives at ~/.local/lib/pkgconfig (see README). The export
# below picks it up; CI installs the real dev packages instead.
export PKG_CONFIG_PATH := env_var_or_default("HOME", "/root") + "/.local/lib/pkgconfig:" + env_var_or_default("PKG_CONFIG_PATH", "")

# list recipes
default:
    @just --list

# rust core tests (fake upstream + TLS fixtures, no network)
test:
    cargo test -p evomi-bridge-core

# fast typecheck of everything
check:
    cargo check --workspace

# production build (bundles land in src-tauri/target/release/bundle/)
build:
    cd src-tauri && cargo tauri build

# run the desktop app in dev mode
dev:
    cd src-tauri && cargo tauri dev

# regenerate icons from an svg source
icon src="icons/icon.svg":
    cd src-tauri && cargo tauri icon {{ src }}

clean:
    cargo clean
