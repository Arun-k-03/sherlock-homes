# Windows / Linux / macOS / Termux notes

Core is a single Rust binary (`sherlock`). Optional engines (Nuclei, Katana, httpx, ZAP) are discovered on PATH and skipped if missing.

## Windows

Requires a C toolchain for `rusqlite` (bundled SQLite):

- Visual Studio Build Tools with C++ workload, or
- MinGW-w64 / WinLibs plus `stable-x86_64-pc-windows-gnu`

```powershell
cargo build --release
.\target\release\sherlock.exe doctor
```

## Linux (x86_64 and aarch64)

```bash
sudo apt install build-essential pkg-config
cargo build --release
```

## macOS (Intel and Apple Silicon)

```bash
xcode-select --install
cargo build --release
```

## Checksums

GitHub Actions `release.yml` publishes binaries and SHA-256 files on version tags (`v1.0.0`).
