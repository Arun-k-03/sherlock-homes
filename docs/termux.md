# Termux / Android

Sherlock core is a Rust CLI. It does not require GUI, Docker, systemd, Chromium, or Java.

**TERMUX SOURCE COMPATIBILITY: DESIGNED / CI-PARTIAL / MANUAL VALIDATION REQUIRED**

This guide was not executed on a physical Termux device in the maintainer Windows workspace. Package names below are the usual Termux set; confirm with `pkg search` on device.

## Intended source install

```bash
pkg update
pkg install rust binutils git
git clone <YOUR_GITHUB_REPO_URL>
cd sherlock-holmes
cargo build --release
cargo install --path . --force
export PATH="$HOME/.cargo/bin:$PATH"
sherlock doctor
sherlock doctor --database
```

Optional engines (Nuclei, Katana, httpx, ZAP) are skipped when not installed. ZAP is unsupported in Termux core mode.

## Update

```bash
git pull
cargo install --path . --force
sherlock doctor --database
```

## Uninstall

```bash
cargo uninstall sherlock-homes
```

This does not delete the Evidence Vault under the Termux home data directory.
