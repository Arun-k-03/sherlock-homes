# Termux

Sherlock core is a Rust binary. No GUI, Java, Chromium, Docker, or systemd required.

```bash
pkg update
pkg install rust binutils git
git clone <repo> && cd sherlock-homes
cargo build --release
./target/release/sherlock doctor
```

Optional engines (Nuclei, Katana, httpx, ZAP) are skipped when not installed. Browser automation is unsupported in Termux core mode.
