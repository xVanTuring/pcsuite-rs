# pcsuite-rs

A pure-Rust core for headless **screen mirroring**, **control input**, and
**clipboard sync** with an Android phone companion suite — reverse-engineered and
reimplemented from scratch, with no vendor binaries, no OpenSSL, and no Python.

The goal is a portable core (macOS today, Windows/Linux next) that delivers raw
HEVC frames + clipboard events and accepts control input, leaving decode and UI
to a platform frontend (FFI / IPC / Flutter — deliberately deferred).

## Workspace

| crate | role |
|-------|------|
| `pcsuite-crypto` | AES-256-CBC "sign" + AES-256-GCM (16-byte nonce) — byte-exact, pure RustCrypto |
| `pcsuite-proto`  | wire formats: 10191 `PAY_LOAD_1`, connect frames, 8904 ruying frame, screen/input/clipboard messages |
| `pcsuite-net`    | SSDP, TLS (rustls/ring, accepts self-signed), hand-rolled RFC6455 WS client |
| `pcsuite-core`   | sessions: ConnectFlow registration, screen data plane, control input, clipboard relay, USB (adb) path |
| `pcsuite-cli`    | headless `pcsuite` binary that drives the core |
| `pcsuite-ffi`    | swift-bridge bindings (static lib + generated Swift) for a SwiftUI macOS app — see `crates/pcsuite-ffi/SWIFT_INTEGRATION.md` |

## Build

```bash
cargo build
cargo test          # offline unit tests (crypto byte-exact, frame round-trips, …)
```

## CLI

```bash
# Screen mirror (counts frames / dumps raw HEVC):
pcsuite screen --usb [--seconds N] [--out cap.h265] [--input-test]
pcsuite screen --phone <IP> [--remote] [--seconds N] [--out cap.h265]

# Clipboard text sync (USB):
pcsuite clipboard --usb [--seconds N]   # --seconds 0 = run until Ctrl-C
```

Transports:
- **USB** — `adb forward` + `am start` + `POST /version` handshake.
- **LAN/remote** — ConnectFlow on 10191 (`connectType=2` with a stored seed, or
  `--remote`/`connectType=1` needing no pre-shared seed).

## Status

- ✅ Crypto, framing, transport — offline-verified (byte-exact vs reference vectors).
- ✅ Screen mirror — live over LAN and USB (raw HEVC frames delivered).
- ✅ Control input — mouse/scroll over `/mirror/control`.
- 🔧 Clipboard — handshake + 8904 relay live; PC→phone working, phone→PC under test.
- ⏳ Pending — clipboard images (vdfs), verify-code relay, LAN clipboard.

## Note

`crates/pcsuite-core/src/config.rs` contains this machine's own pairing identity
(account openId, MAC, device name, per-IP seed). Replace with your own values
before use, and scrub before publishing anywhere public.
