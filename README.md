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

Every subcommand takes a transport: `--usb`, or `--phone <IP>` (optionally
`--remote`, `--reg-ip`, `--data-ip`).

```bash
pcsuite screen      --usb [--seconds N] [--out cap.h265] [--input-test]
pcsuite screen      --phone <IP> [--remote] [--seconds N] [--out cap.h265]
pcsuite clipboard   --phone <IP> [--seconds N]   # text + images, two-way
pcsuite verify-code --phone <IP>                 # SMS verification-code relay
pcsuite notify      --phone <IP>                 # phone notifications -> PC
pcsuite info        --phone <IP>                 # model / OS / storage capacity
pcsuite ls          --phone <IP> [--type recent|image|video|audio|file|doc|home]
pcsuite pull        --phone <IP> --path <phone-path> [--out <file>]
pcsuite all         --phone <IP>                 # clipboard+verify+notify on one connection
```

Transports:
- **USB** — `adb forward` + `am start` + `POST /version` handshake.
- **LAN/remote** — ConnectFlow on 10191 (`connectType=2` with a stored seed, or
  `--remote`/`connectType=1` needing no pre-shared seed).

## Status

Runs headless over **USB, LAN, and remote**; 60 offline unit tests; exercised
against a real device.

- ✅ Crypto / framing / transport — offline unit tests (CBC "sign" KAT, GCM KAT,
  frame round-trips). Real on-device conformance vectors are kept locally, not in-tree.
- ✅ Screen mirror — raw HEVC frames over LAN and USB.
- ✅ Control input — mouse / scroll / keyboard over `/mirror/control`.
- ✅ Clipboard — two-way text **and** images (images via vdfs, AES-GCM 12-byte nonce).
- ✅ SMS verify-code relay.
- ✅ Phone notification relay.
- ✅ Device info — model / OS / storage capacity.
- ✅ File browse — `ls` (per-category listing) + `pull` (download) over the mdfs gateway.
- ✅ SwiftUI macOS frontend via `pcsuite-ffi` (see the PcsuiteMirror app).
- ⏳ Deferred — non-macOS frontends (Windows/Linux), Flutter/IPC layer.

## Configuration

The pairing identity (account openId, PC MAC, device name) and the per-IP pairing
seeds are **not** hardcoded — they load at runtime, with this precedence:

1. environment variables — `PCSUITE_OPEN_ID`, `PCSUITE_PC_MAC`, `PCSUITE_ACCOUNT`,
   `PCSUITE_DEVICE_NAME`, `PCSUITE_SEED`;
2. a JSON file — `$PCSUITE_CONFIG`, else `./pcsuite.json`, else
   `$HOME/.config/pcsuite/config.json` (see [`pcsuite.example.json`](pcsuite.example.json));
3. obviously-fake placeholder defaults that will not pair with a real phone.

Copy `pcsuite.example.json` to `pcsuite.json` (git-ignored) and fill in your own
values. Get the per-IP seed from the phone's `historyPhone` `ext.seeds`.

## License

Copyright (C) 2026 xVanTuring

This program is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this
program. If not, see <https://www.gnu.org/licenses/>. The full text is in
[`LICENSE`](LICENSE).
