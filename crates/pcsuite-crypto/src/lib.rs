//! `pcsuite-crypto` — byte-exact reimplementation of the two crypto recipes used
//! by the phone-suite protocol, reversed from the desktop connection service
//! (x86_64) and the desktop relay binary (x86_64).
//!
//! ## 1. ConnectFlow "sign" (10191 token registration)
//!
//! Used to register a self-made token with the phone so it opens the 10380 control
//! service. The phone side performs the inverse to recover and store the token.
//!
//! ```text
//! key  = SHA256(stored_seed ++ seed_b)      // 32 raw bytes -> AES-256
//! iv   = 0x00 * 16                           // zero IV
//! sign = hex( AES-256-CBC / PKCS7 ( "openId|connId|token", key, iv ) )
//! ```
//!
//! `stored_seed` is the per-IP UUID stored at pairing time (LAN, `connectType=2`),
//! or the empty string for the `connectType=1` remote path (`key = SHA256(seed_b)`).
//! Verified byte-exact against 3 real samples captured from the official desktop
//! service (see [`tests`]).
//!
//! ## 2. "vgcm" (super-clipboard 8904 + vdfs file planes)
//!
//! ```text
//! AES-256-GCM, 32-byte key, 16-byte nonce (non-standard; CryptoPP/OpenSSL derive
//! J0 via GHASH per NIST SP800-38D for nonces != 12 bytes), 16-byte tag appended
//! to the ciphertext, no AAD by default.
//! ```
//!
//! vdfs uses the same primitive but with a 12-byte nonce (`iv[..12]`) — call
//! [`gcm_encrypt`]/[`gcm_decrypt`] with a 12-byte `iv` slice for that case.
//! Verified byte-exact against a Python KAT (see [`tests`]).

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::AesGcm;

/// AES-256-GCM with a 16-byte nonce and 16-byte tag — the relay's "vgcm".
///
/// `aes-gcm` lets us pick the nonce length via the type parameter; for nonces
/// other than 12 bytes it follows NIST SP800-38D (GHASH-derived J0), matching
/// CryptoPP and OpenSSL.
type VGcm16 = AesGcm<Aes256, U16, U16>;

/// Errors from the crypto layer. Deliberately coarse — these recipes either
/// reproduce a known byte string or they don't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// A key/iv/blob slice was shorter than required.
    BadLength(&'static str),
    /// AEAD authentication failed or a padded buffer was malformed.
    Crypt,
    /// Decrypted bytes were not valid UTF-8 where text was expected.
    Utf8,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::BadLength(w) => write!(f, "bad length: {w}"),
            CryptoError::Crypt => write!(f, "decrypt/authentication failed"),
            CryptoError::Utf8 => write!(f, "decrypted bytes are not valid UTF-8"),
        }
    }
}
impl std::error::Error for CryptoError {}

const ZERO_IV: [u8; 16] = [0u8; 16];

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ───────────────────────────── ConnectFlow sign (AES-256-CBC) ─────────────────────────────

/// `key = SHA256(stored_seed ++ seed_b)`. For the `connectType=1` remote path,
/// pass `stored_seed = ""` so `key = SHA256(seed_b)`.
pub fn derive_sign_key(stored_seed: &str, seed_b: &str) -> [u8; 32] {
    let mut s = String::with_capacity(stored_seed.len() + seed_b.len());
    s.push_str(stored_seed);
    s.push_str(seed_b);
    sha256(s.as_bytes())
}

type CbcEnc = cbc::Encryptor<Aes256>;
type CbcDec = cbc::Decryptor<Aes256>;

/// AES-256-CBC / PKCS7 encrypt with a zero IV.
pub fn sign_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    CbcEnc::new_from_slices(key, &ZERO_IV)
        .expect("32-byte key + 16-byte iv")
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// AES-256-CBC / PKCS7 decrypt with a zero IV.
pub fn sign_decrypt_raw(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    CbcDec::new_from_slices(key, &ZERO_IV)
        .expect("32-byte key + 16-byte iv")
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map(|s| s.to_vec())
        .map_err(|_| CryptoError::Crypt)
}

/// Build the hex `sign` string carried in the ConnectFlow connect frame.
///
/// `plaintext = "{open_id}|{conn_id}|{token}"`.
pub fn make_sign(
    open_id: &str,
    conn_id: &str,
    token: &str,
    stored_seed: &str,
    seed_b: &str,
) -> String {
    let key = derive_sign_key(stored_seed, seed_b);
    let pt = format!("{open_id}|{conn_id}|{token}");
    hex::encode(sign_encrypt(pt.as_bytes(), &key))
}

/// Inverse of [`make_sign`]: decrypt a hex `sign` back to `"openId|connId|token"`.
pub fn decrypt_sign(sign_hex: &str, stored_seed: &str, seed_b: &str) -> Result<String, CryptoError> {
    let key = derive_sign_key(stored_seed, seed_b);
    let ct = hex::decode(sign_hex).map_err(|_| CryptoError::BadLength("sign hex"))?;
    let pt = sign_decrypt_raw(&ct, &key)?;
    String::from_utf8(pt).map_err(|_| CryptoError::Utf8)
}

// ───────────────────────────── vgcm (AES-256-GCM, 16-byte nonce) ─────────────────────────────

/// `vgcm` encrypt: returns `ciphertext ‖ tag(16)`.
///
/// `key` is truncated to 32 bytes and `iv` to 16 bytes, matching the Python
/// reference. Pass a 12-byte `iv` slice for the vdfs variant.
pub fn gcm_encrypt(plain: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (cipher, nonce) = gcm_setup(key, iv)?;
    cipher
        .encrypt(nonce, Payload { msg: plain, aad })
        .map_err(|_| CryptoError::Crypt)
}

/// `vgcm` decrypt: `blob = ciphertext ‖ tag(16)`. Fails on bad tag.
pub fn gcm_decrypt(blob: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 16 {
        return Err(CryptoError::BadLength("blob < tag"));
    }
    let (cipher, nonce) = gcm_setup(key, iv)?;
    cipher
        .decrypt(nonce, Payload { msg: blob, aad })
        .map_err(|_| CryptoError::Crypt)
}

fn gcm_setup<'a>(
    key: &[u8],
    iv: &'a [u8],
) -> Result<(VGcm16, &'a GenericArray<u8, U16>), CryptoError> {
    if key.len() < 32 {
        return Err(CryptoError::BadLength("key < 32"));
    }
    if iv.len() < 16 {
        return Err(CryptoError::BadLength("iv < 16"));
    }
    let cipher = VGcm16::new_from_slice(&key[..32]).map_err(|_| CryptoError::BadLength("key"))?;
    let nonce = GenericArray::from_slice(&iv[..16]);
    Ok((cipher, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// per-IP stored seed for 192.168.1.42 (historyPhone.json ext.seeds).
    const STORED: &str = "00000000-0000-4000-8000-000000000000";

    /// 3 real (seed_b, sign) pairs produced by the official desktop service
    /// (captured to /tmp/vcs.log). Source of truth for byte-exact parity.
    const SAMPLES: &[(&str, &str)] = &[
        (
            "11111111-1111-4111-8111-111111111111",
            "REDACTED_SIGN_1",
        ),
        (
            "22222222-2222-4222-8222-222222222222",
            "REDACTED_SIGN_2",
        ),
        (
            "33333333-3333-4333-8333-333333333333",
            "REDACTED_SIGN_3",
        ),
    ];

    #[test]
    fn cbc_sign_byte_exact() {
        for (seed_b, real) in SAMPLES {
            let pt = decrypt_sign(real, STORED, seed_b).expect("decrypt official sign");
            let parts: Vec<&str> = pt.split('|').collect();
            assert_eq!(parts.len(), 3, "plaintext must be openId|connId|token");
            // re-encrypt the recovered fields; must match the official sign exactly.
            let mine = make_sign(parts[0], parts[1], parts[2], STORED, seed_b);
            assert_eq!(&mine, real, "re-encrypt must match official sign byte-for-byte");
        }
    }

    #[test]
    fn connecttype1_key_is_sha256_of_seedb() {
        // remote path: stored_seed = "" -> key = SHA256(seed_b)
        let seed_b = "11111111-1111-4111-8111-111111111111";
        assert_eq!(derive_sign_key("", seed_b), sha256(seed_b.as_bytes()));
    }

    #[test]
    fn gcm_kat_16byte_nonce() {
        // KAT generated from the Python vgcm reference (CryptoPP-equivalent).
        let key: Vec<u8> = (0u8..32).collect();
        let iv: Vec<u8> = (0u8..16).collect();
        let pt = b"vivo clipboard test";
        let expect =
            hex::decode("1105d61919872641ed9db44827c00cc731c01f7c721e880a56f21e8f5b235b2d6da589")
                .unwrap();
        let got = gcm_encrypt(pt, &key, &iv, b"").unwrap();
        assert_eq!(got, expect, "GCM/16B-nonce must match Python/CryptoPP byte-for-byte");

        let back = gcm_decrypt(&got, &key, &iv, b"").unwrap();
        assert_eq!(back, pt, "round-trip");

        // empty plaintext -> tag only
        let empty = gcm_encrypt(b"", &key, &iv, b"").unwrap();
        assert_eq!(hex::encode(&empty), "1fe22185668c52bcacfdff70749c67b9");
    }

    #[test]
    fn gcm_bad_tag_fails() {
        let key: Vec<u8> = (0u8..32).collect();
        let iv: Vec<u8> = (0u8..16).collect();
        let mut blob = gcm_encrypt(b"secret", &key, &iv, b"").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert_eq!(gcm_decrypt(&blob, &key, &iv, b""), Err(CryptoError::Crypt));
    }
}
