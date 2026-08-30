//! Device identity: a long-lived Ed25519 keypair that *is* the device's name
//! on the network.
//!
//! Everything else keys off this. Peers are addressed by public key, never by
//! IP, which is what lets a device roam between interfaces mid-transfer and
//! what will let a relay slot in later without a protocol change.

pub mod store;
pub mod words;

use std::fmt;
use std::str::FromStr;

use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls_pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Domain separator so a device id can never collide with any other BLAKE3
/// output we derive from the same key material.
const DEVICE_ID_CONTEXT: &str = "jetstream 2026-01 device-id v1";

pub const DEVICE_ID_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// A device's stable, self-certifying network identity.
///
/// Derived from the raw Ed25519 public key rather than from the certificate,
/// so it survives certificate regeneration — we mint a fresh short-lived cert
/// on every start, but the id a user paired with never changes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(DEVICE_ID_CONTEXT);
        hasher.update(public_key);
        Self(*hasher.finalize().as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// Full hex form, for logs, config files, and the wire.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First eight hex characters — enough to tell devices apart at a glance in
    /// a UI list, never enough to authenticate. Do not compare these to decide
    /// trust; use [`DeviceId::fingerprint`].
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// The six words a user reads aloud to confirm they are talking to the
    /// device they think they are.
    pub fn fingerprint_words(&self) -> [&'static str; words::FINGERPRINT_WORDS] {
        std::array::from_fn(|i| words::WORDS[self.0[i] as usize])
    }

    /// Hyphenated fingerprint, e.g. `"cobalt-finch-ember-atlas-dahlia-brook"`.
    pub fn fingerprint(&self) -> String {
        self.fingerprint_words().join("-")
    }

    /// Parse a fingerprint phrase back into the leading bytes it encodes.
    ///
    /// Only useful for manual out-of-band pairing, where a user types the words
    /// from the other device. A match means the first six bytes agree, which is
    /// the 48-bit comparison the phrase is defined to make — it does not prove
    /// the full id matches, so callers must still pin the id they observed.
    pub fn matches_fingerprint(&self, phrase: &str) -> bool {
        let mut count = 0;
        for (i, word) in phrase.split(['-', ' ', ',']).filter(|s| !s.is_empty()).enumerate() {
            if i >= words::FINGERPRINT_WORDS {
                return false;
            }
            match words::index_of(word) {
                Some(byte) if byte == self.0[i] => count += 1,
                _ => return false,
            }
        }
        count == words::FINGERPRINT_WORDS
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Debug prints the short form plus fingerprint — the full hex is noise in logs
/// and the fingerprint is what a human debugging a pairing problem needs.
impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({}, {})", self.short(), self.fingerprint())
    }
}

impl FromStr for DeviceId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim())
            .map_err(|e| Error::Protocol(format!("device id is not valid hex: {e}")))?;
        let bytes: [u8; DEVICE_ID_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
            Error::Protocol(format!(
                "device id must be {DEVICE_ID_LEN} bytes, got {}",
                v.len()
            ))
        })?;
        Ok(Self(bytes))
    }
}

impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            // A fixed-size array, not `serialize_bytes`: postcard length-prefixes
            // byte sequences but not arrays, and the two must agree with the
            // `[u8; N]` the deserializer below asks for.
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as DeError;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            let bytes = <[u8; DEVICE_ID_LEN]>::deserialize(d)?;
            Ok(Self(bytes))
        }
    }
}

/// This device's keypair. Holds private key material; keep it out of logs.
pub struct Identity {
    /// PKCS#8 DER. Zeroized on drop.
    pkcs8: Zeroizing<Vec<u8>>,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    device_id: DeviceId,
}

impl Identity {
    /// Mint a brand-new device identity. Called once, on first run.
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(Error::crypto)?;
        Self::from_key_pair(key_pair)
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let pkcs8 = PrivatePkcs8KeyDer::from(der.to_vec());
        let key_pair =
            KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519).map_err(Error::crypto)?;
        Self::from_key_pair(key_pair)
    }

    fn from_key_pair(key_pair: KeyPair) -> Result<Self> {
        let public_key: [u8; ED25519_PUBLIC_KEY_LEN] =
            key_pair.der_bytes().try_into().map_err(|_| {
                Error::Crypto(format!(
                    "expected a {ED25519_PUBLIC_KEY_LEN}-byte Ed25519 public key, got {}",
                    key_pair.der_bytes().len()
                ))
            })?;

        Ok(Self {
            pkcs8: Zeroizing::new(key_pair.serialize_der()),
            device_id: DeviceId::from_public_key(&public_key),
            public_key,
        })
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Private key in PKCS#8 DER. Only [`store`] should need this.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Rebuild an rcgen keypair for signing a fresh certificate.
    ///
    /// rcgen's `KeyPair` is not `Clone` and holds ring state, so we keep the
    /// DER as the source of truth and reconstruct on demand. This happens once
    /// per process start, not per connection.
    pub fn key_pair(&self) -> Result<KeyPair> {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.pkcs8.to_vec());
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519).map_err(Error::crypto)
    }
}

/// Redacts the key material so an accidental `{:?}` cannot leak it.
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .field("pkcs8", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_through_pkcs8() {
        let original = Identity::generate().unwrap();
        let restored = Identity::from_pkcs8_der(original.pkcs8_der()).unwrap();

        assert_eq!(original.device_id(), restored.device_id());
        assert_eq!(original.public_key(), restored.public_key());
    }

    #[test]
    fn distinct_identities_get_distinct_ids() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn device_id_round_trips_through_hex() {
        let id = Identity::generate().unwrap().device_id();
        assert_eq!(id.to_hex().parse::<DeviceId>().unwrap(), id);
    }

    #[test]
    fn device_id_round_trips_through_postcard() {
        // Regression: `Serialize` once emitted a length-prefixed byte string
        // while `Deserialize` asked for a fixed array, so every Hello frame
        // carrying a device id failed to decode.
        let id = Identity::generate().unwrap().device_id();

        let encoded = postcard::to_stdvec(&id).unwrap();
        assert_eq!(encoded.len(), DEVICE_ID_LEN, "no length prefix expected");
        assert_eq!(postcard::from_bytes::<DeviceId>(&encoded).unwrap(), id);
    }

    #[test]
    fn rejects_malformed_device_id_text() {
        assert!("not-hex".parse::<DeviceId>().is_err());
        assert!("abcd".parse::<DeviceId>().is_err(), "too short");
    }

    #[test]
    fn fingerprint_is_six_words_and_self_consistent() {
        let id = Identity::generate().unwrap().device_id();
        let phrase = id.fingerprint();

        assert_eq!(phrase.split('-').count(), words::FINGERPRINT_WORDS);
        assert!(id.matches_fingerprint(&phrase));
        assert!(id.matches_fingerprint(&phrase.replace('-', " ")), "spaces accepted");
    }

    #[test]
    fn fingerprint_rejects_wrong_and_truncated_phrases() {
        let id = DeviceId::from_bytes([0u8; DEVICE_ID_LEN]);
        let right = id.fingerprint();

        assert!(id.matches_fingerprint(&right));
        assert!(!id.matches_fingerprint("acid-acid-acid-acid-acid-galaxy"));
        assert!(!id.matches_fingerprint("acid-acid-acid"), "short phrase must not pass");
        assert!(
            !id.matches_fingerprint(&format!("{right}-galaxy")),
            "extra word must not pass"
        );
        assert!(!id.matches_fingerprint(""));
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let identity = Identity::generate().unwrap();
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex::encode(identity.pkcs8_der())));
    }
}
