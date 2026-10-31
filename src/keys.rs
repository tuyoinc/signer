//! secp256k1 keys, Ethereum addresses and personal_sign (EIP-191).

use k256::ecdsa::{RecoveryId, Signature, SigningKey as EcdsaKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, SignerError};

pub const ALGORITHM: &str = "secp256k1";

/// A software key. The private scalar lives only in memory and is zeroed on drop
/// by k256.
pub struct SigningKey {
    key: EcdsaKey,
}

impl SigningKey {
    pub fn generate() -> Self {
        Self {
            key: EcdsaKey::random(&mut rand_core::OsRng),
        }
    }

    pub fn from_hex(private_key: &str) -> Result<Self> {
        let bytes = Zeroizing::new(parse_hex(private_key, 32).ok_or_else(invalid_secret)?);
        let key = EcdsaKey::from_slice(&bytes).map_err(|_| invalid_secret())?;
        Ok(Self { key })
    }

    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("0x{}", hex::encode(self.key.to_bytes())))
    }

    /// Uncompressed SEC1 public key, `0x04…`.
    pub fn public_key(&self) -> String {
        public_key_hex(self.key.verifying_key())
    }

    pub fn address(&self) -> String {
        address_of(self.key.verifying_key())
    }

    /// Signs a 32-byte digest exactly as given. Returns `r || s || v` with
    /// `v` = 27 or 28, low-s, deterministic (RFC 6979), like viem's `sign`.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<String> {
        let (signature, recovery): (Signature, RecoveryId) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| SignerError::new("signing_failed", "Could not sign the hash."))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&signature.to_bytes());
        out.push(27 + recovery.to_byte());
        Ok(format!("0x{}", hex::encode(out)))
    }
}

/// The digest personal_sign signs for a raw 32-byte message.
pub fn personal_message_digest(hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(hash);
    hasher.finalize().into()
}

pub fn public_key_hex(key: &VerifyingKey) -> String {
    format!("0x{}", hex::encode(key.to_encoded_point(false).as_bytes()))
}

pub fn address_of(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    checksum_address(&hash[12..])
}

/// EIP-55 mixed-case address.
pub fn checksum_address(bytes: &[u8]) -> String {
    let lower = hex::encode(bytes);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses and checksums an address given in any case. Mixed-case input must
/// carry a valid EIP-55 checksum, as viem's `isAddress` requires.
pub fn normalize_address(input: &str) -> Option<String> {
    let bytes = parse_hex(input, 20)?;
    let checksummed = checksum_address(&bytes);
    let body = &input[2..];
    let mixed = body.chars().any(|c| c.is_ascii_uppercase())
        && body.chars().any(|c| c.is_ascii_lowercase());
    if mixed && checksummed != input {
        return None;
    }
    Some(checksummed)
}

/// Parses `0x`-prefixed hex of an exact byte length.
pub fn parse_hex(input: &str, len: usize) -> Option<Vec<u8>> {
    let body = input.strip_prefix("0x")?;
    if body.len() != len * 2 {
        return None;
    }
    hex::decode(body).ok()
}

pub fn parse_hash(input: &str) -> Option<[u8; 32]> {
    parse_hex(input, 32).map(|v| v.try_into().expect("32 bytes"))
}

/// How backends that hold a software key serialize it. Compatible with the
/// TypeScript signer: `{"version":1,"algorithm":"secp256k1","privateKey":"0x…"}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Secret {
    version: u8,
    algorithm: String,
    private_key: String,
    /// Set when every signature must be approved with Touch ID. Kept with the
    /// key, not in state.json, so editing the profile cannot turn it off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    require_touch_id: bool,
}

pub struct StoredKey {
    pub key: SigningKey,
    pub require_touch_id: bool,
}

/// Shows only the address, never the private key.
impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKey")
            .field("address", &self.key.address())
            .field("require_touch_id", &self.require_touch_id)
            .finish()
    }
}

pub fn encode_secret(key: &SigningKey, require_touch_id: bool) -> Zeroizing<String> {
    let mut secret = Secret {
        version: 1,
        algorithm: ALGORITHM.into(),
        private_key: key.private_key_hex().to_string(),
        require_touch_id,
    };
    let text = Zeroizing::new(serde_json::to_string(&secret).expect("serializable"));
    secret.private_key.zeroize();
    text
}

pub fn decode_secret(text: &str) -> Result<StoredKey> {
    let secret: Secret = serde_json::from_str(text.trim()).map_err(|_| invalid_secret())?;
    let private_key = Zeroizing::new(secret.private_key);
    if secret.version != 1 || secret.algorithm != ALGORITHM {
        return Err(invalid_secret());
    }
    Ok(StoredKey {
        key: SigningKey::from_hex(&private_key)?,
        require_touch_id: secret.require_touch_id,
    })
}

fn invalid_secret() -> SignerError {
    SignerError::new(
        "invalid_key",
        "The stored signing key is not a valid secp256k1 key.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ONE: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn derives_the_known_address_for_key_one() {
        let key = SigningKey::from_hex(KEY_ONE).unwrap();
        assert_eq!(key.address(), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        assert!(
            key.public_key().starts_with(
                "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            )
        );
    }

    // Expected values computed with viem 2.56.3, the TypeScript signer's library:
    // privateKeyToAccount(pk).signMessage({ message: { raw: hash } }).
    #[test]
    fn matches_viem_personal_sign() {
        let key = SigningKey::from_hex(
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        )
        .unwrap();
        assert_eq!(key.address(), "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
        assert_eq!(
            key.public_key(),
            "0x044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de"
        );
        let hash = [0xab; 32];
        assert_eq!(
            key.sign_digest(&personal_message_digest(&hash)).unwrap(),
            "0x48dd510466cee1ce1cb709456ac94c33c2db069d0d7fbc8eb9602254f92fcc3766077972b3cd400b29b542d59a567efd79b7dc880155d4875d6e80d713835f2f1c"
        );
    }

    #[test]
    fn normalizes_addresses() {
        let lower = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        assert_eq!(
            normalize_address(lower).unwrap(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        assert!(normalize_address("0x7E5F4552091A69125d5DfCb7b8C2659029395BDf").is_none());
        assert!(normalize_address("7e5f4552091a69125d5dfcb7b8c2659029395bdf").is_none());
    }

    #[test]
    fn round_trips_secrets_and_rejects_unknown_fields() {
        let key = SigningKey::generate();
        let text = encode_secret(&key, false);
        assert!(!text.contains("requireTouchId"));
        let stored = decode_secret(&text).unwrap();
        assert_eq!(stored.key.address(), key.address());
        assert!(!stored.require_touch_id);

        let stored = decode_secret(&encode_secret(&key, true)).unwrap();
        assert!(stored.require_touch_id);

        assert!(
            decode_secret(r#"{"version":1,"algorithm":"secp256k1","privateKey":"0x01","x":1}"#)
                .is_err()
        );
    }
}
