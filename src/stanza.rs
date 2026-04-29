//! `piv-p256` stanza parsing and AEAD-based file-key unwrapping.
//!
//! Matches the wire format used by
//! [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) so files
//! encrypted with the original plugin decrypt unchanged through this agent.

use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use age_core::primitives::{aead_decrypt, hkdf};
use age_core::secrecy::zeroize::Zeroize;
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine};
use p256::PublicKey;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned, little_endian::U32};

use crate::protocol::TAG_BYTES;

const STANZA_TAG: &str = "piv-p256";
/// HKDF label used when deriving the file-key-wrapping AEAD key. Matches
/// `age-plugin-yubikey` so cross-plugin decryption works.
const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
const EPK_BYTES: usize = 33;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

/// A reference to one of the user's `YubiKey` identities.
///
/// Decoded from the bech32 identity blob handed to the plugin by `age`. Same
/// binary encoding as `age-plugin-yubikey`'s Stub: serial (4 LE) | slot (1)
/// | tag (4).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct IdentityStub {
    pub serial: U32,
    pub slot: u8,
    pub tag: [u8; TAG_BYTES],
}

/// A parsed `piv-p256` recipient stanza extracted from an age file.
pub struct PivP256Stanza {
    /// Tag from the stanza's first arg, identifies which recipient identity
    /// this stanza is for.
    pub tag: [u8; TAG_BYTES],
    /// Validated ephemeral public key from the second arg.
    pub ephemeral_pubkey: PublicKey,
    /// The 32-byte AEAD-wrapped file key (stanza body).
    pub encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl PivP256Stanza {
    /// Parse a generic [`Stanza`] as a `piv-p256` stanza.
    ///
    /// - `None` — different tag; the stanza isn't ours (skip silently).
    /// - `Some(Err(()))` — tagged `piv-p256` but malformed (bad arg count,
    ///   invalid point encoding, wrong body length, …).
    /// - `Some(Ok(_))` — a valid `piv-p256` stanza.
    #[must_use]
    pub fn from_stanza(s: &Stanza) -> Option<Result<Self, ()>> {
        if s.tag != STANZA_TAG {
            return None; // not ours
        }

        // Tagged `piv-p256`, so from here any parse failure is "malformed":
        // the closure short-circuits to `None`, which we lift to `Err(())`.
        let parse = || {
            let [tag_b64, epk_b64] = &s.args[..] else {
                return None;
            };

            let tag: [u8; TAG_BYTES] = BASE64_STANDARD_NO_PAD
                .decode(tag_b64)
                .ok()?
                .as_slice()
                .try_into()
                .ok()?;

            let epk_bytes: [u8; EPK_BYTES] = BASE64_STANDARD_NO_PAD
                .decode(epk_b64)
                .ok()?
                .as_slice()
                .try_into()
                .ok()?;
            let encoded = p256::EncodedPoint::from_bytes(epk_bytes).ok()?;
            let ephemeral_pubkey =
                Option::<PublicKey>::from(PublicKey::from_encoded_point(&encoded))?;

            let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = s.body[..].try_into().ok()?;

            Some(Self {
                tag,
                ephemeral_pubkey,
                encrypted_file_key,
            })
        };

        Some(parse().ok_or(()))
    }

    /// Derive the file key from the shared secret returned by the daemon.
    ///
    /// # Errors
    /// Returns `Err(())` if AEAD decryption fails (wrong shared secret,
    /// wrong recipient public key, or tampered ciphertext).
    #[allow(clippy::result_unit_err)]
    pub fn derive_file_key(
        &self,
        shared_secret: &[u8; 32],
        recipient_pubkey: &PublicKey,
    ) -> Result<FileKey, ()> {
        let epk_compressed = self.ephemeral_pubkey.to_encoded_point(true);
        let recipient_compressed = recipient_pubkey.to_encoded_point(true);

        let mut salt = Vec::with_capacity(
            epk_compressed.as_bytes().len() + recipient_compressed.as_bytes().len(),
        );
        salt.extend_from_slice(epk_compressed.as_bytes());
        salt.extend_from_slice(recipient_compressed.as_bytes());

        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared_secret);

        aead_decrypt(&enc_key, FILE_KEY_BYTES, &self.encrypted_file_key)
            .map_err(|_| ())
            .map(|mut pt| {
                FileKey::init_with_mut(|file_key| {
                    file_key.copy_from_slice(&pt);
                    pt.zeroize();
                })
            })
    }
}

#[cfg(test)]
#[path = "stanza_tests.rs"]
mod tests;
