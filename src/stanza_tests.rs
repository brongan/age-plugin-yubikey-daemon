use super::*;

use age_core::format::{FILE_KEY_BYTES, Stanza};
use age_core::primitives::{aead_encrypt, hkdf};
use age_core::secrecy::ExposeSecret;

use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

// ── IdentityStub ────────────────────────────────────────────────────

#[test]
fn stub_parse_valid() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&42u32.to_le_bytes());
    bytes.push(0x82);
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let (stub, _) = IdentityStub::read_from_prefix(bytes.as_slice()).unwrap();
    assert_eq!(stub.serial.get(), 42);
    assert_eq!(stub.slot, 0x82);
    assert_eq!(stub.tag, [0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn stub_reject_too_short() {
    assert!(IdentityStub::read_from_prefix([0; 8].as_slice()).is_err());
    assert!(IdentityStub::read_from_prefix([].as_slice()).is_err());
}

#[test]
fn stub_accept_exactly_9_bytes() {
    assert!(IdentityStub::read_from_prefix([0; 9].as_slice()).is_ok());
}

#[test]
fn stub_accept_extra_bytes() {
    assert!(IdentityStub::read_from_prefix([0; 20].as_slice()).is_ok());
}

// ── PivP256Stanza ───────────────────────────────────────────────────

fn make_valid_stanza() -> (Stanza, p256::PublicKey) {
    let sk = p256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let compressed = pk.to_encoded_point(true);
    let tag = [0x01, 0x02, 0x03, 0x04];
    let stanza = Stanza {
        tag: "piv-p256".to_string(),
        args: vec![
            BASE64_STANDARD_NO_PAD.encode(tag),
            BASE64_STANDARD_NO_PAD.encode(compressed.as_bytes()),
        ],
        body: vec![0xAA; 32],
    };
    (stanza, pk)
}

#[test]
fn stanza_parse_valid() {
    let (stanza, _) = make_valid_stanza();
    let parsed = PivP256Stanza::from_stanza(&stanza).unwrap().unwrap();
    assert_eq!(parsed.tag, [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(parsed.encrypted_file_key, [0xAA; 32]);
}

#[test]
fn stanza_ignore_non_piv_p256() {
    let stanza = Stanza {
        tag: "X25519".to_string(),
        args: vec!["foo".to_string()],
        body: vec![0; 32],
    };
    assert!(PivP256Stanza::from_stanza(&stanza).is_none());
}

#[test]
fn stanza_reject_wrong_arg_count() {
    let stanza = Stanza {
        tag: "piv-p256".to_string(),
        args: vec!["only_one".to_string()],
        body: vec![0; 32],
    };
    assert!(matches!(PivP256Stanza::from_stanza(&stanza), Some(Err(()))));
}

#[test]
fn stanza_reject_wrong_body_length() {
    let (mut stanza, _) = make_valid_stanza();
    stanza.body = vec![0; 16];
    assert!(matches!(PivP256Stanza::from_stanza(&stanza), Some(Err(()))));
}

#[test]
fn epk_decompression_produces_65_bytes() {
    let (stanza, _) = make_valid_stanza();
    let parsed = PivP256Stanza::from_stanza(&stanza).unwrap().unwrap();
    let uncompressed = parsed.ephemeral_pubkey.to_encoded_point(false);
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed.as_bytes()[0], 0x04);
}

// ── KDF compatibility ───────────────────────────────────────────────

#[test]
fn kdf_wrap_then_unwrap_matches() {
    let recipient_pk = p256::SecretKey::random(&mut rand::thread_rng()).public_key();
    let recipient_compressed = recipient_pk.to_encoded_point(true);
    let file_key_bytes: [u8; FILE_KEY_BYTES] = [0x42; FILE_KEY_BYTES];

    let esk = EphemeralSecret::random(&mut rand::thread_rng());
    let epk = esk.public_key();
    let shared_secret = esk.diffie_hellman(&recipient_pk);
    let epk_compressed = epk.to_encoded_point(true);

    let tag_hash = Sha256::digest(recipient_compressed.as_bytes());
    let tag: [u8; 4] = tag_hash[..4].try_into().unwrap();

    let mut salt = Vec::new();
    salt.extend_from_slice(epk_compressed.as_bytes());
    salt.extend_from_slice(recipient_compressed.as_bytes());

    let enc_key = hkdf(
        &salt,
        STANZA_KEY_LABEL,
        shared_secret.raw_secret_bytes().as_slice(),
    );
    let encrypted = aead_encrypt(&enc_key, &file_key_bytes);
    let mut encrypted_file_key = [0u8; 32];
    encrypted_file_key.copy_from_slice(&encrypted);

    let stanza = Stanza {
        tag: "piv-p256".to_string(),
        args: vec![
            BASE64_STANDARD_NO_PAD.encode(tag),
            BASE64_STANDARD_NO_PAD.encode(epk_compressed.as_bytes()),
        ],
        body: encrypted_file_key.to_vec(),
    };

    let parsed = PivP256Stanza::from_stanza(&stanza).unwrap().unwrap();
    let mut daemon_shared_secret = [0u8; 32];
    daemon_shared_secret.copy_from_slice(shared_secret.raw_secret_bytes().as_slice());

    let recovered = parsed
        .derive_file_key(&daemon_shared_secret, &recipient_pk)
        .expect("file key derivation should succeed");

    assert_eq!(recovered.expose_secret(), &file_key_bytes);
}

#[test]
fn kdf_wrong_shared_secret_fails() {
    let recipient_pk = p256::SecretKey::random(&mut rand::thread_rng()).public_key();
    let recipient_compressed = recipient_pk.to_encoded_point(true);
    let file_key_bytes: [u8; FILE_KEY_BYTES] = [0x42; FILE_KEY_BYTES];

    let esk = EphemeralSecret::random(&mut rand::thread_rng());
    let shared_secret = esk.diffie_hellman(&recipient_pk);
    let epk_compressed = esk.public_key().to_encoded_point(true);
    let tag_hash = Sha256::digest(recipient_compressed.as_bytes());
    let tag: [u8; 4] = tag_hash[..4].try_into().unwrap();

    let mut salt = Vec::new();
    salt.extend_from_slice(epk_compressed.as_bytes());
    salt.extend_from_slice(recipient_compressed.as_bytes());
    let enc_key = hkdf(
        &salt,
        STANZA_KEY_LABEL,
        shared_secret.raw_secret_bytes().as_slice(),
    );
    let encrypted = aead_encrypt(&enc_key, &file_key_bytes);
    let mut encrypted_file_key = [0u8; 32];
    encrypted_file_key.copy_from_slice(&encrypted);

    let stanza = Stanza {
        tag: "piv-p256".to_string(),
        args: vec![
            BASE64_STANDARD_NO_PAD.encode(tag),
            BASE64_STANDARD_NO_PAD.encode(epk_compressed.as_bytes()),
        ],
        body: encrypted_file_key.to_vec(),
    };
    let parsed = PivP256Stanza::from_stanza(&stanza).unwrap().unwrap();
    let wrong_secret = [0xFF; 32];
    assert!(
        parsed
            .derive_file_key(&wrong_secret, &recipient_pk)
            .is_err()
    );
}

#[test]
fn kdf_wrong_recipient_pk_fails() {
    let recipient_pk = p256::SecretKey::random(&mut rand::thread_rng()).public_key();
    let recipient_compressed = recipient_pk.to_encoded_point(true);
    let file_key_bytes: [u8; FILE_KEY_BYTES] = [0x42; FILE_KEY_BYTES];

    let esk = EphemeralSecret::random(&mut rand::thread_rng());
    let shared_secret = esk.diffie_hellman(&recipient_pk);
    let epk_compressed = esk.public_key().to_encoded_point(true);
    let tag_hash = Sha256::digest(recipient_compressed.as_bytes());
    let tag: [u8; 4] = tag_hash[..4].try_into().unwrap();

    let mut salt = Vec::new();
    salt.extend_from_slice(epk_compressed.as_bytes());
    salt.extend_from_slice(recipient_compressed.as_bytes());
    let enc_key = hkdf(
        &salt,
        STANZA_KEY_LABEL,
        shared_secret.raw_secret_bytes().as_slice(),
    );
    let encrypted = aead_encrypt(&enc_key, &file_key_bytes);
    let mut encrypted_file_key = [0u8; 32];
    encrypted_file_key.copy_from_slice(&encrypted);

    let stanza = Stanza {
        tag: "piv-p256".to_string(),
        args: vec![
            BASE64_STANDARD_NO_PAD.encode(tag),
            BASE64_STANDARD_NO_PAD.encode(epk_compressed.as_bytes()),
        ],
        body: encrypted_file_key.to_vec(),
    };
    let parsed = PivP256Stanza::from_stanza(&stanza).unwrap().unwrap();
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared_secret.raw_secret_bytes().as_slice());
    let wrong_pk = p256::SecretKey::random(&mut rand::thread_rng()).public_key();
    assert!(
        parsed
            .derive_file_key(&ss, &wrong_pk)
            .is_err()
    );
}


