//! RPC protocol between the age plugin and the daemon, spoken over a Unix
//! socket via tarpc.
//!
//! Two operations:
//! - [`probe_key`](YubikeyAgent::probe_key) — cheap pre-flight: does the
//!   connected YubiKey have a matching P-256 key? No PIN, no touch, no ECDH.
//! - [`ecdh`](YubikeyAgent::ecdh) — perform ECDH on the card and return the
//!   shared secret + recipient public key.

use serde::{Deserialize, Serialize};

pub const TAG_BYTES: usize = 4;

#[tarpc::service]
pub trait YubikeyAgent {
    /// Cheap pre-flight: does the connected YubiKey have a matching P-256 key
    /// in the given slot? Checks serial, validates the slot, reads the
    /// certificate, and verifies the tag. No PIN or touch required.
    async fn probe_key(serial: u32, slot: u8, tag: [u8; TAG_BYTES]) -> ProbeKeyResult;

    /// perform ECDH on the card and return the shared secret + recipient public key
    async fn ecdh(
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        ephemeral_pubkey: p256::PublicKey,
        pin: Option<String>,
    ) -> EcdhResult;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ProbeKeyResult {
    #[error("match")]
    Match,
    #[error("serial mismatch")]
    SerialMismatch,
    #[error("YubiKey disconnected")]
    Disconnected,
    #[error("worker dropped reply channel")]
    WorkerDropped,
    #[error("worker exited")]
    WorkerExited,
    #[error("YubiKey not available")]
    ChipUnavailable,
    #[error("invalid slot: 0x{0:02x}")]
    InvalidSlot(u8),
    #[error("{0}")]
    SlotCheck(EcdhError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhResponse {
    pub shared_secret: [u8; 32],
    pub recipient_pubkey: p256::PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum EcdhError {
    #[error("YubiKey PIN required")]
    NeedPin,

    #[error("YubiKey not available")]
    ChipUnavailable,

    #[error("YubiKey disconnected mid-operation")]
    Disconnected,

    #[error("serial mismatch: daemon serves a different YubiKey")]
    SerialMismatch,

    #[error("wrong PIN ({tries} tries remaining)")]
    WrongPin { tries: u8 },

    #[error("PIN locked")]
    PinLocked,

    #[error("PIN verification failed")]
    PinRejected,

    #[error("invalid slot: 0x{0:02x}")]
    InvalidSlot(u8),

    #[error("failed to read certificate from slot 0x{0:02x}")]
    CertRead(u8),

    #[error("certificate in slot 0x{0:02x} is not a P-256 key")]
    CertNotP256(u8),

    #[error("invalid P-256 public key in certificate")]
    CertInvalidKey,

    #[error("tag mismatch in slot 0x{slot:02x}")]
    TagMismatch { slot: u8 },

    #[error("ECDH operation failed")]
    EcdhFailed,

    #[error("shared secret has wrong length (expected 32, got {got})")]
    SharedSecretLength { got: usize },
}

pub type EcdhResult = Result<EcdhResponse, EcdhError>;

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
