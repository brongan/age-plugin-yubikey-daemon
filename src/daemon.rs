use std::error::Error as _;
use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self as std_mpsc, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::protocol::{
    self, EcdhError, EcdhResponse, EcdhResult, ProbeKeyResult, TAG_BYTES, YubikeyAgent,
};
use crate::signing::{self, SigningAgent};
use futures::StreamExt;
use log::{error, info, warn};
use notify_rust::{Notification, Timeout};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::AssociatedOid;
use p256::{NistP256, PublicKey};
use pinentry::PassphraseInput;
use rsa::traits::PublicKeyParts;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer as _};
use ssh_key::public::KeyData;
use tarpc::server::Channel;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, oneshot};
use tokio_serde::formats::Bincode;
use yubikey::Certificate;
use yubikey::Context;
use yubikey::PinPolicy;
use yubikey::YubiKey;
use yubikey::certificate::yubikey_signer::{Rsa2048, Signer, YubiRsa};
use yubikey::piv;
use yubikey::piv::AlgorithmId;
use yubikey::piv::RetiredSlotId;
use yubikey::piv::SlotId;
use yubikey::piv::decrypt_data;
use zeroize::Zeroizing;

fn open_first_yubikey() -> yubikey::Result<Option<YubiKey>> {
    Context::open()?
        .iter()?
        .next()
        .map(|r| r.open())
        .transpose()
}

/// Heuristic to determine if the yubikey needs to be reconnected.
fn is_session_fatal(err: &yubikey::Error) -> bool {
    matches!(err, yubikey::Error::PcscError { .. })
}

struct Session {
    yubikey: YubiKey,
    pin_verified: bool,
}

/// Errors from opening the YubiKey.
#[derive(Debug, thiserror::Error)]
enum OpenError {
    #[error("no YubiKey is connected")]
    NotFound,
    #[error("could not open the YubiKey: {0}")]
    Open(#[from] yubikey::Error),
}

impl Session {
    fn new() -> Result<Self, OpenError> {
        let yubikey = open_first_yubikey()?.ok_or(OpenError::NotFound)?;
        info!("Connected to YubiKey with serial: {}", yubikey.serial());
        Ok(Self {
            pin_verified: false,
            yubikey,
        })
    }

    /// Verify `pin` on the card and mark this session as verified.
    fn verify_pin(&mut self, pin: &Zeroizing<String>) -> Result<(), PinError> {
        match self.yubikey.verify_pin(pin.as_bytes()) {
            Ok(()) => {
                info!("PIN verified successfully");
            }
            Err(e) if is_session_fatal(&e) => return Err(PinError::Disconnected(e)),
            Err(yubikey::Error::WrongPin { tries }) => return Err(PinError::Wrong { tries }),
            Err(yubikey::Error::PinLocked) => return Err(PinError::Locked),
            Err(e) => return Err(PinError::Rejected(e)),
        }
        self.pin_verified = true;
        Ok(())
    }
}

/// PIN verification errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PinError {
    #[error("YubiKey disconnected: {0}")]
    Disconnected(#[source] yubikey::Error),
    #[error("wrong PIN ({tries} tries remaining)")]
    Wrong { tries: u8 },
    #[error("PIN is locked")]
    Locked,
    #[error("could not verify PIN: {0}")]
    Rejected(#[source] yubikey::Error),
}

impl PinError {
    fn is_disconnected(&self) -> bool {
        matches!(self, PinError::Disconnected(_))
    }
}

impl From<PinError> for EcdhError {
    fn from(e: PinError) -> Self {
        match e {
            PinError::Disconnected(_) => EcdhError::Disconnected,
            PinError::Wrong { tries } => EcdhError::WrongPin { tries },
            PinError::Locked => EcdhError::PinLocked,
            PinError::Rejected(_) => EcdhError::PinRejected,
        }
    }
}

/// Errors from probing keys and ECDH. They keep causes that the wire error
/// cannot carry. The RPC handler logs them and sends the wire error.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DecryptError {
    #[error(transparent)]
    Wire(#[from] EcdhError),
    #[error(transparent)]
    Pin(#[from] PinError),
    #[error("YubiKey disconnected: {0}")]
    Disconnected(#[source] yubikey::Error),
    #[error("could not read certificate from slot 0x{slot:02x}: {source}")]
    CertRead {
        slot: u8,
        #[source]
        source: yubikey::Error,
    },
    #[error("certificate in slot 0x{slot:02x} has an invalid P-256 key: {source}")]
    CertInvalidKey {
        slot: u8,
        #[source]
        source: p256::pkcs8::spki::Error,
    },
    #[error("ECDH with slot 0x{slot:02x} failed: {source}")]
    EcdhFailed {
        slot: u8,
        #[source]
        source: yubikey::Error,
    },
}

impl DecryptError {
    fn is_disconnected(&self) -> bool {
        match self {
            DecryptError::Disconnected(_) => true,
            DecryptError::Pin(e) => e.is_disconnected(),
            _ => false,
        }
    }
}

impl From<DecryptError> for EcdhError {
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::Wire(e) => e,
            DecryptError::Pin(e) => e.into(),
            DecryptError::Disconnected(_) => EcdhError::Disconnected,
            DecryptError::CertRead { slot, .. } => EcdhError::CertRead(slot),
            DecryptError::CertInvalidKey { slot, .. } => EcdhError::CertInvalidKey(slot),
            DecryptError::EcdhFailed { slot, .. } => EcdhError::EcdhFailed(slot),
        }
    }
}

impl From<DecryptError> for ProbeKeyResult {
    fn from(e: DecryptError) -> Self {
        if e.is_disconnected() {
            ProbeKeyResult::Disconnected
        } else {
            ProbeKeyResult::SlotCheck(e.into())
        }
    }
}

/// Signing errors. The ssh-agent protocol has only a generic failure reply,
/// so the daemon logs these errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SignError {
    #[error("no YubiKey is connected")]
    NotConnected,
    #[error("YubiKey is disconnected: {0}")]
    Disconnected(#[source] yubikey::Error),
    #[error("YubiKey worker stopped")]
    WorkerExited,
    #[error("could not read certificate from slot 0x{slot:02x}: {source}")]
    CertRead {
        slot: u8,
        #[source]
        source: yubikey::Error,
    },
    #[error("certificate in slot 0x{slot:02x} does not contain an RSA key: {source}")]
    CertNotRsa {
        slot: u8,
        #[source]
        source: rsa::pkcs8::spki::Error,
    },
    #[error(
        "certificate in slot 0x{slot:02x} has an RSA {bits}-bit key; only RSA 2048 is supported"
    )]
    CertKeySize { slot: u8, bits: usize },
    #[error("could not convert the key in slot 0x{slot:02x} to SSH form: {source}")]
    SshKey {
        slot: u8,
        #[source]
        source: ssh_key::Error,
    },
    #[error("YubiKey could not use the certificate key in slot 0x{slot:02x}: {source}")]
    SignerKey {
        slot: u8,
        #[source]
        source: yubikey::Error,
    },
    #[error("YubiKey needs a PIN or touch for this signature")]
    AuthenticationRequired,
    #[error("YubiKey was not touched in time")]
    TouchTimeout,
    #[error("could not find a pinentry program")]
    PinentryMissing,
    #[error("pinentry error: {0}")]
    Pinentry(String),
    #[error("PIN entry was cancelled")]
    PinCancelled,
    #[error(transparent)]
    Pin(PinError),
    #[error("requested key is not in a slot listed with --sign-slot")]
    KeyNotInSignSlots,
    #[error("signature flags 0x{0:x} are unsupported; only rsa-sha2-256 is supported")]
    UnsupportedFlags(u32),
    #[error("YubiKey could not sign: {0}")]
    Card(#[source] yubikey::Error),
    #[error("could not decode the signature from the YubiKey")]
    SignatureFormat,
    #[error("could not convert the signature to SSH form: {0}")]
    SshSignature(#[source] ssh_key::Error),
}

impl SignError {
    fn is_disconnected(&self) -> bool {
        match self {
            SignError::Disconnected(_) => true,
            SignError::Pin(e) => e.is_disconnected(),
            _ => false,
        }
    }
}

/// Check whether the connected YubiKey has a P-256 key matching the given
/// serial, slot, and tag. No PIN or touch required.
fn handle_probe_key(
    session: &mut Session,
    serial: u32,
    slot: u8,
    tag: [u8; TAG_BYTES],
) -> Result<ProbeKeyResult, DecryptError> {
    if u32::from(session.yubikey.serial()) != serial {
        return Ok(ProbeKeyResult::SerialMismatch);
    }
    let Ok(slot_id) = RetiredSlotId::try_from(slot) else {
        return Ok(ProbeKeyResult::InvalidSlot(slot));
    };
    read_slot_pubkey(&mut session.yubikey, slot_id, slot, tag)?;
    Ok(ProbeKeyResult::Match)
}

/// Compute a P-256 ECDH shared secret on the YubiKey hardware: the card
/// multiplies the ephemeral public key (from the stanza) by the private key
/// in the given PIV slot, returning the raw shared secret. Verifies serial,
/// slot, tag, and PIN before touching the card. Requires physical touch.
fn handle_ecdh(
    session: &mut Session,
    serial: u32,
    slot: u8,
    tag: [u8; TAG_BYTES],
    ephemeral_pubkey: PublicKey,
    pin: Option<Zeroizing<String>>,
) -> Result<EcdhResponse, DecryptError> {
    if u32::from(session.yubikey.serial()) != serial {
        return Err(EcdhError::SerialMismatch.into());
    }

    if !session.pin_verified {
        let Some(pin) = pin.as_ref() else {
            return Ok(EcdhResponse::NeedPin);
        };
        session.verify_pin(pin)?;
    }

    let slot_id = RetiredSlotId::try_from(slot).map_err(|_| EcdhError::InvalidSlot(slot))?;
    let recipient_pubkey = read_slot_pubkey(&mut session.yubikey, slot_id, slot, tag)?;

    let epk_uncompressed = ephemeral_pubkey.to_encoded_point(false);
    let raw_secret = match decrypt_data(
        &mut session.yubikey,
        epk_uncompressed.as_bytes(),
        AlgorithmId::EccP256,
        SlotId::Retired(slot_id),
    ) {
        Ok(buf) => buf,
        Err(e) if is_session_fatal(&e) => return Err(DecryptError::Disconnected(e)),
        Err(source) => return Err(DecryptError::EcdhFailed { slot, source }),
    };
    let shared_secret: [u8; 32] =
        raw_secret
            .as_slice()
            .try_into()
            .map_err(|_| EcdhError::SharedSecretLength {
                got: raw_secret.len(),
            })?;

    Ok(EcdhResponse::Secret {
        shared_secret,
        recipient_pubkey,
    })
}

/// Read the RSA 2048 public key from a PIV slot certificate and convert it to SSH form.
fn handle_slot_key(session: &mut Session, slot: SlotId) -> Result<KeyData, SignError> {
    let cert = read_cert(&mut session.yubikey, slot)?;
    let slot = u8::from(slot);
    let key = rsa::RsaPublicKey::try_from(cert.subject_pki())
        .map_err(|source| SignError::CertNotRsa { slot, source })?;
    let bits = key.n().bits();
    if bits != 2048 {
        return Err(SignError::CertKeySize { slot, bits });
    }
    ssh_key::public::RsaPublicKey::try_from(&key)
        .map(KeyData::Rsa)
        .map_err(|source| SignError::SshKey { slot, source })
}

/// Sign `message` with the RSA 2048 key in `slot` using PKCS#1 v1.5 and
/// SHA-256. If the card says the slot needs a PIN, ask with pinentry and try
/// again. If the card refuses when no PIN is needed, or after the PIN is
/// verified, the touch timed out.
fn handle_sign(session: &mut Session, slot: SlotId, message: &[u8]) -> Result<Vec<u8>, SignError> {
    let cert = read_cert(&mut session.yubikey, slot)?;
    let sign = |yubikey: &mut YubiKey| {
        let _reminder = touch_reminder(slot);
        sign_with_card(yubikey, slot, &cert, message)
    };
    match sign(&mut session.yubikey) {
        Err(SignError::AuthenticationRequired)
            if needs_pin(pin_policy(&mut session.yubikey, slot), session.pin_verified) =>
        {
            prompt_and_verify_pin(session, slot.into())?;
            sign(&mut session.yubikey)
        }
        result => result,
    }
    .map_err(|e| match e {
        SignError::AuthenticationRequired => {
            touch_timeout_notice(slot);
            SignError::TouchTimeout
        }
        e => e,
    })
}

/// How long a signature may take before the card is assumed to wait for a
/// touch. A signature without a touch takes much less time.
const TOUCH_REMINDER_DELAY: Duration = Duration::from_secs(3);

/// Remind the user to touch the YubiKey if signing has not finished after
/// `TOUCH_REMINDER_DELAY`. Signing is finished when the returned sender is
/// dropped. The D-Bus calls run on their own thread, so a hung notification
/// server cannot block the YubiKey worker.
fn touch_reminder(slot: SlotId) -> std_mpsc::Sender<()> {
    let (done, wait) = std_mpsc::channel();
    thread::spawn(move || {
        if wait.recv_timeout(TOUCH_REMINDER_DELAY) != Err(RecvTimeoutError::Timeout) {
            return;
        }
        let body = format!(
            "Touch your YubiKey to sign with PIV slot {:02x}.",
            u8::from(slot)
        );
        let handle = Notification::new()
            .summary("YubiKey is waiting for a touch")
            .body(&body)
            .timeout(Timeout::Never)
            .show();
        match handle {
            Ok(handle) => {
                let _ = wait.recv();
                handle.close();
            }
            Err(e) => warn!("Could not show touch reminder: {e}"),
        }
    });
    done
}

/// Tell the user that signing failed because the YubiKey was not touched in
/// time. The D-Bus call runs on its own thread, so a hung notification server
/// cannot block the YubiKey worker.
fn touch_timeout_notice(slot: SlotId) {
    thread::spawn(move || {
        let body = format!(
            "The YubiKey was not touched in time to sign with PIV slot {:02x}. \
             Sign again and touch the YubiKey when it blinks.",
            u8::from(slot)
        );
        if let Err(e) = Notification::new()
            .summary("YubiKey signing failed")
            .body(&body)
            .timeout(Timeout::Never)
            .show()
        {
            warn!("Could not show touch timeout notice: {e}");
        }
    });
}

/// Firmware before 5.3 cannot report the PIN policy.
fn pin_policy(yubikey: &mut YubiKey, slot: SlotId) -> Option<PinPolicy> {
    piv::metadata(yubikey, slot)
        .ok()?
        .policy
        .map(|(pin, _)| slot_pin_policy(slot, pin))
}

/// Replace `PinPolicy::Default` with the default PIN policy of `slot`.
///
/// NIST SP 800-73-5 Part 1 sets the access rule for each key:
/// 9a "PIN" (§3.1.3), 9c "PIN Always" (§3.2.1), 9d "PIN" (§3.2.2), retired
/// key management keys "PIN" (§3.3.4) and 9e "Always" (§3.1.4).
/// <https://doi.org/10.6028/NIST.SP.800-73pt1-5>
///
/// Yubico maps these to `Always` for 9c, `Never` for 9e and `Once` for the
/// other slots. YubiKey FIPS 5.7.1 and later use `Once` for 9e, so its
/// default stays unresolved.
/// <https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html>
fn slot_pin_policy(slot: SlotId, policy: PinPolicy) -> PinPolicy {
    match (policy, slot) {
        (PinPolicy::Default, SlotId::Signature) => PinPolicy::Always,
        (
            PinPolicy::Default,
            SlotId::Authentication | SlotId::KeyManagement | SlotId::Retired(_),
        ) => PinPolicy::Once,
        (policy, _) => policy,
    }
}

/// The card returns the same error when it needs a PIN or times out.
/// Check whether a PIN is needed.
fn needs_pin(policy: Option<PinPolicy>, pin_verified: bool) -> bool {
    match policy {
        Some(PinPolicy::Never) => false,
        Some(PinPolicy::Once) => !pin_verified,
        _ => true,
    }
}

fn sign_with_card(
    yubikey: &mut YubiKey,
    slot: SlotId,
    cert: &Certificate,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    let signer =
        Signer::<YubiRsa<Rsa2048>>::new(yubikey, slot, cert.subject_pki()).map_err(|source| {
            SignError::SignerKey {
                slot: slot.into(),
                source,
            }
        })?;
    let error = match signer.try_sign(message) {
        Ok(signature) => return Ok(signature.to_vec()),
        Err(e) => e,
    };
    match error
        .source()
        .and_then(|source| source.downcast_ref::<yubikey::Error>())
    {
        Some(yubikey::Error::AuthenticationError) => Err(SignError::AuthenticationRequired),
        Some(&e) if is_session_fatal(&e) => Err(SignError::Disconnected(e)),
        Some(&e) => Err(SignError::Card(e)),
        None => Err(SignError::SignatureFormat),
    }
}

/// Ask for a PIN with pinentry until the card accepts it, the user cancels,
/// or the PIN is locked.
fn prompt_and_verify_pin(session: &mut Session, slot: u8) -> Result<(), SignError> {
    let description = format!("Enter the YubiKey PIN to sign with PIV slot {slot:02x}.");
    let mut error: Option<String> = None;
    loop {
        let mut input = PassphraseInput::with_default_binary().ok_or(SignError::PinentryMissing)?;
        input.with_description(&description).with_prompt("PIN");
        if let Some(error) = &error {
            input.with_error(error);
        }
        let pin = match input.interact() {
            Ok(pin) => Zeroizing::new(pin.expose_secret().to_owned()),
            Err(pinentry::Error::Cancelled) => return Err(SignError::PinCancelled),
            Err(e) => return Err(SignError::Pinentry(e.to_string())),
        };
        match session.verify_pin(&pin) {
            Ok(()) => return Ok(()),
            Err(PinError::Wrong { tries }) => {
                warn!("Wrong PIN ({tries} tries remaining)");
                error = Some(format!("Incorrect PIN; {tries} tries remain"));
            }
            Err(e) => return Err(SignError::Pin(e)),
        }
    }
}

fn read_cert(yubikey: &mut YubiKey, slot: SlotId) -> Result<Certificate, SignError> {
    match Certificate::read(yubikey, slot) {
        Ok(c) => Ok(c),
        Err(e) if is_session_fatal(&e) => Err(SignError::Disconnected(e)),
        Err(source) => Err(SignError::CertRead {
            slot: slot.into(),
            source,
        }),
    }
}

/// Read the P-256 public key from a PIV slot's certificate and verify its
/// tag (first 4 bytes of SHA-256 of the compressed point).
fn read_slot_pubkey(
    yubikey: &mut YubiKey,
    slot_id: RetiredSlotId,
    slot: u8,
    expected_tag: [u8; TAG_BYTES],
) -> Result<PublicKey, DecryptError> {
    let cert = match Certificate::read(yubikey, SlotId::Retired(slot_id)) {
        Ok(c) => c,
        Err(e) if is_session_fatal(&e) => return Err(DecryptError::Disconnected(e)),
        Err(source) => return Err(DecryptError::CertRead { slot, source }),
    };

    let spki = cert.subject_pki();
    if spki.algorithm.parameters_oid().ok() != Some(NistP256::OID) {
        return Err(EcdhError::CertNotP256(slot).into());
    }
    let pk = PublicKey::try_from(spki)
        .map_err(|source| DecryptError::CertInvalidKey { slot, source })?;
    let hash = Sha256::digest(pk.to_encoded_point(true).as_bytes());
    let computed_tag: [u8; TAG_BYTES] = hash[..TAG_BYTES].try_into().unwrap();

    if computed_tag != expected_tag {
        return Err(EcdhError::TagMismatch { slot }.into());
    }

    Ok(pk)
}

pub(crate) enum WorkerRequest {
    ProbeKey {
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        reply: oneshot::Sender<Result<ProbeKeyResult, DecryptError>>,
    },
    Ecdh {
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        ephemeral_pubkey: PublicKey,
        pin: Option<String>,
        reply: oneshot::Sender<Result<EcdhResponse, DecryptError>>,
    },
    SlotKey {
        slot: SlotId,
        reply: oneshot::Sender<Result<KeyData, SignError>>,
    },
    Sign {
        slot: SlotId,
        message: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, SignError>>,
    },
}

/// Blocking function that receives work requests and handles interaction with a yubikey.
fn yubikey_worker(rx: &mut Receiver<WorkerRequest>) {
    let mut session: Option<Session> = None;
    while let Some(request) = rx.blocking_recv() {
        if session.is_none() {
            session = Session::new()
                .inspect_err(|e| warn!("Failed to open YubiKey: {e}"))
                .ok();
        }
        match request {
            WorkerRequest::ProbeKey {
                serial,
                slot,
                tag,
                reply,
            } => {
                let result = match &mut session {
                    Some(s) => {
                        let result = handle_probe_key(s, serial, slot, tag);
                        if result.as_ref().is_err_and(DecryptError::is_disconnected) {
                            session = None;
                        }
                        result
                    }
                    None => Ok(ProbeKeyResult::ChipUnavailable),
                };
                if reply.send(result).is_err() {
                    error!("Failed to send yubikey worker result to daemon.");
                }
            }
            WorkerRequest::Ecdh {
                serial,
                slot,
                tag,
                ephemeral_pubkey,
                pin,
                reply,
            } => {
                let result = match &mut session {
                    Some(s) => {
                        let r = handle_ecdh(
                            s,
                            serial,
                            slot,
                            tag,
                            ephemeral_pubkey,
                            pin.map(Zeroizing::new),
                        );
                        if r.as_ref().is_err_and(DecryptError::is_disconnected) {
                            session = None;
                        }
                        r
                    }
                    None => Err(EcdhError::Disconnected.into()),
                };
                if reply.send(result).is_err() {
                    error!("Failed to send yubikey worker result to daemon.");
                }
            }
            WorkerRequest::SlotKey { slot, reply } => {
                let result = with_sign_session(&mut session, |s| handle_slot_key(s, slot));
                if reply.send(result).is_err() {
                    error!("Failed to send yubikey worker result to daemon.");
                }
            }
            WorkerRequest::Sign {
                slot,
                message,
                reply,
            } => {
                let result = with_sign_session(&mut session, |s| handle_sign(s, slot, &message));
                if reply.send(result).is_err() {
                    error!("Failed to send yubikey worker result to daemon.");
                }
            }
        }
    }
}

/// Run a signing operation and drop the session if the YubiKey disconnects.
fn with_sign_session<T>(
    session: &mut Option<Session>,
    op: impl FnOnce(&mut Session) -> Result<T, SignError>,
) -> Result<T, SignError> {
    let Some(s) = session else {
        return Err(SignError::NotConnected);
    };
    let result = op(s);
    if result.as_ref().is_err_and(SignError::is_disconnected) {
        *session = None;
    }
    result
}

#[derive(Clone)]
struct Server {
    tx: mpsc::Sender<WorkerRequest>,
}

impl protocol::YubikeyAgent for Server {
    async fn probe_key(
        self,
        _: tarpc::context::Context,
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
    ) -> ProbeKeyResult {
        let (reply, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(WorkerRequest::ProbeKey {
                serial,
                slot,
                tag,
                reply,
            })
            .await
            .is_err()
        {
            return ProbeKeyResult::WorkerExited;
        }
        reply_rx
            .await
            .unwrap_or(Ok(ProbeKeyResult::WorkerDropped))
            .unwrap_or_else(|e| {
                warn!("Key probe failed: {e}");
                e.into()
            })
    }

    async fn ecdh(
        self,
        _: tarpc::context::Context,
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        ephemeral_pubkey: p256::PublicKey,
        pin: Option<String>,
    ) -> EcdhResult {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(WorkerRequest::Ecdh {
                serial,
                slot,
                tag,
                ephemeral_pubkey,
                pin,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return Err(EcdhError::Disconnected);
        }
        reply_rx
            .await
            .unwrap_or(Err(EcdhError::Disconnected.into()))
            .inspect_err(|e| warn!("ECDH failed: {e}"))
            .map_err(EcdhError::from)
    }
}

/// Serve age RPC requests on `listener` and ssh-agent signing requests on
/// `signing_listener` until SIGINT/SIGTERM. Offer only keys in `sign_slots`.
pub async fn run(
    listener: tokio::net::UnixListener,
    signing_listener: tokio::net::UnixListener,
    sign_slots: Vec<SlotId>,
) -> io::Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let (tx, mut rx) = mpsc::channel::<WorkerRequest>(1);
    tokio::task::spawn_blocking(move || yubikey_worker(&mut rx));

    if !sign_slots.is_empty() {
        info!("Signing is enabled for slots: {sign_slots:?}");
    }
    let agent = SigningAgent::new(tx.clone(), Arc::from(sign_slots));
    tokio::spawn(ssh_agent_lib::agent::listen(
        signing::Listener(signing_listener),
        agent,
    ));

    let mut incoming = tarpc::serde_transport::unix::listen_on(listener, Bincode::default).await?;

    loop {
        let transport = tokio::select! {
            _ = sigint.recv() => {
                info!("SIGINT received, shutting down");
                break;
            },
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down");
                break;
            },
            next = incoming.next() => match next {
                Some(Ok(t)) => t,
                Some(Err(e)) => {
                    error!("Accept error: {e}");
                    continue;
                }
                None => break,
            },
        };

        let server = Server { tx: tx.clone() };
        let channel = tarpc::server::BaseChannel::with_defaults(transport);
        tokio::spawn(
            channel
                .execute(server.serve())
                .for_each(|response| async move {
                    tokio::spawn(response);
                }),
        );
    }

    Ok(())
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
