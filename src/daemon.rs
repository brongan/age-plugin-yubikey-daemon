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
use zeroize::Zeroizing;
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

impl Session {
    fn new() -> Result<Self, EcdhError> {
        match open_first_yubikey() {
            Ok(Some(yk)) => {
                info!("Connected to YubiKey with serial: {}", yk.serial());
                Ok(Self {
                    pin_verified: false,
                    yubikey: yk,
                })
            }
            Ok(None) => Err(EcdhError::Disconnected),
            Err(_) => Err(EcdhError::ChipUnavailable),
        }
    }

    /// Verify `pin` on the card and mark this session as verified.
    fn verify_pin(&mut self, pin: &Zeroizing<String>) -> Result<(), EcdhError> {
        match self.yubikey.verify_pin(pin.as_bytes()) {
            Ok(()) => {
                info!("PIN verified successfully");
            }
            Err(e) if is_session_fatal(&e) => return Err(EcdhError::Disconnected),
            Err(yubikey::Error::WrongPin { tries }) => {
                warn!("Wrong PIN ({tries} tries remaining)");
                return Err(EcdhError::WrongPin { tries });
            }
            Err(yubikey::Error::PinLocked) => {
                warn!("PIN locked");
                return Err(EcdhError::PinLocked);
            }
            Err(e) => {
                warn!("PIN verification failed: {e}");
                return Err(EcdhError::PinRejected);
            }
        }
        self.pin_verified = true;
        Ok(())
    }
}

/// Signing errors. The ssh-agent protocol has only a generic failure reply,
/// so the daemon logs these errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SignError {
    #[error("YubiKey is disconnected")]
    Disconnected,
    #[error("YubiKey worker stopped")]
    WorkerExited,
    #[error("could not read certificate from slot 0x{0:02x}")]
    CertRead(u8),
    #[error("certificate in slot 0x{0:02x} does not contain an RSA 2048 key")]
    CertKey(u8),
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
    #[error("PIN is locked")]
    PinLocked,
    #[error("could not verify PIN")]
    PinRejected,
    #[error("requested key is not in a slot listed with --sign-slot")]
    UnknownKey,
    #[error("signature flags 0x{0:x} are unsupported; only rsa-sha2-256 is supported")]
    UnsupportedFlags(u32),
    #[error("could not sign data")]
    SignFailed,
}

/// Check whether the connected YubiKey has a P-256 key matching the given
/// serial, slot, and tag. No PIN or touch required.
fn handle_probe_key(
    session: &mut Session,
    serial: u32,
    slot: u8,
    tag: [u8; TAG_BYTES],
) -> ProbeKeyResult {
    if u32::from(session.yubikey.serial()) != serial {
        return ProbeKeyResult::SerialMismatch;
    }
    let slot_id = match RetiredSlotId::try_from(slot) {
        Ok(s) => s,
        Err(_) => return ProbeKeyResult::InvalidSlot(slot),
    };
    match read_slot_pubkey(&mut session.yubikey, slot_id, slot, tag) {
        Ok(_) => ProbeKeyResult::Match,
        Err(EcdhError::Disconnected) => ProbeKeyResult::Disconnected,
        Err(e) => ProbeKeyResult::SlotCheck(e),
    }
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
) -> EcdhResult {
    if u32::from(session.yubikey.serial()) != serial {
        return Err(EcdhError::SerialMismatch);
    }

    if !session.pin_verified {
        let pin = pin.as_ref().ok_or(EcdhError::NeedPin)?;
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
        Err(e) if is_session_fatal(&e) => return Err(EcdhError::Disconnected),
        Err(_) => return Err(EcdhError::EcdhFailed),
    };
    let shared_secret: [u8; 32] =
        raw_secret
            .as_slice()
            .try_into()
            .map_err(|_| EcdhError::SharedSecretLength {
                got: raw_secret.len(),
            })?;

    Ok(EcdhResponse {
        shared_secret,
        recipient_pubkey,
    })
}

/// Read the RSA 2048 public key from a PIV slot certificate and convert it to SSH form.
fn handle_slot_key(session: &mut Session, slot: SlotId) -> Result<KeyData, SignError> {
    let slot_byte = u8::from(slot);
    let cert = read_cert(&mut session.yubikey, slot)?;
    let key = rsa::RsaPublicKey::try_from(cert.subject_pki())
        .map_err(|_| SignError::CertKey(slot_byte))?;
    if key.n().bits() != 2048 {
        return Err(SignError::CertKey(slot_byte));
    }
    ssh_key::public::RsaPublicKey::try_from(&key)
        .map(KeyData::Rsa)
        .map_err(|_| SignError::CertKey(slot_byte))
}

/// Sign `message` with the RSA 2048 key in `slot` using PKCS#1 v1.5 and
/// SHA-256. If the card says the slot needs a PIN, ask with pinentry and try
/// again.
fn handle_sign(session: &mut Session, slot: SlotId, message: &[u8]) -> Result<Vec<u8>, SignError> {
    let cert = read_cert(&mut session.yubikey, slot)?;
    let sign = |yubikey: &mut YubiKey| {
        let _reminder = touch_reminder(slot);
        sign_with_card(yubikey, slot, &cert, message)
    };
    match sign(&mut session.yubikey) {
        Err(SignError::AuthenticationRequired) => {
            let policy = pin_policy(&mut session.yubikey, slot);
            if !needs_pin(policy, session.pin_verified) {
                return Err(SignError::TouchTimeout);
            }
            prompt_and_verify_pin(session, slot.into())?;
            sign(&mut session.yubikey)
        }
        result => result,
    }
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
    let signer = Signer::<YubiRsa<Rsa2048>>::new(yubikey, slot, cert.subject_pki())
        .map_err(|_| SignError::CertKey(slot.into()))?;
    let error = match signer.try_sign(message) {
        Ok(signature) => return Ok(signature.to_vec()),
        Err(e) => e,
    };
    match error
        .source()
        .and_then(|source| source.downcast_ref::<yubikey::Error>())
    {
        Some(yubikey::Error::AuthenticationError) => Err(SignError::AuthenticationRequired),
        Some(e) if is_session_fatal(e) => Err(SignError::Disconnected),
        _ => {
            warn!("Could not sign data: {error}");
            Err(SignError::SignFailed)
        }
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
            Err(EcdhError::WrongPin { tries }) => {
                error = Some(format!("Incorrect PIN; {tries} tries remain"));
            }
            Err(EcdhError::Disconnected) => return Err(SignError::Disconnected),
            Err(EcdhError::PinLocked) => return Err(SignError::PinLocked),
            Err(_) => return Err(SignError::PinRejected),
        }
    }
}

fn read_cert(yubikey: &mut YubiKey, slot: SlotId) -> Result<Certificate, SignError> {
    match Certificate::read(yubikey, slot) {
        Ok(c) => Ok(c),
        Err(e) if is_session_fatal(&e) => Err(SignError::Disconnected),
        Err(_) => Err(SignError::CertRead(slot.into())),
    }
}

/// Read the P-256 public key from a PIV slot's certificate and verify its
/// tag (first 4 bytes of SHA-256 of the compressed point).
fn read_slot_pubkey(
    yubikey: &mut YubiKey,
    slot_id: RetiredSlotId,
    slot: u8,
    expected_tag: [u8; TAG_BYTES],
) -> Result<PublicKey, EcdhError> {
    let cert = match Certificate::read(yubikey, SlotId::Retired(slot_id)) {
        Ok(c) => c,
        Err(e) if is_session_fatal(&e) => return Err(EcdhError::Disconnected),
        Err(_) => return Err(EcdhError::CertRead(slot)),
    };

    let spki = cert.subject_pki();
    if spki.algorithm.parameters_oid().ok() != Some(NistP256::OID) {
        return Err(EcdhError::CertNotP256(slot));
    }
    let pk = PublicKey::try_from(spki).map_err(|_| EcdhError::CertInvalidKey)?;
    let hash = Sha256::digest(pk.to_encoded_point(true).as_bytes());
    let computed_tag: [u8; TAG_BYTES] = hash[..TAG_BYTES].try_into().unwrap();

    if computed_tag != expected_tag {
        return Err(EcdhError::TagMismatch { slot });
    }

    Ok(pk)
}

pub(crate) enum WorkerRequest {
    ProbeKey {
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        reply: oneshot::Sender<ProbeKeyResult>,
    },
    Ecdh {
        serial: u32,
        slot: u8,
        tag: [u8; TAG_BYTES],
        ephemeral_pubkey: PublicKey,
        pin: Option<String>,
        reply: oneshot::Sender<EcdhResult>,
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
                        if matches!(&result, ProbeKeyResult::Disconnected) {
                            warn!("YubiKey disconnected; dropping handle");
                            session = None;
                        }
                        result
                    }
                    None => ProbeKeyResult::ChipUnavailable,
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
                        let r =
                            handle_ecdh(s, serial, slot, tag, ephemeral_pubkey, pin.map(Zeroizing::new));
                        if matches!(&r, Err(EcdhError::Disconnected)) {
                            warn!("YubiKey disconnected; dropping handle");
                            session = None;
                        }
                        r
                    }
                    None => Err(EcdhError::Disconnected),
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
        return Err(SignError::Disconnected);
    };
    let result = op(s);
    if matches!(&result, Err(SignError::Disconnected)) {
        warn!("YubiKey disconnected; dropping handle");
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
            .unwrap_or(ProbeKeyResult::WorkerDropped)
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
            .unwrap_or(Err(EcdhError::Disconnected))
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
