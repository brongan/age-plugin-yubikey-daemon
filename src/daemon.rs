use std::io;

use crate::protocol::{
    self, EcdhError, EcdhResponse, EcdhResult, ProbeKeyResult, TAG_BYTES, YubikeyAgent,
};
use futures::StreamExt;
use log::{error, info, warn};
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use tarpc::server::Channel;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, oneshot};
use tokio_serde::formats::Bincode;
use zeroize::Zeroizing;
use yubikey::Certificate;
use yubikey::Context;
use yubikey::YubiKey;
use yubikey::certificate::PublicKeyInfo;
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
        let Some(pin) = pin.as_ref() else {
            return Err(EcdhError::NeedPin);
        };
        match session.yubikey.verify_pin(pin.as_bytes()) {
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
        session.pin_verified = true;
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

    let encoded_point = match cert.subject_pki() {
        PublicKeyInfo::EcP256(pt) => pt,
        _ => return Err(EcdhError::CertNotP256(slot)),
    };
    let pk = PublicKey::try_from(encoded_point).map_err(|_| EcdhError::CertInvalidKey)?;
    let hash = Sha256::digest(pk.to_encoded_point(true).as_bytes());
    let computed_tag: [u8; TAG_BYTES] = hash[..TAG_BYTES].try_into().unwrap();

    if computed_tag != expected_tag {
        return Err(EcdhError::TagMismatch { slot });
    }

    Ok(pk)
}

enum WorkerRequest {
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
        }
    }
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

/// Serve RPC requests until SIGINT/SIGTERM.
pub async fn run(listener: tokio::net::UnixListener) -> io::Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let (tx, mut rx) = mpsc::channel::<WorkerRequest>(1);
    tokio::task::spawn_blocking(move || yubikey_worker(&mut rx));

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
