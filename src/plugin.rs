use std::collections::HashMap;
use std::io;

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use age_plugin::identity::{self, IdentityPluginV1};
use age_plugin::{Callbacks, PluginHandler};
use age_plugin_yubikey_daemon::protocol::{
    EcdhError, EcdhResponse, ProbeKeyResult, YubikeyAgentClient,
};
use age_plugin_yubikey_daemon::socket;
use age_plugin_yubikey_daemon::stanza::{IdentityStub, PivP256Stanza};
use log::{debug, warn};
use tarpc::client;
use tarpc::context;
use tarpc::serde_transport::unix::connect;
use tokio::runtime::Builder as TokioRuntime;
use tokio_serde::formats::Bincode;
use zerocopy::FromBytes;

const PLUGIN_NAME: &str = "yubikey-daemon";

pub(crate) struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = std::convert::Infallible;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "recipient-v1 not supported (use age-plugin-yubikey for encryption)",
        ))
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

struct PluginIdentity {
    stub: IdentityStub,
    index: usize,
}

#[derive(Default)]
pub(crate) struct IdentityPlugin {
    identities: Vec<PluginIdentity>,
}

type FileKeyMap = HashMap<usize, Result<FileKey, Vec<identity::Error>>>;

/// A stanza matched to the identity that can decrypt it — the join on `tag`.
/// Bundles the parsed stanza (for file key derivation after ECDH) with the
/// identity's serial/slot/tag (for the daemon request). Everything needed to
/// attempt one decryption.
struct Candidate {
    parsed: PivP256Stanza,
    stanza_index: usize,
    identity_index: usize,
    serial: u32,
    slot: u8,
    tag: [u8; 4],
}

impl IdentityPlugin {
    fn match_stanzas<'a>(&'a self, stanzas: &'a [Stanza]) -> impl Iterator<Item = Candidate> + 'a {
        stanzas.iter().enumerate().filter_map(|(stanza_index, s)| {
            let parsed = match PivP256Stanza::from_stanza(s) {
                Some(Ok(p)) => p,
                Some(Err(())) => {
                    warn!("Malformed piv-p256 stanza at index {stanza_index}");
                    return None;
                }
                None => return None,
            };
            let PluginIdentity { stub, index } = &self
                .identities
                .iter()
                .find(|id| id.stub.tag == parsed.tag)?;
            let IdentityStub { serial, slot, tag } = *stub;
            Some(Candidate {
                parsed,
                stanza_index,
                identity_index: *index,
                serial: serial.get(),
                slot,
                tag,
            })
        })
    }
}

/// Outcome of a single ECDH decryption attempt for one candidate.
enum DecryptResult {
    /// File key successfully unwrapped.
    Decrypted(FileKey),
    /// ECDH succeeded but AEAD verification failed — wrong key or tampered
    /// ciphertext. Reported as a `Stanza` error by the caller (which has
    /// the file index).
    AeadFailed,
    /// Daemon's YubiKey doesn't match this candidate's serial. Not an error —
    /// the file simply has no entry in the result map (implicit skip per the
    /// age-plugin spec).
    SerialMismatch,
    /// A reportable error (PIN rejected, chip unavailable, etc.) to be
    /// collected into the per-file error list in the result map.
    Failed(identity::Error),
}

/// Attempt ECDH decryption for one candidate. probe_keys first to check serial/tag
/// match — PIN is only requested after the probe_key confirms the right YubiKey is
/// connected. Callbacks are only used for interactive operations (PIN prompt,
/// touch message). Errors are returned as `DecryptResult::Failed` for the
/// caller to collect.
async fn process_candidate(
    client: &YubikeyAgentClient,
    candidate: &Candidate,
    callbacks: &mut impl Callbacks<identity::Error>,
) -> io::Result<DecryptResult> {
    let Candidate {
        identity_index,
        serial,
        slot,
        tag,
        parsed,
        ..
    } = &candidate;
    let probe_key_result = match client
        .probe_key(context::current(), *serial, *slot, *tag)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Ok(DecryptResult::Failed(identity::Error::Internal {
                message: format!("Daemon RPC error: {e}"),
            }));
        }
    };
    match probe_key_result {
        ProbeKeyResult::Match => {}
        ProbeKeyResult::SerialMismatch => {
            debug!(
                "Skipping identity {} (serial {} not connected)",
                identity_index, serial
            );
            return Ok(DecryptResult::SerialMismatch);
        }
        err @ (ProbeKeyResult::Disconnected
        | ProbeKeyResult::WorkerDropped
        | ProbeKeyResult::WorkerExited
        | ProbeKeyResult::ChipUnavailable
        | ProbeKeyResult::InvalidSlot(_)
        | ProbeKeyResult::SlotCheck(_)) => {
            return Ok(DecryptResult::Failed(identity::Error::Identity {
                index: *identity_index,
                message: err.to_string(),
            }));
        }
    }

    let epk = parsed.ephemeral_pubkey;

    let mut result = match client
        .ecdh(context::current(), *serial, *slot, *tag, epk, None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Ok(DecryptResult::Failed(identity::Error::Internal {
                message: format!("Daemon RPC error: {e}"),
            }));
        }
    };

    if matches!(&result, Err(EcdhError::NeedPin)) {
        let prompt = format!("Enter PIN for YubiKey serial {}", serial);
        if let Ok(secret) = callbacks.request_secret(&prompt)? {
            let pin = secret.expose_secret().to_string();
            let _ = callbacks.message("Touch your YubiKey");
            result = match client
                .ecdh(context::current(), *serial, *slot, *tag, epk, Some(pin))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return Ok(DecryptResult::Failed(identity::Error::Internal {
                        message: format!("Daemon RPC error: {e}"),
                    }));
                }
            };
        } else {
            return Ok(DecryptResult::Failed(identity::Error::Identity {
                index: *identity_index,
                message: format!("PIN required for YubiKey serial {}", candidate.serial),
            }));
        }
    }

    match result {
        Ok(EcdhResponse {
            shared_secret,
            recipient_pubkey,
        }) => match parsed.derive_file_key(&shared_secret, &recipient_pubkey) {
            Ok(file_key) => Ok(DecryptResult::Decrypted(file_key)),
            Err(()) => Ok(DecryptResult::AeadFailed),
        },
        Err(err) => Ok(DecryptResult::Failed(identity::Error::Identity {
            index: *identity_index,
            message: err.to_string(),
        })),
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(identity::Error::Identity {
                index,
                message: format!("unknown plugin: {plugin_name}"),
            });
        }
        let (stub, _) =
            IdentityStub::read_from_prefix(bytes).map_err(|_| identity::Error::Identity {
                index,
                message: format!("invalid identity encoding ({} bytes)", bytes.len()),
            })?;
        self.identities.push(PluginIdentity { stub, index });
        Ok(())
    }

    ///Unwrap file keys by proxying ECDH to the daemon.
    ///
    /// Failures surface through three channels, chosen by scope:
    ///
    /// 1. **Hard abort** — `io::Result::Err` via `?`. Reserved for fatal I/O
    ///    on the `age` callback pipe (e.g. a broken `request_secret`). Aborts
    ///    the whole batch; no map is returned.
    /// 2. **Out-of-band** — `callbacks.error(..)`. For a global precondition
    ///    that dooms every file, namely being unable to reach the daemon.
    ///    Reported to `age` as a side-channel message; the function still
    ///    returns `Ok` with whatever (possibly empty) map it has.
    /// 3. **Per-file** — an `Err(Vec<identity::Error>)` entry in the returned
    ///    map. A file that couldn't be unwrapped carries its own accumulated
    ///    reasons while the batch as a whole succeeds. A pure serial mismatch
    ///    is *not* an error: the file simply gets no entry (an implicit skip).
    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<FileKeyMap> {
        let rt = TokioRuntime::new_current_thread().enable_all().build()?;
        rt.block_on(async {
            let Ok(client) = connect_daemon().await else {
                let _ = callbacks.error(identity::Error::Internal {
                    message: "age-plugin-yubikey-daemon is not running.".to_string(),
                });
                return Ok(FileKeyMap::new());
            };

            let mut file_keys: FileKeyMap = HashMap::with_capacity(files.len());
            for (file_idx, stanzas) in files.iter().enumerate() {
                let mut errors = Vec::new();

                for candidate in self.match_stanzas(stanzas) {
                    match process_candidate(&client, &candidate, &mut callbacks).await? {
                        DecryptResult::Decrypted(file_key) => {
                            debug!("Unwrapped file key for file {file_idx}");
                            file_keys.insert(file_idx, Ok(file_key));
                            break;
                        }
                        DecryptResult::AeadFailed => {
                            errors.push(identity::Error::Stanza {
                                file_index: file_idx,
                                stanza_index: candidate.stanza_index,
                                message: "AEAD decryption failed".to_string(),
                            });
                        }
                        DecryptResult::SerialMismatch => {}
                        DecryptResult::Failed(e) => {
                            errors.push(e);
                        }
                    }
                }

                if !file_keys.contains_key(&file_idx) && !errors.is_empty() {
                    file_keys.insert(file_idx, Err(errors));
                }
            }

            Ok(file_keys)
        })
    }
}

/// Connect to the running daemon and spawn an RPC client.
async fn connect_daemon() -> io::Result<YubikeyAgentClient> {
    let path = socket::path()?;
    let transport = connect(path, Bincode::default).await?;
    Ok(YubikeyAgentClient::new(client::Config::default(), transport).spawn())
}
