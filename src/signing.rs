//! ssh-agent server for signing with keys in `--sign-slot` slots.
//!
//! Only `REQUEST_IDENTITIES` and `SIGN_REQUEST` with the `rsa-sha2-256` flag
//! are supported. All other messages get the protocol's failure reply.

use std::sync::Arc;
use std::time::Duration;

use log::{error, warn};
use ssh_agent_lib::agent::{Agent, ListeningSocket, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest, signature};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use yubikey::piv::SlotId;

use crate::daemon::{SignError, WorkerRequest};

/// A Unix listener that logs `accept()` errors and tries again after one
/// second. The delay prevents a busy loop while the error continues.
///
/// `ssh_agent_lib::agent::listen` stops permanently on the first `accept()`
/// error. These errors are temporary (for example, `EMFILE`), so the
/// signing socket must continue, the same as the age socket.
#[derive(Debug)]
pub(crate) struct Listener(pub(crate) UnixListener);

#[async_trait::async_trait]
impl ListeningSocket for Listener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> std::io::Result<UnixStream> {
        loop {
            match self.0.accept().await {
                Ok((stream, _addr)) => return Ok(stream),
                Err(e) => {
                    error!("Signing socket accept error: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct SigningAgent {
    tx: mpsc::Sender<WorkerRequest>,
    sign_slots: Arc<[SlotId]>,
}

impl SigningAgent {
    pub(crate) fn new(tx: mpsc::Sender<WorkerRequest>, sign_slots: Arc<[SlotId]>) -> Self {
        Self { tx, sign_slots }
    }

    async fn request(&self, request: WorkerRequest) -> Result<(), SignError> {
        self.tx
            .send(request)
            .await
            .map_err(|_| SignError::WorkerExited)
    }

    /// Return public keys for allowed slots. Skip slots whose keys cannot be read.
    async fn slot_keys(&self) -> Result<Vec<(SlotId, KeyData)>, SignError> {
        let mut keys = Vec::new();
        for &slot in self.sign_slots.iter() {
            let (reply, reply_rx) = oneshot::channel();
            self.request(WorkerRequest::SlotKey { slot, reply }).await?;
            match reply_rx.await.map_err(|_| SignError::WorkerExited)? {
                Ok(key) => keys.push((slot, key)),
                Err(e) => warn!(
                    "Could not read key from slot 0x{:02x}; skipping: {e}",
                    u8::from(slot)
                ),
            }
        }
        Ok(keys)
    }

    async fn sign_request(&self, request: SignRequest) -> Result<Signature, SignError> {
        if request.flags != signature::RSA_SHA2_256 {
            return Err(SignError::UnsupportedFlags(request.flags));
        }
        let PublicCredential::Key(requested) = request.credential else {
            return Err(SignError::UnknownKey);
        };
        let slot = self
            .slot_keys()
            .await?
            .into_iter()
            .find_map(|(slot, key)| (key == requested).then_some(slot))
            .ok_or(SignError::UnknownKey)?;

        let (reply, reply_rx) = oneshot::channel();
        self.request(WorkerRequest::Sign {
            slot,
            message: request.data,
            reply,
        })
        .await?;
        let signature = reply_rx.await.map_err(|_| SignError::WorkerExited)??;
        Signature::new(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            signature,
        )
        .map_err(|_| SignError::SignFailed)
    }
}

impl Agent<Listener> for SigningAgent {
    fn new_session(&mut self, _socket: &UnixStream) -> impl Session {
        self.clone()
    }
}

#[async_trait::async_trait]
impl Session for SigningAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.slot_keys().await.map_err(|e| {
            error!("Could not list signing keys: {e}");
            AgentError::Failure
        })?;
        Ok(keys
            .into_iter()
            .map(|(slot, key)| Identity {
                credential: PublicCredential::Key(key),
                comment: format!("YubiKey PIV slot {:02x}", u8::from(slot)),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.sign_request(request).await.map_err(|e| {
            error!("Could not sign: {e}");
            AgentError::Failure
        })
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
