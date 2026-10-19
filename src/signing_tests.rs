use super::*;

use ssh_key::Mpint;
use ssh_key::public::RsaPublicKey;
use tokio::sync::mpsc::error::TryRecvError;

fn rsa_key(fill: u8) -> KeyData {
    KeyData::Rsa(RsaPublicKey {
        e: Mpint::from_positive_bytes(&[0x01, 0x00, 0x01]).unwrap(),
        n: Mpint::from_positive_bytes(&[fill; 256]).unwrap(),
    })
}

fn agent(sign_slots: &[SlotId]) -> (SigningAgent, mpsc::Receiver<WorkerRequest>) {
    let (tx, rx) = mpsc::channel(1);
    let agent = SigningAgent::new(tx, Arc::from(sign_slots));
    (agent, rx)
}

/// Answer worker requests as a card whose slot 9c holds `rsa_key(0xAB)`.
fn fake_worker(mut rx: mpsc::Receiver<WorkerRequest>) -> tokio::task::JoinHandle<Vec<SlotId>> {
    tokio::spawn(async move {
        let mut signed = Vec::new();
        while let Some(request) = rx.recv().await {
            match request {
                WorkerRequest::SlotKey { slot, reply } => {
                    assert_eq!(slot, SlotId::Signature);
                    reply.send(Ok(rsa_key(0xAB))).ok();
                }
                WorkerRequest::Sign {
                    slot,
                    message,
                    reply,
                } => {
                    signed.push(slot);
                    reply.send(Ok(message.into_iter().rev().collect())).ok();
                }
                _ => panic!("unexpected worker request"),
            }
        }
        signed
    })
}

fn sign_request(key: KeyData, flags: u32) -> SignRequest {
    SignRequest {
        credential: PublicCredential::Key(key),
        data: b"message".to_vec(),
        flags,
    }
}

#[tokio::test]
async fn no_sign_slots_lists_no_identities_without_card_access() {
    let (mut agent, mut rx) = agent(&[]);

    let identities = agent.request_identities().await.unwrap();

    assert!(identities.is_empty());
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn lists_allowed_slot_keys() {
    let (mut agent, rx) = agent(&[SlotId::Signature]);
    let worker = fake_worker(rx);

    let identities = agent.request_identities().await.unwrap();
    drop(agent);

    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].credential,
        PublicCredential::Key(rsa_key(0xAB))
    );
    assert_eq!(identities[0].comment, "YubiKey PIV slot 9c");
    assert!(worker.await.unwrap().is_empty());
}

#[tokio::test]
async fn refuses_sign_unless_flags_are_exactly_rsa_sha2_256() {
    let (agent, mut rx) = agent(&[SlotId::Signature]);

    for flags in [
        0,
        signature::RSA_SHA2_512,
        signature::RSA_SHA2_256 | signature::RSA_SHA2_512,
    ] {
        let result = agent.sign_request(sign_request(rsa_key(0xAB), flags)).await;
        assert_eq!(result, Err(SignError::UnsupportedFlags(flags)));
    }
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn refuses_sign_for_key_not_in_allowed_slots() {
    let (agent, rx) = agent(&[SlotId::Signature]);
    let worker = fake_worker(rx);

    let result = agent
        .sign_request(sign_request(rsa_key(0xCD), signature::RSA_SHA2_256))
        .await;
    drop(agent);

    assert_eq!(result, Err(SignError::KeyNotInSignSlots));
    assert!(worker.await.unwrap().is_empty());
}

#[tokio::test]
async fn refused_sign_replies_with_agent_failure() {
    let (mut agent, _rx) = agent(&[SlotId::Signature]);

    let result = agent.sign(sign_request(rsa_key(0xAB), 0)).await;

    assert!(matches!(result, Err(AgentError::Failure)));
}

#[tokio::test]
async fn signs_with_matching_slot_as_rsa_sha2_256() {
    let (agent, rx) = agent(&[SlotId::Signature]);
    let worker = fake_worker(rx);

    let signature = agent
        .sign_request(sign_request(rsa_key(0xAB), signature::RSA_SHA2_256))
        .await
        .unwrap();
    drop(agent);

    assert_eq!(
        signature.algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }
    );
    assert_eq!(signature.as_bytes(), b"egassem");
    assert_eq!(worker.await.unwrap(), vec![SlotId::Signature]);
}
