use super::*;

use futures::StreamExt;
use p256::SecretKey;
use tarpc::client;
use tarpc::context;
use tarpc::server::Channel;
use tokio::net::UnixListener;
use tokio_serde::formats::Bincode;

fn mock_pubkey() -> p256::PublicKey {
    SecretKey::random(&mut rand::thread_rng()).public_key()
}

#[derive(Clone)]
struct MockDaemon;

impl YubikeyAgent for MockDaemon {
    async fn probe_key(
        self,
        _: context::Context,
        serial: u32,
        _slot: u8,
        _tag: [u8; TAG_BYTES],
    ) -> ProbeKeyResult {
        if serial == 12345 {
            ProbeKeyResult::Match
        } else {
            ProbeKeyResult::SerialMismatch
        }
    }

    async fn ecdh(
        self,
        _: context::Context,
        serial: u32,
        _slot: u8,
        _tag: [u8; TAG_BYTES],
        _ephemeral_pubkey: p256::PublicKey,
        pin: Option<String>,
    ) -> EcdhResult {
        if serial != 12345 {
            return Err(EcdhError::SerialMismatch);
        }
        if pin.as_deref() != Some("654321") {
            return Err(EcdhError::NeedPin);
        }
        Ok(EcdhResponse {
            shared_secret: [0xCC; 32],
            recipient_pubkey: mock_pubkey(),
        })
    }
}

#[tokio::test]
async fn probe_key_round_trip() {
    let dir = std::env::temp_dir().join("age-agent-test-probe_key");
    std::fs::create_dir_all(&dir).unwrap();
    let sock_path = dir.join(format!("mock-probe_key-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path).unwrap();
    let mut incoming = tarpc::serde_transport::unix::listen_on(listener, Bincode::default)
        .await
        .unwrap();

    let server_task = tokio::spawn(async move {
        let transport = incoming.next().await.unwrap().unwrap();
        let server = MockDaemon;
        let channel = tarpc::server::BaseChannel::with_defaults(transport);
        channel
            .execute(server.serve())
            .for_each(|response| async move {
                tokio::spawn(response);
            })
            .await;
    });

    let transport = tarpc::serde_transport::unix::connect(&sock_path, Bincode::default)
        .await
        .unwrap();
    let client = YubikeyAgentClient::new(client::Config::default(), transport).spawn();

    let res = client
        .probe_key(context::current(), 12345, 0x82, [0; 4])
        .await
        .unwrap();
    assert_eq!(res, ProbeKeyResult::Match);

    server_task.abort();
}

#[tokio::test]
async fn ecdh_round_trip() {
    let dir = std::env::temp_dir().join("age-agent-test-ecdh");
    std::fs::create_dir_all(&dir).unwrap();
    let sock_path = dir.join(format!("mock-ecdh-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path).unwrap();
    let mut incoming = tarpc::serde_transport::unix::listen_on(listener, Bincode::default)
        .await
        .unwrap();

    let server_task = tokio::spawn(async move {
        while let Some(Ok(transport)) = incoming.next().await {
            tokio::spawn(async move {
                let server = MockDaemon;
                let channel = tarpc::server::BaseChannel::with_defaults(transport);
                channel
                    .execute(server.serve())
                    .for_each(|response| async move {
                        tokio::spawn(response);
                    })
                    .await;
            });
        }
    });

    let transport1 = tarpc::serde_transport::unix::connect(&sock_path, Bincode::default)
        .await
        .unwrap();
    let client1 = YubikeyAgentClient::new(client::Config::default(), transport1).spawn();

    let res = client1
        .ecdh(context::current(), 12345, 0x82, [0; 4], mock_pubkey(), None)
        .await
        .unwrap();
    assert!(matches!(res, Err(EcdhError::NeedPin)));

    let transport2 = tarpc::serde_transport::unix::connect(&sock_path, Bincode::default)
        .await
        .unwrap();
    let client2 = YubikeyAgentClient::new(client::Config::default(), transport2).spawn();

    let res2 = client2
        .ecdh(
            context::current(),
            12345,
            0x82,
            [0; 4],
            mock_pubkey(),
            Some("654321".to_string()),
        )
        .await
        .unwrap();

    match res2 {
        Ok(EcdhResponse { shared_secret, .. }) => {
            assert_eq!(shared_secret, [0xCC; 32]);
        }
        other => panic!("expected Ok, got {:?}", other),
    }

    server_task.abort();
}
