use super::*;

use futures::StreamExt;
use p256::SecretKey;
use tarpc::client;
use tarpc::context;
use tarpc::server::Channel;
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
async fn probe_key_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let (client_stream, server_stream) = tokio::io::duplex(1024);

    let server_transport = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(server_stream),
        Bincode::default(),
    );

    tokio::spawn(async move {
        let server = MockDaemon;
        let channel = tarpc::server::BaseChannel::with_defaults(server_transport);
        channel
            .execute(server.serve())
            .for_each(|response| async move {
                tokio::spawn(response);
            })
            .await;
    });

    let client_transport = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(client_stream),
        Bincode::default(),
    );
    let client = YubikeyAgentClient::new(client::Config::default(), client_transport).spawn();

    let res = client
        .probe_key(context::current(), 12345, 0x82, [0; 4])
        .await?;
    assert_eq!(res, ProbeKeyResult::Match);

    Ok(())
}

#[tokio::test]
async fn ecdh_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    tokio::spawn(async move {
        while let Some(transport) = rx.recv().await {
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

    // First connection
    let (client_stream1, server_stream1) = tokio::io::duplex(1024);
    let server_transport1 = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(server_stream1),
        Bincode::default(),
    );
    tx.send(server_transport1).await?;

    let client_transport1 = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(client_stream1),
        Bincode::default(),
    );
    let client1 = YubikeyAgentClient::new(client::Config::default(), client_transport1).spawn();

    let res = client1
        .ecdh(context::current(), 12345, 0x82, [0; 4], mock_pubkey(), None)
        .await?;
    assert!(matches!(res, Err(EcdhError::NeedPin)));

    // Second connection
    let (client_stream2, server_stream2) = tokio::io::duplex(1024);
    let server_transport2 = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(server_stream2),
        Bincode::default(),
    );
    tx.send(server_transport2).await?;

    let client_transport2 = tarpc::serde_transport::new(
        tokio_util::codec::LengthDelimitedCodec::builder().new_framed(client_stream2),
        Bincode::default(),
    );
    let client2 = YubikeyAgentClient::new(client::Config::default(), client_transport2).spawn();

    let res2 = client2
        .ecdh(
            context::current(),
            12345,
            0x82,
            [0; 4],
            mock_pubkey(),
            Some("654321".to_string()),
        )
        .await??;

    assert_eq!(res2.shared_secret, [0xCC; 32]);

    Ok(())
}

