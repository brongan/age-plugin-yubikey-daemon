//! age-plugin-yubikey-daemon: PIN-caching daemon + age plugin + identity file conversion
//!
//! Invoked without arguments, or with only `--sign-slot <slot>` arguments, it
//! runs as a daemon with a PCSC session to the `YubiKey`. It serves age on one
//! socket and ssh-agent signing for `--sign-slot` slots on another.
//! Invoked with `--age-plugin=identity-v1` (by `age`), it
//! speaks the C2SP age-plugin protocol and proxies ECDH to the daemon.
//! Invoked with a file path, it converts an age-plugin-yubikey identity file to
//! age-plugin-yubikey-daemon.

#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;

use listenfd::ListenFd;
use log::error;

use age_plugin_yubikey_daemon::daemon;
use age_plugin_yubikey_daemon::socket;
use log::info;
use tokio::net::UnixListener;
use yubikey::piv::SlotId;

use crate::convert_identities::convert_identities;
use tokio::runtime::Builder as TokioRuntime;

mod convert_identities;
mod plugin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("--sign-slot") => {
            let sign_slots = parse_sign_slots(&args)?;
            let runtime = TokioRuntime::new_current_thread().enable_all().build()?;
            let result = runtime.block_on(async {
                // `ListenFd::from_env` clears the systemd variables, so read them only once.
                let mut fds = ListenFd::from_env();
                let listener = listen(&mut fds, 0, socket::create)?;
                let signing_listener = listen(&mut fds, 1, socket::create_signing)?;
                daemon::run(listener, signing_listener, sign_slots).await
            });
            // The YubiKey worker can wait for pinentry or a touch. Do not wait for it at exit.
            runtime.shutdown_background();
            Ok(result?)
        }
        Some(arg) => match arg.strip_prefix("--age-plugin=") {
            Some(sm) => age_plugin::run_state_machine(sm, plugin::Handler)
                .inspect_err(|e| error!("Plugin state machine failed: {e}"))
                .map_err(Into::into),
            None => convert_identities(arg),
        },
    }
}

/// Take the systemd socket at `index`, or bind the path from `create`.
fn listen(
    fds: &mut ListenFd,
    index: usize,
    create: fn() -> io::Result<PathBuf>,
) -> io::Result<UnixListener> {
    match socket::from_systemd(fds, index)? {
        Some(listener) => {
            info!("Using systemd socket activation");
            Ok(listener)
        }
        None => {
            let socket_path = create()?;
            info!("Listening on {}", socket_path.display());
            socket::bind(&socket_path)
        }
    }
}

/// Parse `--sign-slot <slot>` pairs, where `<slot>` is a hex PIV slot such as `9c`.
fn parse_sign_slots(args: &[String]) -> Result<Vec<SlotId>, String> {
    args.chunks(2)
        .map(|pair| match pair {
            [flag, slot] if flag == "--sign-slot" => u8::from_str_radix(slot, 16)
                .ok()
                .and_then(|byte| SlotId::try_from(byte).ok())
                .ok_or_else(|| format!("invalid --sign-slot value {slot:?}")),
            _ => Err(format!("expected --sign-slot <slot>, got {pair:?}")),
        })
        .collect()
}
