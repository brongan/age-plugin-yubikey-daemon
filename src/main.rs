//! age-plugin-yubikey-agent: PIN-caching daemon + age plugin + identity file conversion
//!
//! Invoked without arguments, it runs as a daemon holding a PCSC session to the `YubiKey`.
//! Invoked with `--age-plugin=identity-v1` (by `age`), it
//! speaks the C2SP age-plugin protocol and proxies ECDH to the daemon.
//! Invoked with a file path, it converts an age-plugin-yubikey identity file to
//! age-plugin-yubikey-agent.

#![forbid(unsafe_code)]

use log::error;

use age_plugin_yubikey_agent::daemon;
use age_plugin_yubikey_agent::socket;
use log::info;

use crate::convert_identities::convert_identities;
use tokio::runtime::Builder as TokioRuntime;

mod convert_identities;
mod plugin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let arg = std::env::args().nth(1);

    match arg {
        None => {
            let runtime = TokioRuntime::new_current_thread().enable_all().build()?;
            runtime.block_on(async {
                let listener = match socket::from_systemd()? {
                    Some(listener) => {
                        info!("Using systemd socket activation");
                        listener
                    }
                    None => {
                        let socket_path = socket::create()?;
                        info!("Listening on {}", socket_path.display());
                        socket::bind(&socket_path)?
                    }
                };
                daemon::run(listener).await
            })?;
            Ok(())
        }
        Some(arg) => match arg.strip_prefix("--age-plugin=") {
            Some(sm) => age_plugin::run_state_machine(sm, plugin::Handler)
                .inspect_err(|e| error!("Plugin state machine failed: {e}"))
                .map_err(Into::into),
            None => convert_identities(&arg),
        },
    }
}
