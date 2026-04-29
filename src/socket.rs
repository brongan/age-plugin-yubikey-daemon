//! Socket lifecycle: XDG path resolution, systemd activation, stale-socket
//! cleanup, and listener binding.

use std::fs;
use std::io;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use log::info;
use tokio::net::UnixListener;
use xdg::BaseDirectories;

static XDG_PREFIX: &str = "com.brongan.age-plugin-yubikey-agent";
static FILENAME: &str = "daemon.sock";

/// Creates the socket directory and returns the path at
/// `$XDG_RUNTIME_DIR/com.brongan.age-plugin-yubikey-agent/daemon.sock`.
pub fn create() -> io::Result<PathBuf> {
    BaseDirectories::with_prefix(XDG_PREFIX).place_runtime_file(FILENAME)
}

/// Returns the path to an existing socket, or an error if it doesn't exist.
pub fn path() -> io::Result<PathBuf> {
    BaseDirectories::with_prefix(XDG_PREFIX).get_runtime_file(FILENAME)
}

/// Bind a new listener, removing a stale socket if one exists.
///
/// If the socket path exists and a process is still listening on it,
/// returns `AddrInUse`. If the socket is stale (connection refused),
/// removes it and binds fresh.
///
/// Access control rides on the directory, not the socket file's own mode.
/// The socket lives under `$XDG_RUNTIME_DIR`, which is `0700` and owned by
/// the user, so no other user can traverse to it regardless of the socket's
/// permissions. We deliberately don't `chmod` the socket after `bind`: it
/// would only narrow the file mode (the systemd unit already sets `0600` via
/// `UMask=0177`) while opening a TOCTOU window between bind and chmod, and
/// the `0700` parent is the real guard either way.
pub fn bind(socket_path: &Path) -> io::Result<UnixListener> {
    if socket_path.exists() {
        if StdUnixStream::connect(socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another daemon is already listening on this socket",
            ));
        }
        info!("Removing stale socket {}", socket_path.display());
        fs::remove_file(socket_path)?;
    }
    UnixListener::bind(socket_path)
}

/// Take a systemd-activated Unix listener via `listenfd`.
pub fn from_systemd() -> io::Result<Option<UnixListener>> {
    let std_listener = listenfd::ListenFd::from_env()
        .take_unix_listener(0)
        .map_err(io::Error::other)?;
    std_listener
        .map(|l| {
            l.set_nonblocking(true)?;
            UnixListener::from_std(l)
        })
        .transpose()
}
