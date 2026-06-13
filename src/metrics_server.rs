// src/metrics_server.rs — Unix socket server for metrics export
//
// Runs in a dedicated thread. Accepts connections on a Unix domain socket,
// serves a JSON snapshot of current metrics, then closes the connection.
// Protocol: connect → receive JSON line → done. One connection = one snapshot.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, warn};

use crate::metrics::{DEFAULT_METRICS_SOCKET, FALLBACK_METRICS_SOCKET, METRICS};

/// Run the metrics server loop until shutdown is signaled.
/// Designed to be called from a dedicated thread.
pub fn run_metrics_server(shutdown: &AtomicBool) {
    let socket_path = choose_socket_path();

    // Remove stale socket from previous run
    let _ = fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "metrics server: failed to bind {}: {} — monitoring disabled",
                socket_path, e
            );
            return;
        }
    };

    // Make socket accessible to non-root users (metrics data is not sensitive)
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666));

    // Non-blocking accept so we can check shutdown flag periodically
    if let Err(e) = listener.set_nonblocking(true) {
        warn!(
            "metrics server: set_nonblocking failed: {} — using blocking mode",
            e
        );
    }

    debug!("metrics server listening on {}", socket_path);

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Set a write timeout to avoid blocking on slow clients
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                let snapshot = METRICS.snapshot();
                match serde_json::to_string(&snapshot) {
                    Ok(json) => {
                        let _ = stream.write_all(json.as_bytes());
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();
                    }
                    Err(e) => {
                        debug!("metrics server: JSON serialization failed: {}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connections — sleep briefly, then re-check shutdown
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                debug!("metrics server: accept error: {}", e);
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    // Cleanup socket file
    let _ = fs::remove_file(&socket_path);
    debug!("metrics server stopped");
}

fn choose_socket_path() -> String {
    let run_dir = Path::new("/run/cachydpi");
    if run_dir.is_dir() || fs::create_dir_all(run_dir).is_ok() {
        DEFAULT_METRICS_SOCKET.to_string()
    } else {
        FALLBACK_METRICS_SOCKET.to_string()
    }
}
