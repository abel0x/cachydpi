// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
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
use std::time::{Duration, Instant};

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

    // Readable by any local user so `cachydpi monitor` needs no privileges.
    //
    // That is only acceptable because the snapshot carries counters and recent
    // events, and event messages are fixed strings that never name a peer,
    // whatever [logging] log_identifying_fields says. They used to embed the
    // address of every DPI-forged packet's source, which made this socket a
    // second route to the browsing data the journal records. Anything added to
    // the snapshot has to stay safe to hand to an unprivileged process.
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666));

    // Non-blocking accept so we can check shutdown flag periodically
    if let Err(e) = listener.set_nonblocking(true) {
        warn!(
            "metrics server: set_nonblocking failed: {} — using blocking mode",
            e
        );
    }

    debug!("metrics server listening on {}", socket_path);

    let mut cache = SnapshotCache::default();
    let mut admission = Admission::default();

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let now = Instant::now();
                if !admission.admit(now) {
                    // Closing without a reply is the cheapest answer there is;
                    // the monitor reports it as a closed connection.
                    if admission.refused_in_window == 1 {
                        debug!(
                            "metrics server: over {} connections this second, \
                             closing the rest unanswered",
                            MAX_CONNECTIONS_PER_SEC
                        );
                    }
                    continue;
                }

                // Set a write timeout to avoid blocking on slow clients
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                let reply = cache.get(now, build_reply);
                if !reply.is_empty() {
                    let _ = stream.write_all(reply);
                    let _ = stream.flush();
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

/// How long one serialized snapshot is served before a fresh one is built.
///
/// Any local account can connect, as often as it likes, and building a
/// snapshot reads three procfs files and serializes the event buffer. The
/// daemon runs under `CPUQuota=25%` shared with packet handling, so that work
/// has to be paid once per interval, not once per connection. Half the
/// monitor's 1 s refresh keeps every monitor poll on a fresh snapshot.
const SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(500);

/// Connections answered per second. A monitor polls once a second, so this
/// leaves room for a good number of them while capping what a client looping
/// on `connect` can make the daemon do.
const MAX_CONNECTIONS_PER_SEC: u32 = 20;

fn build_reply() -> Vec<u8> {
    match serde_json::to_vec(&METRICS.snapshot()) {
        Ok(mut json) => {
            json.push(b'\n');
            json
        }
        Err(e) => {
            debug!("metrics server: JSON serialization failed: {}", e);
            Vec::new()
        }
    }
}

/// The last serialized snapshot, and when it was built.
#[derive(Default)]
struct SnapshotCache {
    reply: Vec<u8>,
    built: Option<Instant>,
}

impl SnapshotCache {
    fn get(&mut self, now: Instant, build: impl FnOnce() -> Vec<u8>) -> &[u8] {
        let stale = self
            .built
            .is_none_or(|at| now.saturating_duration_since(at) >= SNAPSHOT_MAX_AGE);
        if stale {
            self.reply = build();
            self.built = Some(now);
        }
        &self.reply
    }
}

/// A fixed one-second window counting the connections answered in it.
#[derive(Default)]
struct Admission {
    window_start: Option<Instant>,
    served_in_window: u32,
    refused_in_window: u32,
}

impl Admission {
    fn admit(&mut self, now: Instant) -> bool {
        let new_window = self
            .window_start
            .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(1));
        if new_window {
            self.window_start = Some(now);
            self.served_in_window = 0;
            self.refused_in_window = 0;
        }
        if self.served_in_window < MAX_CONNECTIONS_PER_SEC {
            self.served_in_window += 1;
            true
        } else {
            self.refused_in_window = self.refused_in_window.saturating_add(1);
            false
        }
    }
}

fn choose_socket_path() -> String {
    let run_dir = Path::new("/run/cachydpi");
    if run_dir.is_dir() || fs::create_dir_all(run_dir).is_ok() {
        DEFAULT_METRICS_SOCKET.to_string()
    } else {
        FALLBACK_METRICS_SOCKET.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_is_built_once_per_interval() {
        let mut cache = SnapshotCache::default();
        let mut builds = 0;
        let t0 = Instant::now();
        let mut build = || {
            builds += 1;
            format!("{builds}\n").into_bytes()
        };
        assert_eq!(cache.get(t0, &mut build), b"1\n");
        for ms in [1, 100, 499] {
            assert_eq!(
                cache.get(t0 + Duration::from_millis(ms), &mut build),
                b"1\n"
            );
        }
        assert_eq!(cache.get(t0 + SNAPSHOT_MAX_AGE, &mut build), b"2\n");
        assert_eq!(builds, 2);
    }

    #[test]
    fn connections_past_the_budget_are_refused_until_the_next_second() {
        let mut admission = Admission::default();
        let t0 = Instant::now();
        for _ in 0..MAX_CONNECTIONS_PER_SEC {
            assert!(admission.admit(t0));
        }
        assert!(!admission.admit(t0 + Duration::from_millis(10)));
        assert!(!admission.admit(t0 + Duration::from_millis(999)));
        assert!(admission.admit(t0 + Duration::from_secs(1)));
    }
}
