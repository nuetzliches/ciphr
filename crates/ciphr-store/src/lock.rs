//! One writer at a time, per store.
//!
//! # Why this exists
//!
//! The audit chain lives in memory. A process reads the stored head once, at
//! startup, and holds its position from then on. That is the right design for one
//! writer and quietly wrong for two: the second process moves the head, the first
//! does not notice, and its next record carries a sequence number that is already
//! taken. The device refuses it, no device accepts it, and fail-closed does what
//! it promises — the request is refused. The chain only advances on a committed
//! record, so the collision repeats for every request that follows.
//!
//! Measured, not theorised: one `ciphr put` from the command line while a server
//! was running turned every subsequent request into `503`, permanently, until the
//! server was restarted.
//!
//! Every part of that is a component behaving correctly. Sequence numbers are
//! unique because a gap must be distinguishable from a deletion. The request is
//! refused because nothing may be served unlogged. The chain does not advance
//! because a record no device accepted must not consume a number. What was missing
//! is the assumption underneath all three — that one process at a time writes to a
//! store — which was stated nowhere and enforced nowhere. This module states it and
//! enforces it.
//!
//! # Why refusing is the whole fix
//!
//! Because a restart was always required. After another process has written, the
//! server's in-memory head is stale and only a restart re-reads it. The lock does
//! not add a constraint; it makes an existing one visible **before** the damage
//! rather than as a `503` afterwards, and it says what to do about it.
//!
//! # Why not a fancier lock
//!
//! No new dependency, because `ciphr-store` should not grow one for this. A file
//! created with `create_new` is atomic on every filesystem that matters here, and
//! the holder's process id is written into it so a lock left behind by a crash can
//! be recognised rather than requiring a manual step forever.
//!
//! Liveness is checked through `/proc`, which is a directory lookup and no
//! dependency at all. Where it cannot be checked the lock is treated as held: an
//! unverifiable lock that is assumed dead is the one failure mode this module must
//! not have, and the error says how to clear it by hand.
//!
//! # Why the process id is not enough
//!
//! In a container the server is always process 1. A lock left behind by a killed
//! container therefore names a process id that the *next* container also has, so a
//! stale lock would look alive forever and no service could start again after an
//! unclean stop. Found by killing a container and starting a new one, which is what
//! a deployment does routinely.
//!
//! The lock therefore records the holder's **start time** alongside its id, read
//! from `/proc/<pid>/stat`. It is measured against the same kernel boot in every
//! container on a host, so a recycled process id with a different start time is
//! recognised as a different process.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::StoreError;

/// An acquired store lock. Released when dropped.
///
/// Held for the lifetime of a server, and for the duration of a single command in
/// the CLI. Both take the same lock, because two concurrent CLI invocations have
/// exactly the same problem as a CLI and a server.
#[derive(Debug)]
pub struct StoreLock {
    path: PathBuf,
}

impl StoreLock {
    /// Take the lock for a store, or fail saying who holds it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] if another live process holds it, or if a lock file
    /// exists whose holder cannot be verified. [`StoreError::Io`] if the lock file
    /// cannot be written.
    pub fn acquire(store: &Path) -> Result<Self, StoreError> {
        let path = lock_path(store);

        loop {
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(mut file) => {
                    // Best effort: the lock is the file's existence, not its
                    // contents. A failure to write costs a worse error message later
                    // and a lock that has to be cleared by hand, not correctness.
                    let pid = std::process::id();
                    let _ = match start_time(pid) {
                        Some(started) => write!(file, "{pid} {started}"),
                        None => write!(file, "{pid}"),
                    };
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = read_holder(&path);
                    match holder {
                        Some((pid, started)) if is_alive(pid, started) => {
                            return Err(StoreError::Locked { holder: Some(pid) });
                        }
                        Some((pid, _)) => {
                            // The holder is gone. Clear it and try once more; if
                            // another process wins the race, the next iteration
                            // finds a live holder and reports that instead.
                            let _ = fs::remove_file(&path);
                            let _ = pid;
                        }
                        // Unreadable or empty: cannot verify, so do not assume.
                        None => return Err(StoreError::Locked { holder: None }),
                    }
                }
                Err(error) => {
                    return Err(StoreError::Io {
                        detail: format!("cannot create {}: {error}", path.display()),
                    });
                }
            }
        }
    }

    /// Where the lock file lives, for error messages.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Best effort. A lock left behind by a crash is recognised as stale on the
        // next acquisition, which is why this does not need to be reliable.
        let _ = fs::remove_file(&self.path);
    }
}

/// The lock file for a store: the store path with `.lock` appended.
///
/// Appended rather than substituted, so it cannot collide with anything SQLite
/// creates — `-wal` and `-shm` are suffixes on the same name.
fn lock_path(store: &Path) -> PathBuf {
    let mut name = store.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// The holder recorded in a lock file: its process id, and its start time when the
/// writer was able to determine one.
fn read_holder(path: &Path) -> Option<(u32, Option<u64>)> {
    let text = fs::read_to_string(path).ok()?;
    let mut fields = text.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    Some((pid, fields.next().and_then(|s| s.parse().ok())))
}

/// When a process started, in clock ticks since boot.
///
/// Field 22 of `/proc/<pid>/stat`. Parsed from the last `)` rather than by splitting
/// the whole line, because field 2 is the executable name and may itself contain
/// spaces and parentheses.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(')')?.1;
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
const fn start_time(_pid: u32) -> Option<u64> {
    None
}

/// Whether a process is still running.
///
/// The two mistakes are not symmetric: treating a live holder as dead corrupts the
/// chain the lock exists to protect, while treating a dead one as live costs a
/// manual `rm` and an error message that says so. Everything here leans that way.
///
/// Decided at compile time rather than by probing for `/proc` at runtime. The
/// probe looked more portable and was worse: on Windows `Path::new("/proc")`
/// resolves against the current drive root and reported a directory, so the
/// fallback never ran, every holder looked dead, and the lock was stolen from a
/// live process. A test caught it, which is the only reason this comment exists
/// rather than a bug.
#[cfg(target_os = "linux")]
fn is_alive(pid: u32, started: Option<u64>) -> bool {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        return false;
    }
    match (started, start_time(pid)) {
        // Same id, different start: the id was recycled, and the holder is gone.
        // This is the container case -- every container's server is process 1.
        (Some(recorded), Some(current)) => recorded == current,
        // No start time recorded, or none readable now. Cannot tell them apart, so
        // assume the lock is held.
        _ => true,
    }
}

/// Where liveness cannot be established, a lock is held.
///
/// The deployment target is Linux; this is for a developer machine, where being
/// asked to remove a stale lock by hand is the right amount of friction.
#[cfg(not(target_os = "linux"))]
const fn is_alive(_pid: u32, _started: Option<u64>) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{StoreLock, lock_path};
    use crate::error::StoreError;

    #[test]
    fn the_lock_file_sits_beside_the_store() {
        // Appended, not substituted: `store.db.lock` cannot collide with the
        // `-wal` and `-shm` files SQLite puts next to `store.db`.
        let path = lock_path(std::path::Path::new("/var/lib/ciphr/store.db"));
        assert_eq!(path.to_str().unwrap(), "/var/lib/ciphr/store.db.lock");
    }

    #[test]
    fn a_second_acquisition_is_refused_while_the_first_is_held() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");

        let first = StoreLock::acquire(&store).expect("first acquisition");
        assert!(
            matches!(
                StoreLock::acquire(&store),
                Err(StoreError::Locked { holder: Some(_) })
            ),
            "the second acquisition must name the live holder"
        );
        drop(first);
    }

    #[test]
    fn releasing_makes_it_available_again() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");

        drop(StoreLock::acquire(&store).expect("first"));
        let second = StoreLock::acquire(&store);
        assert!(second.is_ok(), "a released lock must be re-acquirable");
    }

    // Liveness is only knowable on Linux, which is where this matters.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_lock_left_by_a_dead_process_is_taken_over() {
        // The case that would otherwise need a manual step after every crash. Pid 0
        // is never a live process, so this stands in for a holder that is gone.
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        std::fs::write(lock_path(&store), "0").expect("write stale lock");

        assert!(
            StoreLock::acquire(&store).is_ok(),
            "a lock whose holder is gone must not need a manual step"
        );
    }

    /// The container case, and the reason a process id alone is not enough.
    ///
    /// In a container the server is process 1. A lock left behind by a killed
    /// container names process 1, and the next container has a process 1 too -- so
    /// without a start time the stale lock looks alive forever and nothing can start
    /// again after an unclean stop. Found by killing a container and starting
    /// another, which is what a deploy does.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_recycled_process_id_does_not_keep_a_dead_lock_alive() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");

        // This process, but claiming a start time it does not have.
        let pid = std::process::id();
        let real = super::start_time(pid).expect("a start time on linux");
        std::fs::write(lock_path(&store), format!("{pid} {}", real + 1)).expect("write");

        assert!(
            StoreLock::acquire(&store).is_ok(),
            "same id, different start time means a different process"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_holder_with_a_matching_start_time_still_holds() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");

        let pid = std::process::id();
        let real = super::start_time(pid).expect("a start time on linux");
        std::fs::write(lock_path(&store), format!("{pid} {real}")).expect("write");

        assert!(matches!(
            StoreLock::acquire(&store),
            Err(StoreError::Locked { holder: Some(_) })
        ));
    }

    #[test]
    fn an_unreadable_lock_is_treated_as_held() {
        // The asymmetry that matters: assuming a live holder is dead corrupts the
        // chain, assuming a dead one is live costs one `rm` and a message saying so.
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        std::fs::write(lock_path(&store), "not-a-pid").expect("write");

        assert!(matches!(
            StoreLock::acquire(&store),
            Err(StoreError::Locked { holder: None })
        ));
    }
}
