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
    /// The bytes this guard wrote into the lock file, and the only thing that makes
    /// it *this* guard's lock rather than whatever currently has the name.
    ///
    /// F2 of the review of 2026-08-24: the lock used to be the file's existence and
    /// nothing else, so every operation on it acted on a pathname. Two processes
    /// could both classify one dead holder as stale, and the second one's removal
    /// then deleted the *first* one's fresh lock -- after which both held it. `Drop`
    /// had the same shape: it removed whatever was at the path.
    identity: String,
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
                    // The contents are load-bearing now: they are what identifies
                    // this guard's lock later, to `Drop` and to anyone deciding
                    // whether a stale file is still the one they looked at. A lock
                    // that cannot be identified is not one to hold, so a failed
                    // write removes the file and reports rather than proceeding.
                    let pid = std::process::id();
                    let identity = match start_time(pid) {
                        Some(started) => format!("{pid} {started}"),
                        None => format!("{pid}"),
                    };
                    if let Err(error) = file.write_all(identity.as_bytes()) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(StoreError::Io {
                            detail: format!("cannot write {}: {error}", path.display()),
                        });
                    }
                    drop(file);

                    // Read back what is at the path. Between the create above and
                    // here, another process that had already decided the *previous*
                    // holder was stale can have removed this file and created its
                    // own -- the second half of F2. If these bytes are not ours, we
                    // do not hold this lock, whatever `create_new` returned.
                    if read_raw(&path).as_deref() != Some(identity.as_str()) {
                        continue;
                    }

                    return Ok(Self { path, identity });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let Some(existing) = read_raw(&path) else {
                        // Unreadable or empty: cannot verify, so do not assume.
                        return Err(StoreError::Locked { holder: None });
                    };
                    let holder = parse_holder(&existing);
                    match holder {
                        Some((pid, started)) if is_alive(pid, started) => {
                            return Err(StoreError::Locked { holder: Some(pid) });
                        }
                        Some(_) => {
                            // The holder is gone. Remove **the file we just looked
                            // at**, not whatever has the name by the time this runs:
                            // another process may already have cleared it and taken
                            // the lock, and deleting that would hand the store two
                            // writers (F2). If the bytes have changed, the next
                            // iteration reads them and reports the new holder.
                            remove_if_unchanged(&path, &existing);
                        }
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
        // Only this guard's own lock. Removing whatever has the name would let a
        // process that has finished delete a lock somebody else is holding, which
        // is the same defect as the takeover race one level up (F2).
        //
        // Still best effort in the other direction: a lock left behind by a crash
        // is recognised as stale on the next acquisition, which is why this does
        // not need to succeed.
        remove_if_unchanged(&self.path, &self.identity);
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
/// What the lock file says, verbatim.
///
/// Verbatim because the bytes are the identity: a decision about a lock has to be
/// carried out against the same bytes it was made about, and a parsed form cannot
/// answer "is this still the file I looked at".
fn read_raw(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    Some(text)
}

fn parse_holder(text: &str) -> Option<(u32, Option<u64>)> {
    let mut fields = text.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    Some((pid, fields.next().and_then(|s| s.parse().ok())))
}

/// Remove the lock file **only if it still holds `expected`**.
///
/// Not atomic, and it does not have to be: what it prevents is a decision made
/// about one holder being executed against a different one. The window that
/// remains -- the file changing between this read and the removal -- is closed one
/// level up, where a fresh lock is read back after it is created and a guard that
/// does not find its own bytes tries again instead of returning a lock it does not
/// hold.
fn remove_if_unchanged(path: &Path, expected: &str) {
    if read_raw(path).as_deref() == Some(expected) {
        let _ = fs::remove_file(path);
    }
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

    /// F2 of the review of 2026-08-24, as the step where it actually goes wrong.
    ///
    /// Two processes find the same dead holder and both decide it is stale. The
    /// first clears it and takes the lock. The second then executes the removal it
    /// had already decided on — and before this fix that removal deleted the *new*
    /// holder's file, after which both processes held the store.
    ///
    /// What this test does not do is orchestrate two processes: it drives the step
    /// that carries out the decision. That is the whole of the defect, and a test
    /// that spawned two processes would assert the same thing with a scheduler in
    /// the way.
    #[test]
    fn a_decision_about_one_holder_is_not_carried_out_against_another() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        let path = lock_path(&store);

        // What the second process read: a holder it has classified as dead.
        let stale = "4242 100";
        std::fs::write(&path, stale).expect("write");

        // What the first process left there in the meantime.
        let winner = "5151 200";
        std::fs::write(&path, winner).expect("write");

        super::remove_if_unchanged(&path, stale);

        assert_eq!(
            std::fs::read_to_string(&path).expect("the lock must still be there"),
            winner,
            "a stale-lock decision must not remove a lock somebody else now holds"
        );
    }

    /// The same defect in `Drop`, which used to remove whatever had the name.
    #[test]
    fn dropping_a_guard_does_not_remove_a_lock_it_no_longer_owns() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        let path = lock_path(&store);

        let guard = StoreLock::acquire(&store).expect("nothing holds it");

        // Whatever put this here, it is not the guard below.
        let somebody_else = "9999 300";
        std::fs::write(&path, somebody_else).expect("write");

        drop(guard);

        assert_eq!(
            std::fs::read_to_string(&path).expect("the lock must still be there"),
            somebody_else,
            "a guard must release its own lock and nobody else's"
        );
    }

    /// And the ordinary case still has to work: a guard releases what it took.
    #[test]
    fn dropping_a_guard_removes_the_lock_it_does_own() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        let path = lock_path(&store);

        drop(StoreLock::acquire(&store).expect("nothing holds it"));

        assert!(!path.exists(), "the lock file must be gone");
    }

    /// The identity is what the file says, so an empty one is not a lock.
    ///
    /// Before this fix the write was best effort and an empty lock file counted as
    /// held-by-nobody-identifiable. It still counts as held — that asymmetry is
    /// deliberate — but a guard can no longer *return* holding one.
    #[test]
    fn a_lock_file_with_no_identity_is_not_a_lock_anybody_holds() {
        let directory = tempfile::tempdir().expect("temp dir");
        let store = directory.path().join("store.db");
        std::fs::write(lock_path(&store), "   ").expect("write");

        assert!(matches!(
            StoreLock::acquire(&store),
            Err(StoreError::Locked { holder: None })
        ));
    }
}
