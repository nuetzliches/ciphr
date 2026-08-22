//! The rule, one sentence, and the open, shared by the two places that read a credential
//! file.
//!
//! [`open_credential`] is the third thing they share and the last to arrive: both used to
//! inspect the path and then read it again, which is a window rather than a check. The
//! reasoning is on that function.
//!
//! Both `ciphr-crypto` (the master key file) and `ciphr-run` (the token file) stop the
//! process when a credential is readable or writable by everyone, and both are right to.
//! [`WorldAccess`] is that rule; each caller only turns its answer into its own error type.
//! The message they printed named a cause that is frequently not the one that occurred.
//!
//! A bind mount from a filesystem that has no Unix permissions — a Windows or macOS host
//! under a Linux container engine, or a share mounted over CIFS — reports **mode 0777 for
//! every file**, whatever the file is on the host. The check fires, correctly by its own
//! rule, and the message sends the reader looking for a permission they never set. That
//! cost about an hour the first time it happened, and it would have cost it again for
//! every new contributor on such a host.
//!
//! So the hint is attached to exactly one mode. Not "and by the way this might be a bind
//! mount" on every refusal, which would teach readers to ignore the sentence that matters:
//! 0777 exactly is the signature of a filesystem that reports no permissions, and a
//! deliberately world-writable *and* world-readable key file is not a thing anyone arrives
//! at by accident.
//!
//! The check itself does not change, and must not. The right answer on such a host is a
//! named volume, not a weaker rule — which is what the hint says.

/// What everyone outside a credential file's owner and group can do to it.
///
/// The rule lives here, and not in each of the two callers, for the reason F2 moved the
/// reserved prefix into one place: a rule written down twice is a rule enforced once.
/// Finding F6 of the 2026-08-21 review is that failure exactly — both checks tested
/// `0o004` and neither tested `0o002`, so a key file at mode `0602` started the process.
///
/// The execute bit is not consulted. A file nobody can read or write is not made
/// dangerous by being executable, and refusing `0o001` would be a rule without a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldAccess {
    /// Anyone can read the credential.
    Read,
    /// Anyone can replace the credential.
    ///
    /// Arguably the worse of the two: before `init` it plants a key the attacker knows,
    /// and afterwards it manufactures an unseal failure on the next restart.
    Write,
    /// Both.
    ReadWrite,
}

impl WorldAccess {
    /// What the world may do to a file at `mode`, or `None` if the answer is nothing.
    ///
    /// Group bits are deliberately not consulted: a root-owned file read by a service
    /// group is a legitimate and common arrangement, and refusing it would push
    /// deployments towards running as root instead. World bits are not that judgement
    /// call.
    #[must_use]
    pub const fn of(mode: u32) -> Option<Self> {
        match (mode & 0o004 != 0, mode & 0o002 != 0) {
            (true, true) => Some(Self::ReadWrite),
            (true, false) => Some(Self::Read),
            (false, true) => Some(Self::Write),
            (false, false) => None,
        }
    }

    /// Names what is wrong, to be read directly after "is mode 0602 and ".
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Read => "world-readable",
            Self::Write => "world-writable",
            Self::ReadWrite => "world-readable and world-writable",
        }
    }
}

/// A credential file, opened once, and what the world may do to *the file that was
/// opened*.
///
/// The distinction in that sentence is the whole reason this type exists — see
/// [`open_credential`].
pub struct Credential {
    /// The open file. **Read the credential from this handle and from nothing else**:
    /// re-opening the path would undo the property this is here for.
    pub file: std::fs::File,
    /// The permission bits the descriptor reports, on Unix. `None` where the platform
    /// has none, and no check runs there.
    pub mode: Option<u32>,
    /// What the world may do to it, or `None` if the answer is nothing.
    pub world: Option<WorldAccess>,
}

/// Why a credential file could not be opened for inspection.
///
/// Two cases, kept apart because they send a reader to different places: one is about
/// reaching the file, the other about what was found there.
#[derive(Debug)]
pub enum CredentialError {
    /// The file could not be opened, or its metadata not read from the descriptor.
    Io(std::io::Error),
    /// What was opened is not a regular file.
    NotARegularFile,
}

impl CredentialError {
    /// The short category a caller puts in its own error's `reason` field.
    ///
    /// A category rather than the operating system's sentence, matching what both
    /// callers already reported: the message is read by whoever mounted the file, and
    /// the kind is the part that tells them what to fix.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Io(error) => error.kind().to_string(),
            Self::NotARegularFile => "not a regular file".to_owned(),
        }
    }
}

impl core::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.reason())
    }
}

impl core::error::Error for CredentialError {}

/// Open a credential file **once**, and inspect the file that was actually opened.
///
/// **Check-then-open was the defect** (F10 of `docs/review-2026-08-21-current-tree.md`,
/// issue #13). Both callers — the master key file in `ciphr-crypto`, the token file in
/// `ciphr-run` — used to call `metadata(path)` and then `read_to_string(path)`: two
/// resolutions of one name, with a window between them. Whoever can create entries in the
/// directory a credential lives in could exchange the file in that window, so the file
/// whose permissions were approved and the file whose content was read need not be the
/// same file. The mode check is what makes that reachable rather than theoretical: it is
/// the reason a deployment leaves a credential in a directory a service account can write.
///
/// One descriptor closes it. The metadata comes from the open file, the content is read
/// from the same open file, and a replacement afterwards replaces the *name* — this handle
/// still refers to the inode that was inspected.
///
/// **A regular file is required, from the descriptor.** A FIFO where a token is expected
/// is not a permission problem, it is a read that never returns, and the mode bits on a
/// pipe say nothing about who is on the other end of it.
///
/// **`O_NOFOLLOW` is deliberately not used.** It needs `libc`, and `ciphr-run`'s
/// dependency list is itself the guarantee there (ADR-14) — that binary is bind-mounted
/// into images this project does not own. It would also add little: whoever can plant a
/// symlink in that directory can plant a regular file, so the substance is that the
/// metadata and the content come from one descriptor. What remains is a trust requirement
/// on the file's owner and its parent directory, which is documented for the reader who
/// writes the mount (`docs/operations/wrapper.md`, `docs/operations/master-key.md`).
///
/// # Errors
///
/// [`CredentialError::Io`] if the file cannot be opened or its metadata not read from the
/// descriptor, [`CredentialError::NotARegularFile`] if what was opened is something else.
/// A world-accessible file is **not** an error here: the caller owns that refusal, because
/// each one names its own credential in its own message.
pub fn open_credential(path: &std::path::Path) -> Result<Credential, CredentialError> {
    let file = std::fs::File::open(path).map_err(CredentialError::Io)?;
    let metadata = file.metadata().map_err(CredentialError::Io)?;

    if !metadata.is_file() {
        return Err(CredentialError::NotARegularFile);
    }

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;

        Some(metadata.permissions().mode() & 0o777)
    };
    // No portable equivalent of the mode bits. Reported as "there is no answer here"
    // rather than as a mode nobody set, so a caller cannot mistake one for the other.
    #[cfg(not(unix))]
    let mode = None;

    Ok(Credential {
        file,
        mode,
        world: mode.and_then(WorldAccess::of),
    })
}

/// The mode a bind mount from a filesystem without Unix permissions reports.
pub const BIND_MOUNT_MODE: u32 = 0o777;

/// Appended to a refusal when the mode is exactly [`BIND_MOUNT_MODE`].
///
/// Begins mid-sentence: it is concatenated onto a message that has already named the file
/// and what is wrong with it.
pub const BIND_MOUNT_HINT: &str = ". Mode 0777 exactly is also what a bind mount from a \
     filesystem without Unix permissions reports — a Windows or macOS host, or a CIFS share \
     — whatever the file is on that host. If that is what happened, move the file into a \
     named volume rather than relaxing this check";

#[cfg(test)]
mod tests {
    use super::{BIND_MOUNT_HINT, BIND_MOUNT_MODE, CredentialError, WorldAccess, open_credential};

    /// The content comes from the handle that was inspected, not from the name again.
    #[test]
    fn a_credential_is_read_through_the_descriptor_that_was_checked() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("token");
        std::fs::write(&path, "ciphr_token_value").expect("write the credential");

        let mut credential = open_credential(&path).expect("a regular file");
        assert!(
            credential.world.is_none(),
            "a file written by this process is not world-accessible"
        );

        let mut read = String::new();
        std::io::Read::read_to_string(&mut credential.file, &mut read).expect("read");
        assert_eq!(read, "ciphr_token_value");
    }

    /// A directory where a credential belongs is refused for what it is.
    ///
    /// The mode bits of something that is not a regular file say nothing about who can
    /// supply its content — and a FIFO, the case that actually matters, is a read that
    /// never returns rather than a permission to check.
    #[test]
    fn something_that_is_not_a_regular_file_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");

        // Matched rather than `expect_err`: [`Credential`] has no `Debug` and must not
        // grow one to satisfy a test — it carries a handle to a credential (ADR-1).
        let Err(refused) = open_credential(directory.path()) else {
            panic!("a directory is not a credential")
        };
        // Which of the two refusals it is depends on the platform, and both are refusals:
        // a Unix `open` on a directory succeeds and the descriptor says what it is, while
        // Windows refuses the open itself. The claim is that neither accepts it.
        match refused {
            CredentialError::NotARegularFile => {
                assert_eq!(refused.reason(), "not a regular file");
            }
            CredentialError::Io(_) => assert!(!refused.reason().is_empty()),
        }
    }

    /// A path with nothing at it is reported as unreachable, by category.
    #[test]
    fn an_absent_credential_reports_the_kind_and_not_a_sentence_about_content() {
        let directory = tempfile::tempdir().expect("temp dir");

        let Err(refused) = open_credential(&directory.path().join("never-written")) else {
            panic!("nothing is there to open")
        };
        assert!(matches!(refused, CredentialError::Io(_)));
        assert!(
            !refused.reason().is_empty(),
            "the caller puts this in its own message"
        );
    }

    #[test]
    fn the_hint_continues_a_sentence_rather_than_starting_one() {
        // It is concatenated onto a message that ends without punctuation, so a
        // leading separator is the whole reason it reads as one message and not two
        // run together.
        assert!(BIND_MOUNT_HINT.starts_with(". "));
    }

    #[test]
    fn the_hint_points_away_from_relaxing_the_check() {
        // The failure this guards against is a reader who takes "0777 is expected on
        // this platform" as permission to loosen the rule. The sentence has to carry
        // the alternative, not merely the explanation.
        assert!(BIND_MOUNT_HINT.contains("named volume"));
    }

    #[test]
    fn the_mode_is_the_one_that_carries_no_information() {
        assert_eq!(BIND_MOUNT_MODE, 0o777);
    }

    #[test]
    fn a_mode_only_the_owner_and_group_can_touch_is_allowed() {
        // The arrangement the check exists to permit: 0640, root-owned, read by a
        // service group.
        assert_eq!(WorldAccess::of(0o600), None);
        assert_eq!(WorldAccess::of(0o640), None);
        assert_eq!(WorldAccess::of(0o660), None);
    }

    #[test]
    fn world_writable_is_refused_even_when_nobody_can_read_it() {
        // The finding, pinned: 0602 used to start the process, because the check asked
        // only whether the world could read.
        assert_eq!(WorldAccess::of(0o602), Some(WorldAccess::Write));
        assert_eq!(WorldAccess::of(0o622), Some(WorldAccess::Write));
    }

    #[test]
    fn each_answer_names_only_what_is_actually_wrong() {
        // The reason this is an enum and not a boolean: a refusal at 0602 that says
        // "world-readable" sends the reader to look at a bit nobody set, which is the
        // same mistake the bind-mount hint above exists to undo.
        assert_eq!(
            WorldAccess::of(0o604).unwrap().description(),
            "world-readable"
        );
        assert_eq!(
            WorldAccess::of(0o602).unwrap().description(),
            "world-writable"
        );
        assert_eq!(
            WorldAccess::of(0o606).unwrap().description(),
            "world-readable and world-writable"
        );
    }

    #[test]
    fn the_bind_mount_mode_is_both() {
        // The hint is attached to this mode alone, and the reason it can be is that
        // 0777 is not a mode anyone sets on a credential on purpose.
        assert_eq!(
            WorldAccess::of(BIND_MOUNT_MODE),
            Some(WorldAccess::ReadWrite)
        );
    }

    #[test]
    fn the_execute_bit_alone_is_not_the_check_s_business() {
        assert_eq!(WorldAccess::of(0o601), None);
    }
}
