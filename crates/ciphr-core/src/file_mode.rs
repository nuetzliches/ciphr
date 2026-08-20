//! The rule, and one sentence, shared by the two places that refuse a world-accessible
//! credential.
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
    use super::{BIND_MOUNT_HINT, BIND_MOUNT_MODE, WorldAccess};

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
