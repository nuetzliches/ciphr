//! One sentence, shared by the two places that refuse a world-readable credential.
//!
//! Both `ciphr-crypto` (the master key file) and `ciphr-run` (the token file) stop the
//! process when a credential is readable by everyone, and both are right to. The message
//! they printed named a cause that is frequently not the one that occurred.
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
    use super::{BIND_MOUNT_HINT, BIND_MOUNT_MODE};

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
}
