//! What can go wrong before the child starts, and what the exit code says about it.
//!
//! # Why the exit codes are what they are
//!
//! This process is a container's entrypoint. When it fails, the thing reading the exit
//! code is a restart policy, and the question that policy cannot answer today is **"did
//! my service crash, or did it never start?"** A wrapper that exits `1` for its own
//! failures makes that unanswerable, because the service exits `1` too.
//!
//! So the codes follow the convention `docker run` and every shell already use, which
//! means an operator does not have to learn a third one:
//!
//! | Code | Meaning |
//! |---|---|
//! | `125` | **`ciphr-run` itself failed.** No child was started. |
//! | `126` | The command was found and could not be executed. |
//! | `127` | The command was not found. |
//! | anything else | The child's own exit code. `ciphr-run` is gone by then. |
//!
//! `125` is the one that matters: it means no secret reached anything, the service was
//! never started, and restarting will produce the same result until something outside
//! the container changes.

use core::fmt;

use ciphr_core::{BIND_MOUNT_HINT, BIND_MOUNT_MODE, WorldAccess};
use ciphr_sdk::SdkError;

/// `ciphr-run` failed before the child started.
///
/// Every variant means the same thing operationally — **the command was not executed** —
/// which is the whole point of collecting them into one type. Fail-closed is not a
/// property of one branch here; it is the only shape this type has.
// Two variants are constructed only on Unix -- the permission check and `exec` itself --
// and this program refuses to run anywhere else. The alternative to allowing them here
// would be a platform-dependent error type, whose `Display` and exit-code mapping would
// then differ by target: worse, and for a binary that only has one real target.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum RunError {
    /// The platform has no `exec`.
    NoExec,
    /// The token file could not be read.
    TokenFile {
        /// Which file.
        path: String,
        /// Why not. An `io::ErrorKind`, never the contents.
        reason: String,
    },
    /// The token file can be read, or replaced, by anyone on the host.
    TokenFileWorldAccessible {
        /// Which file.
        path: String,
        /// The permission bits found.
        mode: u32,
        /// Which of the two the mode grants, so the message names the bit that is set.
        access: WorldAccess,
    },
    /// The certificate authority could not be read.
    AuthorityFile {
        /// Which file.
        path: String,
        /// Why not.
        reason: String,
    },
    /// A path or prefix given on the command line is not a valid secret path.
    Path(ciphr_core::PathError),
    /// The service refused, could not be reached, or answered something unusable.
    Service(SdkError),
    /// A fetched secret is named after a variable that decides how a process starts.
    ProcessControlName {
        /// The variable name, which is a path segment and not a secret.
        name: String,
        /// Why that name is refused, in words.
        reason: &'static str,
    },
    /// The command to execute was given as an empty argument list.
    ///
    /// Reachable only through `--` with nothing after it.
    NoCommand,
    /// `exec` itself failed. The child does not exist, so this is still a `ciphr-run`
    /// failure — but the *reason* is about the command, which is why it carries its own
    /// exit code.
    Exec {
        /// The program that could not be executed.
        program: String,
        /// Why not.
        reason: String,
        /// Whether the program was absent, as opposed to present and unusable.
        not_found: bool,
    },
}

impl RunError {
    /// The process exit code for this failure.
    pub(crate) fn code(&self) -> u8 {
        match self {
            Self::Exec { not_found, .. } => {
                if *not_found {
                    127
                } else {
                    126
                }
            }
            // Everything else is this program failing, not the command failing.
            _ => 125,
        }
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExec => formatter.write_str(
                "this platform has no exec, so the command cannot replace this process. Running \
                 it as a child instead would leave a supervisor alive holding the plaintext, which \
                 is the opposite of what this program is for -- so it refuses rather than offering \
                 a weaker version of itself",
            ),
            Self::TokenFile { path, reason } => {
                write!(formatter, "cannot read the token file {path}: {reason}")
            }
            Self::TokenFileWorldAccessible { path, mode, access } => {
                write!(
                    formatter,
                    "the token file {path} is mode {mode:04o} and {}; restrict it to \
                     its owner (and group, if a service needs it)",
                    access.description()
                )?;
                if *mode == BIND_MOUNT_MODE {
                    formatter.write_str(BIND_MOUNT_HINT)?;
                }
                Ok(())
            }
            Self::AuthorityFile { path, reason } => write!(
                formatter,
                "cannot read the certificate authority {path}: {reason}"
            ),
            Self::Path(error) => write!(formatter, "{error}"),
            Self::Service(error) => write!(formatter, "{error}"),
            Self::ProcessControlName { name, reason } => write!(
                formatter,
                "refusing to hand {name} to the command: {reason}, so a secret named after \
                 it decides how that program starts rather than what it reads. Nothing was \
                 executed. If this deployment genuinely needs that variable, set it in the \
                 container definition, where it is a decision somebody reviewed -- and if \
                 this arrived under --prefix, note that whoever may write there chose this \
                 name"
            ),
            Self::NoCommand => {
                formatter.write_str("nothing to execute; put the command after `--`")
            }
            Self::Exec {
                program,
                reason,
                not_found,
            } => {
                if *not_found {
                    write!(
                        formatter,
                        "{program} was not found. The secrets were fetched and are gone with this \
                         process; nothing was started"
                    )
                } else {
                    write!(formatter, "cannot execute {program}: {reason}")
                }
            }
        }
    }
}

impl core::error::Error for RunError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ciphr_core::PathError> for RunError {
    fn from(error: ciphr_core::PathError) -> Self {
        Self::Path(error)
    }
}

impl From<SdkError> for RunError {
    fn from(error: SdkError) -> Self {
        Self::Service(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{RunError, WorldAccess};

    #[test]
    fn our_own_failures_are_all_125() {
        // The property a restart policy depends on: one code that means "no child was
        // started, and retrying changes nothing on its own".
        let failures = [
            RunError::NoExec,
            RunError::NoCommand,
            RunError::TokenFile {
                path: "/run/secrets/token".to_owned(),
                reason: "not found".to_owned(),
            },
            RunError::TokenFileWorldAccessible {
                path: "/run/secrets/token".to_owned(),
                mode: 0o644,
                access: WorldAccess::Read,
            },
            RunError::AuthorityFile {
                path: "/etc/ciphr/ca.crt".to_owned(),
                reason: "not found".to_owned(),
            },
            RunError::Service(ciphr_sdk::SdkError::Unauthenticated),
            RunError::ProcessControlName {
                name: "LD_PRELOAD".to_owned(),
                reason: "the dynamic loader reads it before the program starts",
            },
        ];

        for failure in failures {
            assert_eq!(failure.code(), 125, "{failure}");
        }
    }

    /// F4: the refusal has to say why this name is different from a password.
    ///
    /// Somebody meeting it is looking at a secret path that works everywhere else,
    /// so "refused" without "because a loader reads it before your program does"
    /// reads as a bug in the wrapper.
    #[test]
    fn refusing_a_process_control_name_says_why_and_says_nothing_ran() {
        let message = RunError::ProcessControlName {
            name: "NODE_OPTIONS".to_owned(),
            reason: "a language runtime or the shell reads it before the program starts",
        }
        .to_string();

        assert!(message.contains("NODE_OPTIONS"), "{message}");
        assert!(message.contains("before the program starts"), "{message}");
        assert!(message.contains("Nothing was executed"), "{message}");
        // And it names the way out that is not "turn the check off".
        assert!(message.contains("container definition"), "{message}");
    }

    #[test]
    fn a_missing_command_is_127_and_an_unusable_one_is_126() {
        // Borrowed from the shell so nobody has to learn a third convention.
        assert_eq!(
            RunError::Exec {
                program: "/original/entrypoint".to_owned(),
                reason: "not found".to_owned(),
                not_found: true,
            }
            .code(),
            127
        );
        assert_eq!(
            RunError::Exec {
                program: "/original/entrypoint".to_owned(),
                reason: "permission denied".to_owned(),
                not_found: false,
            }
            .code(),
            126
        );
    }

    #[test]
    fn the_refusal_on_a_platform_without_exec_says_why_rather_than_what() {
        // Someone hitting this needs to know it is a deliberate refusal, not a gap.
        let message = RunError::NoExec.to_string();
        assert!(message.contains("supervisor"), "{message}");
        assert!(message.contains("refuses"), "{message}");
    }

    #[test]
    fn a_failed_exec_says_the_secrets_are_gone() {
        // The operationally important half: the fetch happened, the audit trail has the
        // reads in it, and nothing is holding the values.
        let message = RunError::Exec {
            program: "/original/entrypoint".to_owned(),
            reason: "not found".to_owned(),
            not_found: true,
        }
        .to_string();
        assert!(message.contains("nothing was started"), "{message}");
    }

    #[test]
    fn a_refusal_at_0777_names_the_cause_that_platform_actually_has() {
        // Same hint as the master key check in `ciphr-crypto`, and for the same
        // reason: this wrapper runs in containers, which is exactly where a bind
        // mount from a host without Unix permissions reports 0777 for everything.
        let message = RunError::TokenFileWorldAccessible {
            path: "/run/secrets/token".to_owned(),
            mode: 0o777,
            access: WorldAccess::ReadWrite,
        }
        .to_string();
        assert!(message.contains("bind mount"), "{message}");
        assert!(message.contains("named volume"), "{message}");
    }

    #[test]
    fn a_refusal_at_any_other_mode_does_not_offer_the_excuse() {
        let message = RunError::TokenFileWorldAccessible {
            path: "/run/secrets/token".to_owned(),
            mode: 0o644,
            access: WorldAccess::Read,
        }
        .to_string();
        assert!(!message.contains("bind mount"), "{message}");
    }

    #[test]
    fn a_refusal_names_the_bit_that_is_set_and_not_the_other_one() {
        // The wrapper's half of finding F6. An operator told "world-readable" about a
        // 0602 file goes looking for a bit nobody set.
        let message = RunError::TokenFileWorldAccessible {
            path: "/run/secrets/token".to_owned(),
            mode: 0o602,
            access: WorldAccess::Write,
        }
        .to_string();
        assert!(message.contains("world-writable"), "{message}");
        assert!(!message.contains("world-readable"), "{message}");
    }
}
