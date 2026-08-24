//! What can go wrong before a value reaches the runner, and what it looks like.
//!
//! # Why every failure here is exit code `1`
//!
//! `ciphr-run` needs three codes because it is an entrypoint and the thing reading its
//! exit code is a restart policy that has to tell "my service crashed" from "it never
//! started" ([ADR-14](../../../docs/adr/0014-ciphr-run-injects-into-a-child-process.md)).
//! Nothing here has that question. The reader of this program's exit code is a workflow
//! step, and a step that fails fails the job — there is no second interpretation to
//! encode, and inventing one would be a convention every consumer would have to learn
//! for no decision it could make.
//!
//! What the codes do carry is the guarantee attached to the failure: **a non-zero exit
//! from this program means no assignment was written**. Rendering happens whole, before
//! anything is emitted, so a refused fetch or an unusable name leaves the job's
//! environment exactly as it was.

use core::fmt;

use ciphr_core::{BIND_MOUNT_HINT, BIND_MOUNT_MODE, WorldAccess};
use ciphr_export::{ExportError, UnknownFormat};
use ciphr_sdk::SdkError;

/// `ciphr-ci` did not deliver the secrets it was asked for.
#[derive(Debug)]
pub(crate) enum CiError {
    /// The `--format` is not one of the three.
    Format(UnknownFormat),
    /// The token file could not be read.
    TokenFile {
        /// Which file.
        path: String,
        /// Why not. An `io::ErrorKind`, never the contents.
        reason: String,
    },
    /// The token file can be read, or replaced, by anyone on the runner.
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
    /// A value is not UTF-8 and therefore cannot be rendered as text.
    ///
    /// The API says values are UTF-8 (`openapi.yaml`), so this is a service that broke
    /// its own contract rather than a secret somebody stored badly — but it is worth its
    /// own message, because "not valid UTF-8" from a JSON parser names nothing an
    /// operator can act on and this one names the path.
    NotText {
        /// Which secret. A path, never the bytes.
        path: String,
    },
    /// The set could not be rendered: no usable variable names, or no usable delimiter.
    Render(ExportError),
    /// A fetched secret is named after a variable that decides how a process starts.
    ProcessControlName {
        /// The variable name. A path segment, not a secret.
        name: String,
        /// Why it is refused, in words.
        reason: &'static str,
    },
    /// A prefix produced nothing, which is two causes with one shape on the wire.
    NothingUnderPrefix {
        /// The prefix that produced nothing.
        prefix: String,
    },
    /// `--github-env` was given for a format that has no environment file to write.
    ///
    /// Refused rather than ignored: a flag that quietly does nothing is a workflow whose
    /// author believes the values reached the next step.
    GithubEnvWithoutActions,
    /// `--github-env` was given outside a runner that sets `GITHUB_ENV`.
    GithubEnvUnset,
    /// This program's own output could not be written.
    ///
    /// Worth a variant rather than a panic: a closed pipe on the mask half means the
    /// runner did not receive the masks, and continuing to the assignments would put
    /// values into a file whose values nothing is redacting.
    Output {
        /// Why not. An `io::ErrorKind`, never what was being written.
        reason: String,
    },
    /// The environment file could not be appended to.
    EnvironmentFile {
        /// Which file.
        path: String,
        /// Why not.
        reason: String,
    },
    /// Values would go to a pipe that nobody asked to have them.
    ///
    /// The same rule as `ciphr get` and `ciphr export` on a host: a secret is not
    /// written where a shell can capture it into a variable, a log, or a transcript
    /// unless the invocation says so.
    WouldPipeSecret,
}

impl CiError {
    /// The process exit code. One, for every failure this program has.
    ///
    /// A function rather than a literal at the call site, because the property worth
    /// pinning is that there is exactly one — see the test at the bottom of this file.
    pub(crate) fn code() -> u8 {
        1
    }
}

impl fmt::Display for CiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => write!(formatter, "{error}"),
            Self::TokenFile { path, reason } => {
                write!(formatter, "cannot read the token file {path}: {reason}")
            }
            Self::TokenFileWorldAccessible { path, mode, access } => {
                write!(
                    formatter,
                    "the token file {path} is mode {mode:04o} and {}; restrict it to \
                     its owner (and group, if the job needs it)",
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
            Self::NotText { path } => write!(
                formatter,
                "{path} is not valid UTF-8 and cannot be written into an environment; \
                 the API serves text, so a binary secret has to be encoded by whoever \
                 stored it"
            ),
            Self::Render(error) => write!(formatter, "{error}"),
            Self::ProcessControlName { name, reason } => write!(
                formatter,
                "refusing to deliver {name}: {reason}, so a secret named after it would                  decide how the steps after this one run rather than what they read.                  Nothing was fetched and nothing was written. If this job genuinely needs                  that variable, set it in the workflow, where it is a line somebody                  reviewed"
            ),
            Self::NothingUnderPrefix { prefix } => write!(
                formatter,
                "nothing is visible under {prefix}: either there is nothing there, or this \
                 token has no 'list' capability on it — the service cannot tell those apart \
                 and neither can this program. Naming the paths with --path needs only \
                 'read'"
            ),
            Self::GithubEnvWithoutActions => formatter.write_str(
                "--github-env belongs to --format actions-env, which is the format that has \
                 an environment file to append to; the other two write to standard output",
            ),
            Self::GithubEnvUnset => formatter.write_str(
                "--github-env was given but GITHUB_ENV is not set; that variable is set by \
                 the runner, so this is either not a job step or not a runner that supports \
                 environment files",
            ),
            Self::Output { reason } => write!(
                formatter,
                "cannot write to standard output: {reason}. Nothing further was written, \
                 because a runner that did not receive the mask commands would log the \
                 values unredacted"
            ),
            Self::EnvironmentFile { path, reason } => write!(
                formatter,
                "cannot append to the environment file {path}: {reason}. The masks were \
                 emitted and no assignment was written"
            ),
            Self::WouldPipeSecret => formatter.write_str(
                "this would write secret values to a pipe. Pass --force if that is what the \
                 step wants -- or use --format actions-env, which puts the values in the \
                 runner's environment file and only mask commands on standard output",
            ),
        }
    }
}

impl core::error::Error for CiError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::Service(error) => Some(error),
            Self::Render(error) => Some(error),
            Self::Format(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ciphr_core::PathError> for CiError {
    fn from(error: ciphr_core::PathError) -> Self {
        Self::Path(error)
    }
}

impl From<SdkError> for CiError {
    fn from(error: SdkError) -> Self {
        Self::Service(error)
    }
}

impl From<ExportError> for CiError {
    fn from(error: ExportError) -> Self {
        Self::Render(error)
    }
}

impl From<UnknownFormat> for CiError {
    fn from(error: UnknownFormat) -> Self {
        Self::Format(error)
    }
}

/// A naming failure found before the fetch is the same failure as one found during the
/// render, and says the same sentence: the rule is one rule (ADR-18).
impl From<ciphr_core::EnvNameError> for CiError {
    fn from(error: ciphr_core::EnvNameError) -> Self {
        Self::Render(ExportError::EnvName(error))
    }
}

#[cfg(test)]
mod tests {
    use super::{CiError, WorldAccess};

    #[test]
    fn a_refused_fetch_says_nothing_was_written() {
        // The property a workflow author depends on: a failure here leaves the job's
        // environment as it was, so a step that continues on error does not continue
        // with half a configuration.
        let message = CiError::EnvironmentFile {
            path: "/runner/env".to_owned(),
            reason: "permission denied".to_owned(),
        }
        .to_string();
        assert!(message.contains("no assignment was written"), "{message}");
    }

    #[test]
    fn the_pipe_refusal_names_the_format_that_does_not_need_force() {
        // Somebody hitting this on a runner is one flag away from the right answer, and
        // the right answer is usually `actions-env` rather than `--force`.
        let message = CiError::WouldPipeSecret.to_string();
        assert!(message.contains("actions-env"), "{message}");
        assert!(message.contains("--force"), "{message}");
    }

    #[test]
    fn a_world_readable_token_file_is_refused_by_the_shared_rule() {
        // The same rule as the master key and the wrapper's token file, and the message
        // names the bit that is actually set rather than both.
        let message = CiError::TokenFileWorldAccessible {
            path: "/runner/token".to_owned(),
            mode: 0o604,
            access: WorldAccess::Read,
        }
        .to_string();
        assert!(message.contains("world-readable"), "{message}");
        assert!(!message.contains("world-writable"), "{message}");
    }

    #[test]
    fn a_bind_mounted_token_file_gets_the_hint_and_nothing_else_does() {
        let mounted = CiError::TokenFileWorldAccessible {
            path: "/runner/token".to_owned(),
            mode: 0o777,
            access: WorldAccess::ReadWrite,
        }
        .to_string();
        assert!(mounted.contains("bind mount"), "{mounted}");

        let ordinary = CiError::TokenFileWorldAccessible {
            path: "/runner/token".to_owned(),
            mode: 0o644,
            access: WorldAccess::Read,
        }
        .to_string();
        assert!(!ordinary.contains("bind mount"), "{ordinary}");
    }

    #[test]
    fn there_is_exactly_one_exit_code_for_a_failure() {
        // Stated as a test because the alternative -- three codes, as `ciphr-run` has --
        // is a convention consumers would have to learn, and this program has no
        // question that would justify it.
        assert_eq!(CiError::code(), 1);
    }
}
