//! CLI errors.
//!
//! These are read by a person at a terminal, so each one says what to do rather than
//! only what went wrong. They still never contain a secret value or key material: an
//! error message is as likely to be pasted into a ticket as anything else on the
//! screen.

use core::fmt;

/// Something went wrong running a command.
#[derive(Debug)]
pub(crate) enum CliError {
    /// The database has no root key yet.
    NotInitialized {
        /// Which file.
        path: String,
    },
    /// The database already has one.
    AlreadyInitialized {
        /// Which file.
        path: String,
    },
    /// The identity named is not in the policy file.
    UnknownIdentity {
        /// The name that was given.
        name: String,
    },
    /// A value was expected on standard input and standard input is a terminal.
    NeedsStdin,
    /// A secret would be written somewhere other than a terminal without `--force`.
    WouldPipeSecret,
    /// A duration such as `90d` could not be parsed.
    Duration {
        /// What was written.
        found: String,
    },
    /// A `.env` line could not be read.
    DotEnv {
        /// Which line.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
    /// The audit trail could not be written, so the command was abandoned.
    Audit(String),
    /// The audit chain does not verify.
    ChainBroken(ciphr_audit::ChainBreak),
    /// The store said no.
    Store(ciphr_store::StoreError),
    /// The store is locked — normally by the running service — and for this command
    /// the service itself answers while it runs.
    ///
    /// The hint announces the alternative and never takes it. Routing to the API
    /// when a lock file exists would make the same command mean two identities:
    /// the operator with the master key here, an authenticated token there. If the
    /// operator wants the API path, they choose it, and the trail names who acted.
    LockedButServed {
        /// The store's own refusal, shown first and unchanged.
        locked: ciphr_store::StoreError,
        /// The equivalent request against the running service.
        request: String,
    },
    /// A cryptographic operation failed.
    Crypto(ciphr_crypto::CryptoError),
    /// A policy file could not be loaded.
    Policy(ciphr_policy::PolicyError),
    /// A path or pattern is invalid.
    Path(ciphr_core::PathError),
    /// A rotation class is not one of the five.
    Rotation(ciphr_core::RotationError),
    /// An export cannot name a variable for one of its secrets, or two of them want
    /// the same name.
    EnvName(ciphr_core::EnvNameError),
    /// A configuration file could not be read as one.
    ///
    /// Distinct from [`Self::Io`], which covers a file that could not be *reached*, and
    /// from [`Self::Audit`], which is about the trail rather than about an input. Reusing
    /// `Audit` here — which an earlier draft of `surface show` did — produces "the audit
    /// trail could not be written" in front of a TOML parse error, and an operator who
    /// reads that goes looking at the wrong subsystem.
    Config {
        /// Which file.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// A path was to be marked as bait and holds nothing.
    BaitNeedsASecret {
        /// The path that was given.
        path: String,
    },
    /// Something failed while reading or writing a file.
    Io(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized { path } => {
                write!(f, "{path} has no root key yet; run `ciphr init` first")
            }
            Self::AlreadyInitialized { path } => write!(
                f,
                "{path} is already initialized; initializing again would orphan every secret in it"
            ),
            Self::UnknownIdentity { name } => write!(
                f,
                "'{name}' is not an identity in the policy file; identities are defined there, \
                 not created by this command"
            ),
            Self::NeedsStdin => f.write_str(
                "the value must come from standard input, not from an argument — an argument ends \
                 up in shell history and in /proc, where other processes can read it.\n\
                 \n    printf %s \"$VALUE\" | ciphr put <path>\n    ciphr put <path> < value.txt",
            ),
            Self::WouldPipeSecret => f.write_str(
                "refusing to write a secret to something that is not a terminal; pass --force if \
                 that is what you meant",
            ),
            Self::Duration { found } => write!(
                f,
                "'{found}' is not a duration; use a number with a unit, such as 30d, 12h or 90m"
            ),
            Self::DotEnv { line, reason } => write!(f, "line {line}: {reason}"),
            Self::Audit(detail) => write!(
                f,
                "the audit trail could not be written, so the command was abandoned: {detail}"
            ),
            Self::ChainBroken(reason) => write!(f, "{reason}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::LockedButServed { locked, request } => write!(
                f,
                "{locked}\n\
                 \n\
                 If the holder is the running ciphr-server, no outage is needed for this \
                 one: it serves the same operation as `{request}` (see openapi.yaml), \
                 authenticated with a token whose policy allows it. The CLI does not make \
                 that call for you — there the trail names an authenticated identity, here \
                 it names the operator, and which of the two acted must not depend on a \
                 lock file."
            ),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Policy(error) => write!(f, "{error}"),
            Self::Path(error) => write!(f, "{error}"),
            Self::Rotation(error) => write!(f, "{error}"),
            Self::EnvName(error) => write!(f, "{error}"),
            Self::Config { path, reason } => {
                write!(f, "{path} is not a usable configuration: {reason}")
            }
            Self::BaitNeedsASecret { path } => write!(
                f,
                "{path} holds nothing. Bait is a real secret with a real-looking value \
                 in it -- write one there first, then mark it. A tier on an empty path \
                 is a honeypot that answers 404 to whoever takes it."
            ),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for CliError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for CliError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}

from_error!(ciphr_store::StoreError, Store);
from_error!(ciphr_crypto::CryptoError, Crypto);
from_error!(ciphr_policy::PolicyError, Policy);
from_error!(ciphr_core::PathError, Path);
from_error!(ciphr_core::RotationError, Rotation);
from_error!(ciphr_core::EnvNameError, EnvName);
from_error!(ciphr_audit::ChainBreak, ChainBroken);
from_error!(std::io::Error, Io);

/// Parse a duration such as `90d`, `12h`, `30m`, or `3600s`.
///
/// # Errors
///
/// Returns [`CliError::Duration`] for anything else. A bare number is rejected rather
/// than assumed to be seconds: a token issued for "90" when the operator meant days is
/// a token that expires before the deploy finishes.
pub(crate) fn parse_duration_millis(input: &str) -> Result<i64, CliError> {
    let text = input.trim();
    let (digits, unit_millis) = match text.chars().last() {
        Some('d') => (&text[..text.len() - 1], 24 * 60 * 60 * 1000),
        Some('h') => (&text[..text.len() - 1], 60 * 60 * 1000),
        Some('m') => (&text[..text.len() - 1], 60 * 1000),
        Some('s') => (&text[..text.len() - 1], 1000),
        _ => {
            return Err(CliError::Duration {
                found: input.to_owned(),
            });
        }
    };

    digits
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .and_then(|value| value.checked_mul(unit_millis))
        .ok_or_else(|| CliError::Duration {
            found: input.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::{CliError, parse_duration_millis};

    #[test]
    fn parses_the_units_the_help_text_mentions() {
        assert_eq!(parse_duration_millis("1s").unwrap(), 1_000);
        assert_eq!(parse_duration_millis("30m").unwrap(), 1_800_000);
        assert_eq!(parse_duration_millis("12h").unwrap(), 43_200_000);
        assert_eq!(parse_duration_millis("90d").unwrap(), 7_776_000_000);
        assert_eq!(parse_duration_millis(" 7d ").unwrap(), 604_800_000);
    }

    #[test]
    fn a_bare_number_is_refused_rather_than_guessed() {
        // "90" meaning seconds when days were intended is a token that expires
        // mid-deploy.
        assert!(matches!(
            parse_duration_millis("90"),
            Err(CliError::Duration { .. })
        ));
        for bad in ["", "0d", "-1d", "d", "1w", "1.5d", "999999999999999d"] {
            assert!(parse_duration_millis(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_served_hint_keeps_the_refusal_and_adds_the_route() {
        // The store's own message must survive unchanged -- it is the one that says
        // why two writers cannot coexist -- and the hint must name the live request
        // without pretending the CLI will make it.
        let message = CliError::LockedButServed {
            locked: ciphr_store::StoreError::Locked { holder: Some(4711) },
            request: "GET /v1/secrets/infra/service-a/DB_PASSWORD".to_owned(),
        }
        .to_string();
        assert!(message.contains("in use by process 4711"));
        assert!(message.contains("GET /v1/secrets/infra/service-a/DB_PASSWORD"));
        assert!(message.contains("does not make that call"));
    }

    #[test]
    fn the_stdin_message_shows_how_to_do_it_right() {
        // The error a first-time user is most likely to hit, so it has to teach.
        let message = CliError::NeedsStdin.to_string();
        assert!(message.contains("printf"));
        assert!(message.contains("shell history"));
    }
}
