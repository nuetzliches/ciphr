//! What can go wrong, in the shape a caller has to act on.
//!
//! The variants are cut along the lines of *what a consumer does about it*, not along
//! the lines of the HTTP status codes they come from. A service fetching its secrets at
//! startup has three sensible reactions and no more: retry later, fail and stay down, or
//! report a misconfiguration to the person who deployed it. Anything finer would be a
//! distinction nobody can act on.
//!
//! **No variant carries a secret value.** Paths, identities, versions and error classes
//! are all safe — a path is not a secret, and the API document says so publicly. Values
//! are absent by construction, because none of these variants has a field that could
//! hold one.

use core::fmt;

use ciphr_core::{EnvNameError, PathError};

/// A request that did not produce what was asked for.
#[derive(Debug)]
#[non_exhaustive]
pub enum SdkError {
    /// The service could not be reached, or the connection failed: DNS, refused
    /// connection, timeout, or a TLS handshake that did not verify.
    ///
    /// **This is the retryable one.** It says nothing about whether the caller is
    /// allowed to do what it asked.
    Transport {
        /// What was attempted, in words. Never a URL with a query string, because
        /// nothing here builds one containing a value.
        detail: String,
    },
    /// The token was missing, malformed, expired, or unknown — `401`.
    ///
    /// The service deliberately does not distinguish between those, so neither does
    /// this. Retrying will not help; a new token might.
    Unauthenticated,
    /// The identity is known and the policy refused the access — `403`.
    ///
    /// The rule that refused is deliberately not in the response. It is in the audit
    /// trail, where the operator can see it and the caller cannot.
    Forbidden {
        /// The path that was refused. Safe to log, and the only thing that makes this
        /// error actionable.
        path: String,
    },
    /// No such secret, or no such version — `404`.
    NotFound {
        /// The path that was not found.
        path: String,
    },
    /// The request was refused as malformed — `400`.
    ///
    /// Reachable from an SDK by asking for a reserved path (`sys/**`) or a version that
    /// does not exist. The detail describes the request, not the server.
    BadRequest {
        /// The reason the service gave.
        detail: String,
    },
    /// The audit trail could not be written, so nothing was served and nothing was
    /// changed — `503`.
    ///
    /// A separate variant because it is the one server-side failure with a documented
    /// guarantee attached: **no secret was served and no change was made.** A caller may
    /// retry it without wondering whether its write half-happened. It also means the
    /// deployment has a problem a consumer cannot fix — usually a full volume.
    AuditUnavailable,
    /// The service answered with something this client could not use: an unexpected
    /// status, or a body that is not the documented shape.
    ///
    /// Almost always a version mismatch — a client built against a newer or older
    /// `openapi.yaml` than the service implements.
    Unexpected {
        /// The status, if there was one.
        status: Option<u16>,
        /// What could not be read. Never the body itself: a `200` body contains a
        /// secret, so a parse failure must not quote what it failed to parse.
        detail: String,
    },
    /// A route this deployment did not turn on — `404` from an optional route (ADR-20).
    ///
    /// Its own variant because the status is the same one a missing secret produces and
    /// the two need opposite reactions: a missing secret is a question about the store,
    /// an absent route is a question about the deployment's configuration, and only one
    /// of them is fixed by editing a file on the server.
    ///
    /// **A `404` is only read this way where the route has nothing else to be missing.**
    /// `POST /v1/export` takes its paths in the body, so there is no path in its URL that
    /// could be absent; the same status on `GET /v1/secrets/{path}` stays
    /// [`SdkError::NotFound`], because there it genuinely means the secret.
    ///
    /// The entry name comes from `openapi.yaml`, which carries `x-surface-entry` on every
    /// optional route. It is not a copy of the entry *list* — that lives in the server and
    /// the CLI, with `ci/check-surface-entries.sh` keeping the two in step — but the one
    /// entry this client's own request belongs to.
    SurfaceEntryUnavailable {
        /// The route that answered, as it is written in the API document.
        route: String,
        /// The surface entry it belongs to, as a deployment would name it.
        entry: String,
    },
    /// A path this client was given is not a valid secret path.
    ///
    /// Refused here rather than sent, so that an invalid path never becomes a request
    /// and never reaches the audit trail as an access attempt.
    Path(PathError),
    /// A prefix that was asked for as a whole environment turned out to contain nothing.
    ///
    /// Its own variant because it has **two causes that look identical on the wire** and
    /// only one of them is benign: there is genuinely nothing under the prefix, or this
    /// identity holds no `list` capability there. `GET /v1/list` authorizes every path it
    /// would return individually, so "you may list nothing here" arrives as an empty
    /// array — indistinguishable from an empty prefix, by design.
    ///
    /// A consumer that asked for its own prefix is misconfigured in either case, and a
    /// service that boots with an empty environment because its token lacks a capability
    /// is precisely the silent start this refusal exists to prevent.
    NothingUnderPrefix {
        /// The prefix that produced nothing.
        prefix: String,
    },
    /// A set of secrets has no usable environment variable names (ADR-18).
    ///
    /// Two paths under the prefix want the same name, or one of them is not a name a
    /// shell can read. This is a property of the secret layout, not of the network, and
    /// no retry changes it.
    EnvName(EnvNameError),
    /// The client could not be built: the base URL is not usable, or the certificate
    /// authority could not be read.
    Configuration {
        /// What is wrong with it.
        detail: String,
    },
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { detail } => {
                write!(formatter, "could not reach the service: {detail}")
            }
            Self::Unauthenticated => formatter.write_str(
                "the token was not accepted; the service does not say which part of it was wrong",
            ),
            Self::Forbidden { path } => {
                write!(
                    formatter,
                    "this identity may not do that to {path}; the rule that refused is in the \
                     audit trail, not in the response"
                )
            }
            Self::NotFound { path } => write!(formatter, "{path} does not exist"),
            Self::BadRequest { detail } => write!(formatter, "the request was refused: {detail}"),
            Self::AuditUnavailable => formatter.write_str(
                "the service could not write its audit trail, so it served nothing and changed \
                 nothing; this is a deployment problem, not a client one",
            ),
            Self::Unexpected { status, detail } => match status {
                Some(code) => write!(formatter, "unexpected {code} response: {detail}"),
                None => write!(formatter, "unexpected response: {detail}"),
            },
            Self::NothingUnderPrefix { prefix } => write!(
                formatter,
                "nothing is visible under {prefix}: either there is nothing there, or this \
                 identity has no 'list' capability on it — the service cannot tell those apart \
                 and neither can this client"
            ),
            Self::SurfaceEntryUnavailable { route, entry } => write!(
                formatter,
                "{route} is not available on this deployment: it belongs to the '{entry}' \
                 surface entry, which is off unless a configuration names it. GET /v1/health \
                 lists the entries this instance has"
            ),
            Self::Path(error) => write!(formatter, "{error}"),
            Self::EnvName(error) => write!(formatter, "{error}"),
            Self::Configuration { detail } => {
                write!(formatter, "this client cannot be built: {detail}")
            }
        }
    }
}

impl core::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::EnvName(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PathError> for SdkError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

impl From<EnvNameError> for SdkError {
    fn from(error: EnvNameError) -> Self {
        Self::EnvName(error)
    }
}

impl SdkError {
    /// Whether retrying the same request could plausibly succeed without anything else
    /// changing.
    ///
    /// Deliberately narrow. A `401` is not retryable even though a *new token* would
    /// fix it, because retrying with the same credential is what a retry does. A `503`
    /// from the audit trail is retryable and carries the guarantee that nothing
    /// half-happened, which is what makes retrying it safe for a write as well as for a
    /// read.
    ///
    /// ```
    /// use ciphr_sdk::SdkError;
    ///
    /// assert!(SdkError::AuditUnavailable.is_retryable());
    /// assert!(!SdkError::Unauthenticated.is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::AuditUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::SdkError;

    #[test]
    fn only_the_two_states_that_can_change_by_themselves_are_retryable() {
        assert!(
            SdkError::Transport {
                detail: "connection refused".to_owned()
            }
            .is_retryable()
        );
        assert!(SdkError::AuditUnavailable.is_retryable());

        // A retry sends the same credential and asks for the same path, so neither of
        // these can turn into a success on its own.
        assert!(!SdkError::Unauthenticated.is_retryable());
        assert!(
            !SdkError::Forbidden {
                path: "infra/a/DB_PASSWORD".to_owned()
            }
            .is_retryable()
        );
        assert!(
            !SdkError::NotFound {
                path: "infra/a/DB_PASSWORD".to_owned()
            }
            .is_retryable()
        );
    }

    #[test]
    fn an_absent_optional_route_is_not_retryable_and_says_what_to_edit() {
        // A route that is off stays off until somebody changes a file on the server, so
        // retrying is not the reaction -- and the message has to name the thing that gets
        // changed, because the status code alone is indistinguishable from a path that
        // never existed.
        let error = SdkError::SurfaceEntryUnavailable {
            route: "POST /v1/export".to_owned(),
            entry: "bulk_export".to_owned(),
        };
        assert!(!error.is_retryable());

        let message = error.to_string();
        assert!(message.contains("bulk_export"), "{message}");
        assert!(message.contains("surface entry"), "{message}");
        // Where to look without guessing: the health route lists what this instance has.
        assert!(message.contains("/v1/health"), "{message}");
    }

    #[test]
    fn the_audit_failure_says_whose_problem_it_is() {
        // A consumer that reads this message should not go looking at its own token.
        let message = SdkError::AuditUnavailable.to_string();
        assert!(
            message.contains("served nothing and changed nothing"),
            "{message}"
        );
        assert!(message.contains("deployment problem"), "{message}");
    }

    #[test]
    fn a_forbidden_error_names_the_path_and_not_the_rule() {
        let message = SdkError::Forbidden {
            path: "infra/a/DB_PASSWORD".to_owned(),
        }
        .to_string();
        assert!(message.contains("infra/a/DB_PASSWORD"), "{message}");
        // The rule lives in the audit trail; saying it here would tell a caller what to
        // probe for next.
        assert!(message.contains("audit trail"), "{message}");
    }
}
