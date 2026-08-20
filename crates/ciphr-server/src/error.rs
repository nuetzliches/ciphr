//! Errors, and what a client is told about them.
//!
//! Two audiences, two levels of detail. The operator gets the reason in the process
//! log; the client gets a status code and a short, stable string. That split is
//! deliberate: a client that learns *why* it was refused learns something about the
//! policy file, and a client that learns why a token was rejected learns whether the
//! identifier exists.
//!
//! In particular:
//!
//! - Authentication failure is always `401` with the same body, whatever was wrong.
//! - Authorization failure is `403` with no mention of the rule that refused. The
//!   rule is in the audit trail, where the operator can see it and the caller cannot.
//! - A failed audit write is `503`, and no secret is served. This is the fail-closed
//!   promise, and it is why the audit write happens before the response is produced.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Something went wrong handling a request.
#[derive(Debug)]
pub enum ApiError {
    /// No credential, or one that is not valid.
    Unauthenticated,
    /// A valid identity that may not do this.
    Forbidden,
    /// The path or version does not exist.
    NotFound,
    /// The request is malformed: an unparseable path, a reserved prefix, a bad body.
    BadRequest {
        /// A short, stable reason. Safe to show a client: it describes the request,
        /// not the configuration.
        reason: String,
    },
    /// The audit trail could not be written, so the request is refused.
    AuditUnavailable,
    /// Something failed that the client cannot do anything about.
    Internal {
        /// What to write to the process log. Never sent to the client.
        detail: String,
    },
}

/// The body of an error response.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: &'static str,
    /// Present only where it describes the request rather than the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ApiError {
    /// The status code a client sees.
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::AuditUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::BadRequest { .. } => "bad_request",
            Self::AuditUnavailable => "audit_unavailable",
            Self::Internal { .. } => "internal",
        }
    }

    const fn message(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "a valid bearer token is required",
            Self::Forbidden => "this identity may not perform this action",
            Self::NotFound => "no such secret or version",
            Self::BadRequest { .. } => "the request could not be understood",
            Self::AuditUnavailable => "the audit trail is unavailable, so the request was refused",
            Self::Internal { .. } => "the request could not be completed",
        }
    }

    /// What belongs in the process log, if anything.
    ///
    /// Returns `None` where the response already says everything there is to say.
    pub fn log_detail(&self) -> Option<&str> {
        match self {
            Self::Internal { detail } => Some(detail),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let detail = match &self {
            // The only case where a detail is safe to return: it describes what was
            // wrong with the request itself.
            Self::BadRequest { reason } => Some(reason.clone()),
            _ => None,
        };

        let body = ErrorBody {
            error: self.code(),
            message: self.message(),
            detail,
        };

        let mut response = (self.status(), Json(body)).into_response();
        if matches!(self, Self::Unauthenticated) {
            // RFC 9110: a 401 says how to authenticate. `Bearer` and nothing else —
            // no realm, which would only invite a browser password prompt for an API
            // that has no password.
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

impl From<ciphr_store::StoreError> for ApiError {
    fn from(error: ciphr_store::StoreError) -> Self {
        use ciphr_store::StoreError;
        match error {
            // "It is deleted" and "it never existed" are both 404 to the client. The
            // difference is in the audit trail, for the operator.
            StoreError::NotFound { .. }
            | StoreError::VersionNotFound { .. }
            | StoreError::VersionDeleted { .. }
            | StoreError::VersionDestroyed { .. } => Self::NotFound,
            // The client asked for something that cannot exist, which is a fault in
            // the request and not in the service. Reachable only if a route forgets
            // its own early check, and a `500` would then blame the wrong side.
            StoreError::Reserved { .. } => Self::BadRequest {
                reason: error.to_string(),
            },
            other => Self::Internal {
                detail: other.to_string(),
            },
        }
    }
}

impl From<ciphr_crypto::CryptoError> for ApiError {
    fn from(error: ciphr_crypto::CryptoError) -> Self {
        Self::Internal {
            detail: error.to_string(),
        }
    }
}

/// A configuration file could not be used.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Read {
        /// Which file.
        path: String,
        /// Why not.
        source: std::io::Error,
    },
    /// The file is not valid TOML, or has an unknown key.
    Syntax {
        /// Which file.
        path: String,
        /// Why not.
        source: toml::de::Error,
    },
    /// A size value could not be parsed.
    Size {
        /// What was written.
        found: String,
    },
    /// No audit device was configured.
    NoAuditDevice,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "cannot read {path}: {source}"),
            Self::Syntax { path, source } => write!(f, "invalid configuration in {path}: {source}"),
            Self::Size { found } => write!(
                f,
                "'{found}' is not a size; use a byte count or a value such as 64MB"
            ),
            Self::NoAuditDevice => f.write_str(
                "no audit device is configured; a secret store without an audit trail is a \
                 configuration error, so the server will not start",
            ),
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Syntax { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The server could not start.
#[derive(Debug)]
pub enum StartupError {
    /// Configuration is unusable.
    Config(ConfigError),
    /// The policy file is unusable.
    Policy(ciphr_policy::PolicyError),
    /// The store could not be opened or is not initialized.
    Store(ciphr_store::StoreError),
    /// The seal could not produce the root key.
    Seal(ciphr_crypto::CryptoError),
    /// An audit device could not be opened.
    Audit(String),
    /// TLS material could not be loaded.
    Tls(String),
    /// The listener could not be bound, or the runtime failed.
    Io(std::io::Error),
}

impl core::fmt::Display for StartupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Policy(error) => write!(f, "policy file: {error}"),
            Self::Store(error) => write!(f, "store: {error}"),
            Self::Seal(error) => write!(f, "seal: {error}"),
            Self::Audit(detail) => write!(f, "audit device: {detail}"),
            Self::Tls(detail) => write!(f, "tls: {detail}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for StartupError {}

impl From<ConfigError> for StartupError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<ciphr_policy::PolicyError> for StartupError {
    fn from(error: ciphr_policy::PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<ciphr_store::StoreError> for StartupError {
    fn from(error: ciphr_store::StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ciphr_crypto::CryptoError> for StartupError {
    fn from(error: ciphr_crypto::CryptoError) -> Self {
        Self::Seal(error)
    }
}

impl From<std::io::Error> for StartupError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::ApiError;
    use axum::http::StatusCode;

    #[test]
    fn statuses_are_what_the_api_documents() {
        assert_eq!(ApiError::Unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::Forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::AuditUnavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn a_forbidden_response_says_nothing_about_the_rule_that_refused() {
        // The rule belongs in the audit trail, not in a reply to the caller who was
        // just refused by it.
        let message = ApiError::Forbidden.message();
        assert!(!message.contains("policy"));
        assert!(!message.contains("rule"));
        assert!(ApiError::Forbidden.log_detail().is_none());
    }

    #[test]
    fn only_a_bad_request_carries_a_detail_to_the_client() {
        let detail = ApiError::BadRequest {
            reason: "path contains whitespace".to_owned(),
        };
        assert_eq!(detail.status(), StatusCode::BAD_REQUEST);

        // An internal error's detail goes to the log and not to the client.
        let internal = ApiError::Internal {
            detail: "database is locked".to_owned(),
        };
        assert_eq!(internal.log_detail(), Some("database is locked"));
        assert!(!internal.message().contains("database"));
    }

    #[test]
    fn deleted_and_missing_are_both_not_found_to_a_client() {
        use ciphr_core::SecretVersion;
        use ciphr_store::StoreError;

        for error in [
            StoreError::NotFound {
                path: "a/b".to_owned(),
            },
            StoreError::VersionDeleted {
                path: "a/b".to_owned(),
                version: SecretVersion::FIRST,
            },
            StoreError::VersionDestroyed {
                path: "a/b".to_owned(),
                version: SecretVersion::FIRST,
            },
        ] {
            assert_eq!(ApiError::from(error).status(), StatusCode::NOT_FOUND);
        }
    }
}
