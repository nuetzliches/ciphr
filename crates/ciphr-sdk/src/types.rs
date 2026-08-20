//! What the endpoints return, in types a caller can hold.
//!
//! Two layers, deliberately:
//!
//! - **The wire structs** are private, derive `Deserialize`, and hold a value as a plain
//!   `String`, because that is what `serde_json` produces.
//! - **The public types** hold a value as [`Plaintext`], which has no `Debug`, no
//!   `Display` and no `Serialize`, so a caller cannot log one by accident (ADR-1).
//!
//! The honest part, stated here because the alternative is pretending otherwise: **the
//! intermediate `String` is not wiped.** `serde_json` allocates it, and a copy of the
//! plaintext therefore exists in the heap between the response arriving and it being
//! moved into `Plaintext`. That window is not closable without a JSON parser that
//! deserializes into zeroizing buffers, which does not exist in this dependency budget
//! and would be a cryptographic-grade rewrite of a parser for a value that is about to
//! be put into a process environment anyway. What the wrapper buys is the thing that
//! actually goes wrong in practice: a value in a log line, a `Debug` print, or a
//! serialized error report.

use ciphr_core::{Plaintext, SecretPath, SecretVersion};
use serde::Deserialize;

/// A secret and the metadata of the version that was read.
///
/// No `Debug`: it holds a value. The metadata is reachable individually for anything
/// that needs to be logged.
pub struct Secret {
    /// Where it came from, normalized by the service.
    pub path: SecretPath,
    /// Which version was served.
    pub version: SecretVersion,
    /// The value.
    pub value: Plaintext,
    /// Milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// The identity that wrote this version.
    pub created_by: String,
}

/// The result of a write: where it went and which version it became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The path written.
    pub path: SecretPath,
    /// The version the write created.
    pub version: SecretVersion,
}

/// A secret's history, and how safe it is recorded to be to rotate.
///
/// The classification belongs to the secret rather than to any one version, which
/// is why it is here and not on [`VersionSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// How safe this secret is recorded to be to rotate.
    pub rotation: Classification,
    /// Every version, oldest first.
    pub versions: Vec<VersionSummary>,
}

/// How safe a secret is recorded to be to rotate.
///
/// The class is carried as the string the service sent rather than as an enum, and
/// that is deliberate: a client built against one version of the service must not
/// fail to parse a class a later one added. `needs_care` is the service's own answer
/// to "should this stop somebody", so a client that acts on it stays correct when the
/// set of classes grows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The class, as the service names it — `unclassified`, `rotatable`, and so on.
    pub class: String,
    /// Whether changing this value can destroy data or silently do nothing.
    pub needs_care: bool,
    /// What to do instead of rotating blindly, in the service's own words.
    pub advice: String,
}

/// One entry of a version listing.
///
/// `deleted` and `destroyed` are separate states and not degrees of the same one: a
/// deleted version is restorable, a destroyed one is not recoverable by anyone,
/// including from a backup taken afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSummary {
    /// The version.
    pub version: SecretVersion,
    /// Milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// The identity that wrote it.
    pub created_by: String,
    /// Soft-deleted, and restorable.
    pub deleted: bool,
    /// Crypto-shredded: the wrapped data key is gone.
    pub destroyed: bool,
}

/// What the service reports about itself.
///
/// Unauthenticated, and therefore free of anything that describes what is *stored*: no
/// counts, no paths, no identities. Everything here is a property of the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// Liveness, as the service words it.
    pub status: String,
    /// Whether the root key is unavailable. Always false in v1, which unseals at startup
    /// or refuses to start.
    pub sealed: bool,
    /// The seal mechanism recorded in the store.
    pub seal: String,
    /// Where *this process* read its master key: `env`, `file`, or `supplied`. Reported
    /// separately from `seal` because the two legitimately differ while a deployment
    /// moves from one to the other.
    pub key_source: String,
    /// The configured audit devices, in order.
    pub audit_devices: Vec<DeviceHealth>,
    /// The API version, `v1`.
    pub api_version: String,
}

/// One audit device, and whether it is still accepting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHealth {
    /// The device name, as configured.
    pub name: String,
    /// Whether it accepted the last record. `None` until the first record is written —
    /// "nothing recorded yet" is a different state from "the last record was accepted",
    /// and a monitor that conflates them reports a healthy device on a service that has
    /// never written to it.
    pub accepting: Option<bool>,
}

// -- the wire, as `openapi.yaml` describes it ------------------------------------------
//
// `deny_unknown_fields` is deliberately **not** set. A service one minor version ahead
// may add a field, and a consumer that fetches its secrets at startup must not fail to
// boot over a field it does not read.

#[derive(Deserialize)]
pub(crate) struct SecretWire {
    pub(crate) path: String,
    pub(crate) version: u32,
    pub(crate) value: String,
    pub(crate) created_at: i64,
    pub(crate) created_by: String,
}

#[derive(Deserialize)]
pub(crate) struct WrittenWire {
    pub(crate) path: String,
    pub(crate) version: u32,
}

#[derive(Deserialize)]
pub(crate) struct VersionsWire {
    pub(crate) rotation: RotationWire,
    pub(crate) versions: Vec<VersionSummaryWire>,
}

#[derive(Deserialize)]
pub(crate) struct RotationWire {
    pub(crate) class: String,
    pub(crate) needs_care: bool,
    pub(crate) advice: String,
}

#[derive(Deserialize)]
pub(crate) struct VersionSummaryWire {
    pub(crate) version: u32,
    pub(crate) created_at: i64,
    pub(crate) created_by: String,
    pub(crate) deleted: bool,
    pub(crate) destroyed: bool,
}

#[derive(Deserialize)]
pub(crate) struct ListingWire {
    pub(crate) paths: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct ExportWire {
    pub(crate) secrets: Vec<ExportedWire>,
}

#[derive(Deserialize)]
pub(crate) struct ExportedWire {
    pub(crate) path: String,
    pub(crate) version: u32,
    pub(crate) value: String,
}

#[derive(Deserialize)]
pub(crate) struct HealthWire {
    pub(crate) status: String,
    pub(crate) sealed: bool,
    pub(crate) seal: String,
    pub(crate) key_source: String,
    pub(crate) audit_devices: Vec<DeviceHealthWire>,
    pub(crate) api_version: String,
}

#[derive(Deserialize)]
pub(crate) struct DeviceHealthWire {
    pub(crate) name: String,
    pub(crate) accepting: Option<bool>,
}

/// The error body every failing route returns.
#[derive(Deserialize)]
pub(crate) struct ErrorWire {
    pub(crate) error: String,
    pub(crate) detail: Option<String>,
}
