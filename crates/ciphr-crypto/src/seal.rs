//! The seal: how the root key becomes available at startup.
//!
//! This is the decision that sets the security boundary of the whole system
//! (ADR-5). v1 reads a master key from an environment variable, which buys
//! unattended startup and buys **no cryptographic strength**: trust rests on file
//! permissions and on whatever distributes that file. Root on the host reads the
//! key. That is adversary A5 in the threat model and it is deliberately out of
//! scope.
//!
//! The trait is the substance. Because the master key wraps only the root key, a
//! different seal mechanism — a split key, a hardware module, another service —
//! re-wraps exactly one record. No data format changes and no secret is
//! re-encrypted, which is what keeps that upgrade path real rather than
//! aspirational.
//!
//! # Deviation from the plan
//!
//! The plan sketches `fn unseal(&self) -> Result<RootKey>`. That signature cannot
//! work: unsealing needs the wrapped record, which lives in the store, and a seal
//! that reached into the store would invert the dependency. [`Seal::unseal`]
//! therefore takes the record as input. The decision the ADR records is unchanged;
//! only the sketch was wrong.

use zeroize::Zeroizing;

use crate::envelope::{WrappedRootKey, unwrap_root_key, wrap_root_key};
use crate::error::CryptoError;
use crate::key::{MasterKey, RootKey, RootKeyId};

/// How the root key is protected at rest.
///
/// Implementations hold whatever the mechanism needs — an environment variable, a
/// PKCS#11 session, a set of key shares — and nothing else. They never see a
/// secret value and never touch the database.
pub trait Seal {
    /// Stable identifier of the mechanism, stored alongside the wrapped root key.
    ///
    /// Recorded so that a database says which mechanism sealed it, rather than
    /// leaving that to be inferred from configuration that may since have changed.
    fn id(&self) -> &str;

    /// Recover the root key from its wrapped form.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Aead`] if the mechanism cannot unwrap the record —
    /// a wrong master key and a modified record are indistinguishable.
    fn unseal(&self, wrapped: &WrappedRootKey) -> Result<RootKey, CryptoError>;

    /// Wrap a root key, keeping its identifier.
    ///
    /// Used at `init` and again whenever the master key or the mechanism changes.
    /// The identifier is preserved because it is the same root key: only its
    /// wrapping changes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Entropy`] if no randomness is available, or
    /// [`CryptoError::Aead`] if the mechanism refuses to wrap.
    fn rewrap(&self, root: &RootKey, id: RootKeyId) -> Result<WrappedRootKey, CryptoError>;
}

/// Where a static master key came from.
///
/// Recorded so that an operator can see which source *this process* actually used,
/// rather than which one the configuration file appears to say. Those differ during a
/// migration from one to the other, and that is exactly when it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// An environment variable, named here.
    Environment(String),
    /// A file, at this path.
    File(std::path::PathBuf),
    /// Supplied directly by the caller. Tests, and callers that obtain the key from
    /// somewhere this crate does not know about.
    Supplied(String),
}

impl KeySource {
    /// A short, stable word for the kind of source: `env`, `file`, or `supplied`.
    ///
    /// Machine-readable half, for the health endpoint.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Environment(_) => "env",
            Self::File(_) => "file",
            Self::Supplied(_) => "supplied",
        }
    }
}

impl core::fmt::Display for KeySource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Environment(variable) => write!(f, "environment variable {variable}"),
            Self::File(path) => write!(f, "file {}", path.display()),
            Self::Supplied(label) => write!(f, "{label}"),
        }
    }
}

/// A seal that takes its master key from outside the process, unchanged, at startup.
///
/// The v1 implementation. It exists so that a restart needs no human, and that is its
/// entire justification — see the module documentation and ADR-5 before treating it as
/// a security measure.
///
/// The key may come from an environment variable or from a file. Both are the same
/// mechanism — a static key supplied from outside — and the difference is only where
/// it is read. The file is the better of the two where the deployment allows it: see
/// [`StaticSeal::from_file`].
pub struct StaticSeal {
    source: KeySource,
    master: MasterKey,
}

impl StaticSeal {
    /// The identifier recorded in the database for this mechanism.
    pub const ID: &'static str = "static";

    /// The identifier written by builds before the key could come from a file.
    ///
    /// Accepted as equivalent when opening an existing store: it names the same
    /// mechanism, and the key bytes are the same wherever they were read from. A store
    /// sealed by such a build therefore keeps working, and records [`Self::ID`] the next
    /// time its root key is re-wrapped.
    pub const LEGACY_ENV_ID: &'static str = "static_env";

    /// The variable consulted unless configuration names another.
    pub const DEFAULT_VARIABLE: &'static str = "CIPHR_MASTER_KEY";

    /// Whether a stored seal identifier names this mechanism.
    pub fn recognizes(seal_id: &str) -> bool {
        seal_id == Self::ID || seal_id == Self::LEGACY_ENV_ID
    }

    /// Read the master key from an environment variable.
    ///
    /// The value is 64 hexadecimal characters — 32 bytes. Generate one with
    /// `openssl rand -hex 32` and keep it out of the same backup as the database:
    /// together they are a complete secret store, separately the backup is inert.
    ///
    /// Prefer [`StaticSeal::from_file`] where the deployment allows it. A key in the
    /// environment is baked into the container configuration at creation and is visible
    /// in `/proc/<pid>/environ`, which is the same objection this project raises against
    /// passing secrets to *other* services that way.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MasterKeyMissing`] if the variable is unset,
    /// [`CryptoError::MasterKeyNotUnicode`] if it cannot be read as text, or
    /// [`CryptoError::Encoding`] if it is not exactly 64 hexadecimal characters.
    /// The error never contains the value.
    pub fn from_env(variable: &str) -> Result<Self, CryptoError> {
        let value = match std::env::var(variable) {
            Ok(value) => Zeroizing::new(value),
            Err(std::env::VarError::NotPresent) => {
                return Err(CryptoError::MasterKeyMissing {
                    variable: variable.to_owned(),
                });
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(CryptoError::MasterKeyNotUnicode {
                    variable: variable.to_owned(),
                });
            }
        };
        let master = MasterKey::from_hex(value.trim())?;
        Ok(Self {
            source: KeySource::Environment(variable.to_owned()),
            master,
        })
    }

    /// Read the master key from a file.
    ///
    /// Intended for a secret mounted at `/run/secrets/…`. Compared with an environment
    /// variable this removes two exposures that are real and often overlooked:
    ///
    /// - The key is **not** baked into the container configuration, so it does not
    ///   appear in the runtime's inspect output — which is readable by every principal
    ///   with access to the container runtime socket, a broader set than root.
    /// - It is **not** in `/proc/<pid>/environ` of this process.
    ///
    /// It does **not** change the boundary that matters most: root on the host reads
    /// the file just as it read the variable (adversary A5), and the key is in this
    /// process's memory either way. Nor does it reduce the number of secrets on the
    /// host — it is still one bootstrap secret per host.
    ///
    /// **Whether the key is at rest on disk depends on the runtime.** Swarm secrets and
    /// Kubernetes secret volumes are memory-backed, so the file never touches a disk.
    /// Plain Compose outside Swarm bind-mounts a real file, so the key *is* on disk —
    /// better than the container configuration, which no permission bits protect, but
    /// not "never at rest". The deployment has to know which case it is in.
    ///
    /// Content is trimmed of surrounding whitespace, so a file written with `echo` works
    /// as well as one written with `printf %s`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MasterKeyFileUnreadable`] if the file cannot be read,
    /// [`CryptoError::MasterKeyFileWorldReadable`] on Unix if anyone but the owner and
    /// group may read it, or [`CryptoError::Encoding`] if the content is not exactly 64
    /// hexadecimal characters. No error contains the content.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        check_not_world_readable(path)?;

        let value = Zeroizing::new(std::fs::read_to_string(path).map_err(|error| {
            CryptoError::MasterKeyFileUnreadable {
                path: path.display().to_string(),
                reason: error.kind().to_string(),
            }
        })?);

        let master = MasterKey::from_hex(value.trim())?;
        Ok(Self {
            source: KeySource::File(path.to_path_buf()),
            master,
        })
    }

    /// Build a seal from a master key that is already in hand.
    ///
    /// For callers that obtain the key from somewhere other than the process
    /// environment or a file — and for tests, which must not depend on process-wide
    /// state. `label` describes the origin in messages only.
    pub fn from_master_key(label: impl Into<String>, master: MasterKey) -> Self {
        Self {
            source: KeySource::Supplied(label.into()),
            master,
        }
    }

    /// Where this seal read its key.
    pub const fn source(&self) -> &KeySource {
        &self.source
    }
}

/// Refuse a key file that anyone but its owner and group can read.
///
/// A world-readable master key is unambiguously wrong, so it stops the process rather
/// than producing a warning nobody reads. Group bits are left alone: a root-owned file
/// read by a service group is a legitimate and common arrangement, and refusing it
/// would push deployments towards running as root instead.
///
/// Windows has no equivalent bit, and no check runs there. Saying so is better than a
/// check that silently does nothing on one platform.
#[cfg(unix)]
fn check_not_world_readable(path: &std::path::Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        std::fs::metadata(path).map_err(|error| CryptoError::MasterKeyFileUnreadable {
            path: path.display().to_string(),
            reason: error.kind().to_string(),
        })?;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o004 != 0 {
        return Err(CryptoError::MasterKeyFileWorldReadable {
            path: path.display().to_string(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
// The `Result` is unnecessary on this platform and required by the other one: both
// variants must share a signature. Collapsing it here would mean the caller changes
// shape depending on the target, which is worse than an unused wrapper.
#[allow(clippy::unnecessary_wraps)]
fn check_not_world_readable(_path: &std::path::Path) -> Result<(), CryptoError> {
    // No portable equivalent of the mode bits. Documented on `from_file` rather than
    // silently skipped.
    Ok(())
}

impl Seal for StaticSeal {
    fn id(&self) -> &str {
        Self::ID
    }

    fn unseal(&self, wrapped: &WrappedRootKey) -> Result<RootKey, CryptoError> {
        unwrap_root_key(&self.master, wrapped)
    }

    fn rewrap(&self, root: &RootKey, id: RootKeyId) -> Result<WrappedRootKey, CryptoError> {
        wrap_root_key(&self.master, root, id)
    }
}

#[cfg(test)]
mod tests {
    use super::{Seal, StaticSeal};
    use crate::error::CryptoError;
    use crate::key::{KEY_LEN, MasterKey, RootKey, RootKeyId};

    fn seal_with(master: [u8; KEY_LEN]) -> StaticSeal {
        StaticSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::from_bytes(master))
    }

    #[test]
    fn seals_and_unseals() {
        let seal = seal_with([0x44; KEY_LEN]);
        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();

        let wrapped = seal.rewrap(&root, id).unwrap();
        // The mechanism is named for what it is, not for where the key came from.
        assert_eq!(seal.id(), "static");
        assert_eq!(wrapped.id, id);
        assert_eq!(seal.unseal(&wrapped).unwrap().expose(), root.expose());
    }

    #[test]
    fn rewrapping_keeps_the_identifier_and_changes_the_ciphertext() {
        let seal = seal_with([0x44; KEY_LEN]);
        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();

        let first = seal.rewrap(&root, id).unwrap();
        let second = seal.rewrap(&root, id).unwrap();

        assert_eq!(first.id, second.id);
        // A fresh nonce every time, so the same key never gets wrapped twice
        // under the same nonce.
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_seal_with_the_wrong_master_key_cannot_unseal() {
        let wrapped = seal_with([0x44; KEY_LEN])
            .rewrap(
                &RootKey::generate().unwrap(),
                RootKeyId::generate().unwrap(),
            )
            .unwrap();

        assert!(matches!(
            seal_with([0x45; KEY_LEN]).unseal(&wrapped),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn reports_a_missing_variable_without_guessing() {
        // A name no environment sets, so the test does not depend on the
        // environment it runs in.
        let Err(error) = StaticSeal::from_env("CIPHR_MASTER_KEY_ABSENT_IN_TESTS") else {
            panic!("a variable that is not set must not produce a seal");
        };
        assert_eq!(
            error,
            CryptoError::MasterKeyMissing {
                variable: "CIPHR_MASTER_KEY_ABSENT_IN_TESTS".to_owned()
            }
        );
        // The message names the variable and nothing else.
        assert!(
            error
                .to_string()
                .contains("CIPHR_MASTER_KEY_ABSENT_IN_TESTS")
        );
    }
    #[test]
    fn reads_a_key_from_a_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("master.key");
        let hex = "11".repeat(32);
        std::fs::write(&path, &hex).expect("write");
        restrict(&path);

        let seal = StaticSeal::from_file(&path).expect("must read the key");
        assert_eq!(seal.source().kind(), "file");
        assert!(seal.source().to_string().contains("master.key"));

        // The same key, whichever way it was read: a record wrapped by one opens with
        // the other.
        let from_bytes = StaticSeal::from_master_key("test", MasterKey::from_bytes([0x11; 32]));
        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();
        let wrapped = from_bytes.rewrap(&root, id).unwrap();
        assert_eq!(
            seal.unseal(&wrapped).unwrap().expose(),
            root.expose(),
            "the source must not change the key"
        );
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_key() {
        // `echo > key` writes one, and that must not be a different key from the one
        // `printf %s` writes.
        let directory = tempfile::tempdir().expect("temp dir");
        let with_newline = directory.path().join("echoed.key");
        let without = directory.path().join("printed.key");
        let hex = "22".repeat(32);
        std::fs::write(
            &with_newline,
            format!(
                "{hex}
"
            ),
        )
        .expect("write");
        std::fs::write(&without, &hex).expect("write");
        restrict(&with_newline);
        restrict(&without);

        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();
        let wrapped = StaticSeal::from_file(&with_newline)
            .expect("read")
            .rewrap(&root, id)
            .expect("wrap");

        assert_eq!(
            StaticSeal::from_file(&without)
                .expect("read")
                .unseal(&wrapped)
                .expect("the two files hold the same key")
                .expose(),
            root.expose()
        );
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path_and_not_its_content() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("absent.key");

        let Err(error) = StaticSeal::from_file(&path) else {
            panic!("a file that does not exist must not produce a seal");
        };
        assert!(matches!(error, CryptoError::MasterKeyFileUnreadable { .. }));
        assert!(error.to_string().contains("absent.key"), "got {error}");
    }

    #[test]
    fn a_file_holding_something_other_than_a_key_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("wrong.key");
        std::fs::write(&path, "this is not a key").expect("write");
        restrict(&path);

        let Err(error) = StaticSeal::from_file(&path) else {
            panic!("64 hexadecimal characters or nothing");
        };
        assert!(matches!(error, CryptoError::Encoding(_)));
        // The message must not quote what the file contained.
        assert!(!error.to_string().contains("this is not"), "got {error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_stops_the_process() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("exposed.key");
        std::fs::write(&path, "33".repeat(32)).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let Err(error) = StaticSeal::from_file(&path) else {
            panic!("a world-readable master key must not be accepted");
        };
        assert!(matches!(
            error,
            CryptoError::MasterKeyFileWorldReadable { mode: 0o644, .. }
        ));

        // A group-readable file is accepted: root-owned and read by a service group is a
        // legitimate arrangement, and refusing it would push deployments towards root.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        assert!(StaticSeal::from_file(&path).is_ok());
    }

    #[test]
    fn a_store_sealed_by_an_older_build_is_still_recognized() {
        // The identifier changed from `static_env` to `static` when the key could come
        // from a file. It names the same mechanism, so a store written before that keeps
        // working rather than looking foreign.
        assert!(StaticSeal::recognizes("static"));
        assert!(StaticSeal::recognizes(StaticSeal::LEGACY_ENV_ID));
        assert!(!StaticSeal::recognizes("shamir"));
        assert!(!StaticSeal::recognizes("pkcs11"));
    }

    /// Make a key file unreadable by anyone but its owner, where the platform has the
    /// concept. The tests write files that would otherwise inherit a permissive umask.
    fn restrict(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        #[cfg(not(unix))]
        let _ = path;
    }
}
