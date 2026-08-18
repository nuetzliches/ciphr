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

/// A seal that takes its master key from an environment variable.
///
/// The v1 implementation. It exists so that a restart needs no human, and that is
/// its entire justification — see the module documentation and ADR-5 before
/// treating it as a security measure.
pub struct StaticEnvSeal {
    variable: String,
    master: MasterKey,
}

impl StaticEnvSeal {
    /// The identifier recorded in the database for this mechanism.
    pub const ID: &'static str = "static_env";

    /// The variable consulted unless configuration names another.
    pub const DEFAULT_VARIABLE: &'static str = "CIPHR_MASTER_KEY";

    /// Read the master key from an environment variable.
    ///
    /// The value is 64 hexadecimal characters — 32 bytes. Generate one with
    /// `openssl rand -hex 32` and keep it out of the same backup as the database:
    /// together they are a complete secret store, separately the backup is inert.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MasterKeyMissing`] if the variable is unset,
    /// [`CryptoError::MasterKeyNotUnicode`] if it cannot be read as text, or
    /// [`CryptoError::Encoding`] if it is not exactly 64 hexadecimal characters.
    /// The error never contains the value.
    pub fn from_env(variable: &str) -> Result<Self, CryptoError> {
        let value = match std::env::var(variable) {
            Ok(value) => value,
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
            variable: variable.to_owned(),
            master,
        })
    }

    /// Build a seal from a master key that is already in hand.
    ///
    /// For callers that obtain the key from somewhere other than the process
    /// environment — and for tests, which must not depend on process-wide state.
    /// `variable` is a label used in messages only.
    pub fn from_master_key(variable: impl Into<String>, master: MasterKey) -> Self {
        Self {
            variable: variable.into(),
            master,
        }
    }

    /// Name of the environment variable this seal was configured with.
    pub fn variable(&self) -> &str {
        &self.variable
    }
}

impl Seal for StaticEnvSeal {
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
    use super::{Seal, StaticEnvSeal};
    use crate::error::CryptoError;
    use crate::key::{KEY_LEN, MasterKey, RootKey, RootKeyId};

    fn seal_with(master: [u8; KEY_LEN]) -> StaticEnvSeal {
        StaticEnvSeal::from_master_key("CIPHR_MASTER_KEY", MasterKey::from_bytes(master))
    }

    #[test]
    fn seals_and_unseals() {
        let seal = seal_with([0x44; KEY_LEN]);
        let root = RootKey::generate().unwrap();
        let id = RootKeyId::generate().unwrap();

        let wrapped = seal.rewrap(&root, id).unwrap();
        assert_eq!(seal.id(), "static_env");
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
        let Err(error) = StaticEnvSeal::from_env("CIPHR_MASTER_KEY_ABSENT_IN_TESTS") else {
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
}
