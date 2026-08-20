//! Cryptographic errors.
//!
//! Two rules shape this type.
//!
//! **No error carries a value or key material.** Not the plaintext, not the key,
//! not a fragment of either, not a length that only makes sense with the value in
//! hand (ADR-1).
//!
//! **Every authentication failure looks the same.** A wrong key, a tampered tag,
//! a ciphertext bound to a different path, and a ciphertext bound to a different
//! version all produce [`CryptoError::Aead`]. Distinguishing them would hand an
//! attacker a decryption oracle that tells them *why* their guess failed, which
//! is exactly the information they lack.

use core::fmt;

use ciphr_core::hex::HexError;
use ciphr_core::{BIND_MOUNT_HINT, BIND_MOUNT_MODE};

/// Something went wrong in the cryptographic layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Authenticated decryption failed.
    ///
    /// Deliberately indistinguishable between a wrong key, a modified
    /// ciphertext, and a ciphertext that belongs to a different path or version.
    Aead,
    /// The operating system refused to provide randomness.
    ///
    /// Not recoverable and not worth retrying: without entropy there is no safe
    /// way to generate a key, and falling back to anything else would be the
    /// worst possible response.
    Entropy,
    /// A key was not the expected length.
    KeyLength {
        /// Length the algorithm requires, in bytes.
        expected: usize,
        /// Length supplied, in bytes.
        found: usize,
    },
    /// A key or identifier was not valid hexadecimal.
    ///
    /// Carries the reason, which contains lengths and never content.
    Encoding(HexError),
    /// The sealed root key does not carry the identifier it was expected to.
    ///
    /// This is what a swapped or mixed-up seal record looks like. Continuing
    /// would mean decrypting with a key whose provenance is unclear.
    RootKeyIdMismatch,
    /// The environment variable holding the master key is not set.
    MasterKeyMissing {
        /// Name of the variable that was consulted.
        variable: String,
    },
    /// The environment variable holding the master key is not valid Unicode.
    MasterKeyNotUnicode {
        /// Name of the variable that was consulted.
        variable: String,
    },
    /// The file holding the master key could not be read.
    ///
    /// Carries the path and the kind of I/O failure, never the content.
    MasterKeyFileUnreadable {
        /// Which file.
        path: String,
        /// What went wrong, as a category rather than a message that might quote data.
        reason: String,
    },
    /// The file holding the master key is readable by everyone.
    ///
    /// Refused rather than warned about: a world-readable master key is unambiguously
    /// wrong, and a warning in a startup log is a warning nobody reads. Group bits are
    /// deliberately not checked — a root-owned file read by a service group is a
    /// legitimate arrangement, and refusing it would push deployments towards running
    /// as root.
    MasterKeyFileWorldReadable {
        /// Which file.
        path: String,
        /// The permission bits found.
        mode: u32,
    },
    /// A token is not a ciphr token.
    ///
    /// One variant for every way a token can be malformed — wrong length, wrong
    /// prefix, wrong alphabet. Distinguishing them would tell whoever is probing
    /// which half of their guess was closer, and none of it helps a legitimate
    /// caller, who either has a token or does not.
    TokenFormat,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => f.write_str("authenticated decryption failed"),
            Self::Entropy => f.write_str("the operating system provided no randomness"),
            Self::KeyLength { expected, found } => {
                write!(f, "expected a {expected}-byte key, found {found} bytes")
            }
            Self::Encoding(reason) => write!(f, "invalid hexadecimal: {reason}"),
            Self::RootKeyIdMismatch => {
                f.write_str("the sealed root key carries an unexpected identifier")
            }
            Self::MasterKeyMissing { variable } => {
                write!(f, "environment variable {variable} is not set")
            }
            Self::MasterKeyNotUnicode { variable } => {
                write!(f, "environment variable {variable} is not valid Unicode")
            }
            Self::MasterKeyFileUnreadable { path, reason } => {
                write!(f, "cannot read the master key file {path}: {reason}")
            }
            Self::MasterKeyFileWorldReadable { path, mode } => {
                write!(
                    f,
                    "the master key file {path} is mode {mode:04o} and world-readable; \
                     restrict it to its owner (and group, if a service needs it)"
                )?;
                if *mode == BIND_MOUNT_MODE {
                    f.write_str(BIND_MOUNT_HINT)?;
                }
                Ok(())
            }
            Self::TokenFormat => f.write_str("not a valid token"),
        }
    }
}

impl core::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encoding(reason) => Some(reason),
            _ => None,
        }
    }
}

impl From<HexError> for CryptoError {
    fn from(reason: HexError) -> Self {
        Self::Encoding(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn authentication_failures_are_indistinguishable() {
        // Not a formality: if the envelope layer ever grows a second variant for
        // "wrong AAD" or "bad tag", that difference is a decryption oracle. The
        // proof that all four failure shapes end up here lives in the envelope
        // tests; this only pins the message.
        assert_eq!(
            CryptoError::Aead.to_string(),
            "authenticated decryption failed"
        );
    }

    #[test]
    fn a_refusal_at_0777_names_the_cause_that_platform_actually_has() {
        // The check is right and stays. What was wrong is the message: on a bind
        // mount from a host without Unix permissions every file reports 0777, so the
        // reader was sent looking for a permission nobody set.
        let message = CryptoError::MasterKeyFileWorldReadable {
            path: "/etc/ciphr/master.key".to_owned(),
            mode: 0o777,
        }
        .to_string();
        assert!(message.contains("bind mount"), "{message}");
        assert!(message.contains("named volume"), "{message}");
    }

    #[test]
    fn a_refusal_at_any_other_mode_does_not_offer_the_excuse() {
        // 0644 is a permission somebody set. Suggesting a bind mount here would teach
        // the reader that this refusal is usually spurious, which is the opposite of
        // true.
        let message = CryptoError::MasterKeyFileWorldReadable {
            path: "/etc/ciphr/master.key".to_owned(),
            mode: 0o644,
        }
        .to_string();
        assert!(!message.contains("bind mount"), "{message}");
    }
}
