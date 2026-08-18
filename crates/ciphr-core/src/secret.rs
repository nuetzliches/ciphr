//! The wrapper that plaintext secrets live in.
//!
//! [`Plaintext`] implements neither `Debug`, `Display`, `Serialize` nor
//! `PartialEq`, and it never will. That is the guarantee ADR-1 chose this
//! language for: a line that logs a secret does not compile, so it cannot be
//! caught late in review or not at all.
//!
//! `PartialEq` is absent for a second reason — comparing two secrets with `==`
//! is a variable-time comparison. Where a comparison is genuinely needed it is
//! done in constant time, explicitly, at the site that needs it.

use secrecy::{ExposeSecret, SecretSlice};

/// A plaintext secret value.
///
/// The bytes are wiped when the value is dropped. Getting at them requires
/// calling [`Plaintext::expose`], which is deliberately ugly to write: every
/// call site is a place where a secret becomes visible, and those are worth
/// being able to grep for.
pub struct Plaintext(SecretSlice<u8>);

impl Plaintext {
    /// Take ownership of secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretSlice::from(bytes))
    }

    /// Borrow the plaintext.
    ///
    /// Every call is a deliberate exposure. Do not pass the result to anything
    /// that formats, logs, or serializes.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Length in bytes.
    ///
    /// Not secret in itself, and needed for size limits and metadata responses.
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Vec<u8>> for Plaintext {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for Plaintext {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::Plaintext;

    #[test]
    fn exposes_what_it_was_given() {
        let value = Plaintext::new(b"hunter2".to_vec());
        assert_eq!(value.expose(), b"hunter2");
        assert_eq!(value.len(), 7);
        assert!(!value.is_empty());
    }

    #[test]
    fn empty_is_a_valid_value() {
        // A secret store should not decide that an empty value is a mistake; the
        // API layer can, if it ever needs to.
        let value = Plaintext::new(Vec::new());
        assert!(value.is_empty());
        assert_eq!(value.expose(), b"");
    }
}
