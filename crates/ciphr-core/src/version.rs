//! Secret version numbers.

use core::fmt;

/// A version of a secret, counting from one.
///
/// Zero is not a version. It is the value a fresh secret has *before* its first
/// write, and keeping it out of the type means "no version yet" cannot be
/// confused with "version zero" — including in the additional authenticated data
/// that binds a ciphertext to its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretVersion(u32);

impl SecretVersion {
    /// The version of the first write to a path.
    pub const FIRST: Self = Self(1);

    /// Wrap a number, rejecting zero.
    pub const fn new(version: u32) -> Option<Self> {
        if version == 0 {
            None
        } else {
            Some(Self(version))
        }
    }

    /// The number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next version, or `None` on overflow.
    ///
    /// Overflow is not a realistic scenario, but silently wrapping to zero in
    /// something that ends up inside authenticated data would be.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    /// Big-endian encoding, as used in additional authenticated data.
    ///
    /// Fixed width on purpose: the byte string that binds a ciphertext to its
    /// location must be unambiguous.
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for SecretVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretVersion;

    #[test]
    fn zero_is_not_a_version() {
        assert!(SecretVersion::new(0).is_none());
        assert_eq!(SecretVersion::new(1), Some(SecretVersion::FIRST));
    }

    #[test]
    fn counts_up_and_refuses_to_wrap() {
        assert_eq!(SecretVersion::FIRST.next().unwrap().get(), 2);
        assert!(SecretVersion::new(u32::MAX).unwrap().next().is_none());
    }

    #[test]
    fn encodes_big_endian() {
        assert_eq!(SecretVersion::FIRST.to_be_bytes(), [0, 0, 0, 1]);
        assert_eq!(
            SecretVersion::new(0x0102_0304).unwrap().to_be_bytes(),
            [1, 2, 3, 4]
        );
    }
}
