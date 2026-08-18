//! Keys and key identifiers.
//!
//! Three key types, one per level of the hierarchy, deliberately not
//! interchangeable: the compiler refuses to wrap a data key with a data key or to
//! pass a master key where a root key belongs. The same applies to identifiers —
//! a [`DekId`] cannot be used where a [`RootKeyId`] is expected, so the byte
//! strings that bind ciphertexts to their place cannot be crossed by accident.
//!
//! All three wrap [`secrecy::SecretBox`], so they implement neither `Debug`,
//! `Display` nor `Serialize`, and their bytes are wiped on drop. Raw access is
//! crate-private: no caller outside this crate ever holds key bytes.

use ciphr_core::hex;
use secrecy::{ExposeSecret, SecretBox};

use crate::error::CryptoError;

/// Length of every key in the hierarchy, in bytes. AES-256 takes 32.
pub const KEY_LEN: usize = 32;

/// Length of a key identifier, in bytes.
///
/// 128 bits of randomness, which makes a collision between two independently
/// generated identifiers not worth reasoning about.
pub const ID_LEN: usize = 16;

/// Fill a buffer from the operating system's CSPRNG.
///
/// The only source of randomness in this crate. There is no seeded or
/// deterministic alternative anywhere in the dependency graph, which is why
/// `getrandom` is used directly instead of `rand` (see the workspace manifest).
fn random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buffer).map_err(|_| CryptoError::Entropy)
}

macro_rules! key_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// Wiped on drop. Implements neither `Debug`, `Display` nor `Serialize`.
        pub struct $name(SecretBox<[u8; KEY_LEN]>);

        impl $name {
            /// Generate a key from the operating system's CSPRNG.
            ///
            /// # Errors
            ///
            /// Returns [`CryptoError::Entropy`] if the OS provides no
            /// randomness. There is no fallback, by design.
            pub fn generate() -> Result<Self, CryptoError> {
                let mut bytes = [0_u8; KEY_LEN];
                let result = random_bytes(&mut bytes);
                let key = Self(SecretBox::new(Box::new(bytes)));
                // `bytes` is a copy; wipe it rather than leaving it on the stack.
                zeroize::Zeroize::zeroize(&mut bytes);
                result.map(|()| key)
            }

            /// Adopt existing key bytes.
            ///
            /// The caller's copy is the caller's responsibility: an array is
            /// `Copy`, so this cannot wipe it. Prefer [`Self::generate`] or a
            /// constructor that owns its buffer.
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(SecretBox::new(Box::new(bytes)))
            }

            /// Parse a key from lower- or upper-case hexadecimal.
            ///
            /// The decode buffer is wiped before returning, on both the success
            /// and the failure path.
            ///
            /// # Errors
            ///
            /// Returns [`CryptoError::Encoding`] if the input is not exactly
            /// `2 * KEY_LEN` hexadecimal characters.
            pub fn from_hex(input: &str) -> Result<Self, CryptoError> {
                let mut bytes = [0_u8; KEY_LEN];
                let result = hex::decode_into(input, &mut bytes);
                let key = Self(SecretBox::new(Box::new(bytes)));
                zeroize::Zeroize::zeroize(&mut bytes);
                match result {
                    Ok(()) => Ok(key),
                    Err(reason) => Err(CryptoError::Encoding(reason)),
                }
            }

            /// The raw bytes. Crate-private on purpose.
            pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
                self.0.expose_secret()
            }
        }
    };
}

key_type!(
    MasterKey,
    "The key that comes from outside the system and wraps the root key."
);
key_type!(
    RootKey,
    "The key that wraps every data key. Generated once, at `init`, and stored only in wrapped form."
);
key_type!(
    Dek,
    "A data encryption key. Exactly one per secret version, so exactly one nonce ever exists for it."
);

macro_rules! id_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// Not secret: identifiers are labels that appear in the database and in
        /// authenticated data. They are a distinct type per level so that one
        /// cannot be substituted for another.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Generate an identifier from the operating system's CSPRNG.
            ///
            /// # Errors
            ///
            /// Returns [`CryptoError::Entropy`] if the OS provides no randomness.
            pub fn generate() -> Result<Self, CryptoError> {
                let mut bytes = [0_u8; ID_LEN];
                random_bytes(&mut bytes)?;
                Ok(Self(bytes))
            }

            /// Adopt existing identifier bytes.
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// The raw bytes, as they appear in authenticated data.
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// Lower-case hexadecimal, as stored in the database.
            pub fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }

            /// Parse from hexadecimal.
            ///
            /// # Errors
            ///
            /// Returns [`CryptoError::Encoding`] if the input is not exactly
            /// `2 * ID_LEN` hexadecimal characters.
            pub fn from_hex(input: &str) -> Result<Self, CryptoError> {
                let mut bytes = [0_u8; ID_LEN];
                hex::decode_into(input, &mut bytes)?;
                Ok(Self(bytes))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
    };
}

id_type!(RootKeyId, "Identifies a root key.");
id_type!(DekId, "Identifies a data encryption key.");

#[cfg(test)]
mod tests {
    use super::{Dek, DekId, KEY_LEN, MasterKey, RootKey, RootKeyId};
    use crate::error::CryptoError;
    use ciphr_core::hex::HexError;

    #[test]
    fn generated_keys_differ() {
        let a = RootKey::generate().unwrap();
        let b = RootKey::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        // A generated key must not be all zeroes, which is what a broken entropy
        // path tends to produce.
        assert_ne!(a.expose(), &[0_u8; KEY_LEN]);
    }

    #[test]
    fn hex_round_trips_through_every_key_type() {
        let hex = "0f".repeat(KEY_LEN);
        assert_eq!(
            MasterKey::from_hex(&hex).unwrap().expose(),
            &[0x0f; KEY_LEN]
        );
        assert_eq!(RootKey::from_hex(&hex).unwrap().expose(), &[0x0f; KEY_LEN]);
        assert_eq!(Dek::from_hex(&hex).unwrap().expose(), &[0x0f; KEY_LEN]);
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length() {
        // Keys implement neither `Debug` nor `PartialEq`, so a `Result` holding
        // one cannot be compared with `assert_eq!`. That is the guarantee working,
        // not an inconvenience to design around.
        assert!(matches!(
            MasterKey::from_hex("00"),
            Err(CryptoError::Encoding(HexError::Length {
                expected: 64,
                found: 2
            }))
        ));
        assert!(matches!(
            MasterKey::from_hex(&"z".repeat(64)),
            Err(CryptoError::Encoding(HexError::InvalidCharacter))
        ));
    }

    #[test]
    fn identifiers_round_trip_and_stay_distinct_types() {
        let root = RootKeyId::generate().unwrap();
        assert_eq!(RootKeyId::from_hex(&root.to_hex()).unwrap(), root);
        assert_eq!(root.to_hex().len(), 32);

        let dek = DekId::generate().unwrap();
        assert_ne!(dek.as_bytes(), root.as_bytes());

        // The following would not compile, which is the point of two types:
        //     let _: RootKeyId = dek;
    }
}
