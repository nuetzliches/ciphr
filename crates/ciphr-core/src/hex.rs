//! Lower-case hexadecimal encoding.
//!
//! Used for identifiers and for wrapped key material on its way into the
//! database. Neither is secret — a wrapped key is ciphertext, and an identifier
//! is a label — so nothing here is a secret-handling path. Plaintext secrets are
//! stored as ciphertext blobs and never pass through this module.
//!
//! Hand-written rather than pulled from a crate, because it is twenty lines and
//! the dependency budget is spent where it buys something (ADR-1).

use core::fmt;

/// Encode bytes as lower-case hexadecimal.
///
/// ```
/// assert_eq!(ciphr_core::hex::encode(&[0x0f, 0xa0]), "0fa0");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decode hexadecimal into a caller-provided buffer, which must match exactly.
///
/// The buffer is only written to on success, so a rejected input cannot leave a
/// half-filled key behind.
///
/// # Errors
///
/// Returns [`HexError`] if the input length does not correspond to `out`, or if
/// it contains anything other than hexadecimal digits.
pub fn decode_into(input: &str, out: &mut [u8]) -> Result<(), HexError> {
    let expected = out.len() * 2;
    if input.len() != expected {
        return Err(HexError::Length {
            expected,
            found: input.len(),
        });
    }

    let bytes = input.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let high = digit(bytes[index * 2])?;
        let low = digit(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(())
}

/// Decode hexadecimal of any even length.
///
/// # Errors
///
/// Returns [`HexError`] for an odd length or a non-hexadecimal character.
pub fn decode(input: &str) -> Result<Vec<u8>, HexError> {
    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength { found: input.len() });
    }
    let mut out = vec![0_u8; input.len() / 2];
    decode_into(input, &mut out)?;
    Ok(out)
}

fn digit(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HexError::InvalidCharacter),
    }
}

/// Why a hexadecimal input was rejected.
///
/// Deliberately free of the offending input: this type is used while decoding
/// key material, and an error that echoes its input is an error that logs a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The input length does not match the expected buffer.
    Length {
        /// Number of characters the buffer requires.
        expected: usize,
        /// Number of characters supplied.
        found: usize,
    },
    /// The input has an odd number of characters.
    OddLength {
        /// Number of characters supplied.
        found: usize,
    },
    /// The input contains a character that is not a hexadecimal digit.
    InvalidCharacter,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, found } => {
                write!(f, "expected {expected} hex characters, found {found}")
            }
            Self::OddLength { found } => {
                write!(
                    f,
                    "expected an even number of hex characters, found {found}"
                )
            }
            Self::InvalidCharacter => f.write_str("input contains a non-hexadecimal character"),
        }
    }
}

impl core::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::{HexError, decode, decode_into, encode};

    #[test]
    fn round_trips() {
        let bytes = [0x00, 0x01, 0x7f, 0x80, 0xff];
        assert_eq!(encode(&bytes), "00017f80ff");
        assert_eq!(decode("00017f80ff").unwrap(), bytes);
    }

    #[test]
    fn accepts_upper_case_input_but_never_emits_it() {
        assert_eq!(decode("AbCdEf").unwrap(), [0xab, 0xcd, 0xef]);
        assert_eq!(encode(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode("abc"), Err(HexError::OddLength { found: 3 }));
        assert_eq!(decode("zz"), Err(HexError::InvalidCharacter));

        let mut buf = [0_u8; 2];
        assert_eq!(
            decode_into("00", &mut buf),
            Err(HexError::Length {
                expected: 4,
                found: 2
            })
        );
    }

    #[test]
    fn leaves_the_buffer_untouched_when_the_length_is_wrong() {
        let mut buf = [0xaa_u8; 2];
        assert!(decode_into("ff", &mut buf).is_err());
        assert_eq!(buf, [0xaa, 0xaa]);
    }
}
