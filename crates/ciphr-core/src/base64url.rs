//! Unpadded base64url, as used in token strings.
//!
//! Hand-written for the same reason as the hexadecimal encoder: it is forty lines,
//! and the dependency budget in the crates that hold security-relevant logic is
//! spent where it buys something. The alphabet and the padding-free form are RFC
//! 4648 §5; the tests check against the RFC's own vectors.
//!
//! Unpadded, because a token is something a person pastes: 43 characters for 32
//! bytes rather than 44 with a `=` that some tools helpfully strip.
//!
//! Decoding is strict. A non-alphabet character, a wrong length, or non-zero bits
//! in the final partial group are all rejected rather than silently rounded, so two
//! different strings can never decode to the same bytes — which for a credential
//! would mean two tokens that both work.

use core::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as unpadded base64url.
///
/// ```
/// assert_eq!(ciphr_core::base64url::encode(b"foobar"), "Zm9vYmFy");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let group = (b0 << 16) | (b1 << 8) | b2;

        // Every group contributes at least two characters; the third and fourth
        // exist only if the input had a second and third byte.
        out.push(char::from(ALPHABET[((group >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((group >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((group >> 6) & 0x3f) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(group & 0x3f) as usize]));
        }
    }

    out
}

/// Decode unpadded base64url.
///
/// # Errors
///
/// Returns [`Base64Error`] for a character outside the alphabet, for a length that
/// cannot be the encoding of any byte string, or for a final group whose unused
/// bits are not zero.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = input.as_bytes();

    // A base64 group of four characters carries three bytes. A trailing group of
    // one character carries nothing, so that length is impossible.
    if bytes.len() % 4 == 1 {
        return Err(Base64Error::Length { found: bytes.len() });
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);

    for chunk in bytes.chunks(4) {
        let mut group = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            group |= u32::from(sextet(*byte)?) << (18 - 6 * index);
        }

        match chunk.len() {
            2 => {
                // Four unused bits must be zero, or two strings decode to one byte
                // string.
                if group & 0x0000_ffff != 0 {
                    return Err(Base64Error::TrailingBits);
                }
                out.push(((group >> 16) & 0xff) as u8);
            }
            3 => {
                if group & 0x0000_00ff != 0 {
                    return Err(Base64Error::TrailingBits);
                }
                out.push(((group >> 16) & 0xff) as u8);
                out.push(((group >> 8) & 0xff) as u8);
            }
            _ => {
                out.push(((group >> 16) & 0xff) as u8);
                out.push(((group >> 8) & 0xff) as u8);
                out.push((group & 0xff) as u8);
            }
        }
    }

    Ok(out)
}

/// Decode into a fixed-size buffer, which the input must fill exactly.
///
/// The buffer is written only on success, so a rejected input cannot leave half a
/// credential behind.
///
/// # Errors
///
/// Returns [`Base64Error`] as [`decode`], or [`Base64Error::Length`] if the decoded
/// length is not `out.len()`.
pub fn decode_into(input: &str, out: &mut [u8]) -> Result<(), Base64Error> {
    let decoded = decode(input)?;
    if decoded.len() != out.len() {
        return Err(Base64Error::Length { found: input.len() });
    }
    out.copy_from_slice(&decoded);
    Ok(())
}

fn sextet(byte: u8) -> Result<u8, Base64Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Base64Error::InvalidCharacter),
    }
}

/// Why a base64url input was rejected.
///
/// Free of the offending input: this type is used while decoding tokens, and an
/// error that echoes its input is an error that logs a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// The input length cannot be the encoding of any byte string of the expected
    /// size.
    Length {
        /// Number of characters supplied.
        found: usize,
    },
    /// The input contains a character outside the base64url alphabet.
    ///
    /// Standard base64 `+` and `/` are outside it too: accepting them would mean
    /// two spellings of one token.
    InvalidCharacter,
    /// The final partial group has non-zero unused bits.
    TrailingBits,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { found } => write!(f, "{found} characters is not a valid length"),
            Self::InvalidCharacter => {
                f.write_str("input contains a character outside the base64url alphabet")
            }
            Self::TrailingBits => f.write_str("input has non-zero unused bits in its final group"),
        }
    }
}

impl core::error::Error for Base64Error {}

#[cfg(test)]
mod tests {
    use super::{Base64Error, decode, decode_into, encode};

    /// RFC 4648 §10, with the padding removed.
    const RFC_VECTORS: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn matches_the_rfc_vectors() {
        for (bytes, expected) in RFC_VECTORS {
            assert_eq!(encode(bytes), expected, "encoding {bytes:?}");
            assert_eq!(decode(expected).unwrap(), bytes, "decoding {expected}");
        }
    }

    #[test]
    fn uses_the_url_safe_alphabet() {
        // The two bytes that distinguish base64url from base64: `-` and `_` where
        // standard base64 would put `+` and `/`.
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert!(decode("+/8").is_err(), "standard base64 must not decode");
    }

    #[test]
    fn thirty_two_bytes_encode_to_forty_three_characters() {
        // The token secret length the format depends on.
        assert_eq!(encode(&[0xab; 32]).len(), 43);
        assert_eq!(encode(&[0xab; 6]).len(), 8);
    }

    #[test]
    fn round_trips_every_byte_value() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn rejects_input_that_could_be_read_two_ways() {
        // "Zh" and "Zg" would both decode to `f` if the unused bits were ignored,
        // which for a credential means two strings that both authenticate.
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zh"), Err(Base64Error::TrailingBits));

        assert_eq!(decode("A"), Err(Base64Error::Length { found: 1 }));
        assert_eq!(decode("Zm9v!!!"), Err(Base64Error::InvalidCharacter));

        // Padding is not part of the accepted form. `Zm9vYg==` is a valid *padded*
        // encoding of "foob", and it is rejected: accepting both spellings would
        // mean one token with two text forms. The length check happens first, so a
        // single trailing `=` is reported as a length error instead — either way it
        // does not decode.
        assert_eq!(decode("Zm9vYg=="), Err(Base64Error::InvalidCharacter));
        assert_eq!(decode("Zm9v="), Err(Base64Error::Length { found: 5 }));
    }

    #[test]
    fn decode_into_requires_an_exact_fit() {
        let mut buffer = [0_u8; 6];
        assert!(decode_into("Zm9vYmFy", &mut buffer).is_ok());
        assert_eq!(&buffer, b"foobar");

        let mut wrong = [0xaa_u8; 3];
        assert!(decode_into("Zm9vYmFy", &mut wrong).is_err());
        assert_eq!(wrong, [0xaa; 3], "the buffer must be untouched on failure");
    }
}
