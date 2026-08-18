//! Bearer tokens: how a machine proves which identity it is.
//!
//! ```text
//! cph_ + <id: 8 chars base64url>  + <secret: 43 chars base64url>
//!        6 bytes, not secret        32 bytes, 256 bits of entropy
//! ```
//!
//! # Why the shape is this shape
//!
//! **The `cph_` prefix** makes tokens recognizable to secret scanners — gitleaks,
//! GitHub secret scanning, and anything else that looks for known credential
//! shapes. A token committed by accident gets found instead of quietly rotting in a
//! repository.
//!
//! **The leading identifier is not secret**, so a lookup is a primary-key hit rather
//! than a scan over every stored verifier. Without it, authentication would have to
//! compare against every token in the database, which is both slow and a far larger
//! timing surface.
//!
//! **The secret half is 256 bits from the OS CSPRNG.** That is why password hashing
//! is the wrong tool here: Argon2id exists to make guessing a human-chosen password
//! expensive, and there is nothing to guess. It would cost CPU time on every request
//! and buy nothing.
//!
//! # What is stored
//!
//! `HMAC-SHA256(pepper, secret)`, where the pepper is derived from the root key. A
//! leak of the database alone therefore does **not** allow offline verification of
//! guessed tokens: reconstructing the pepper needs the master key, which is not in
//! the database (ADR-5). A plain hash would let whoever holds a database copy test
//! candidate tokens at their leisure.
//!
//! Comparison is constant-time, through [`subtle`]. An early-exit comparison would
//! leak how many leading bytes of a guess were right, which is enough to reconstruct
//! a verifier byte by byte.

use ciphr_core::base64url;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::key::{KEY_LEN, RootKey};

/// The prefix every ciphr token carries.
pub const TOKEN_PREFIX: &str = "cph_";

/// Length of the non-secret identifier, in bytes.
pub const TOKEN_ID_LEN: usize = 6;

/// Length of the secret half, in bytes.
pub const TOKEN_SECRET_LEN: usize = 32;

/// Length of a token string: prefix, 8 characters of identifier, 43 of secret.
pub const TOKEN_TEXT_LEN: usize = 4 + 8 + 43;

/// The label that separates the token pepper from every other use of the root key.
const PEPPER_LABEL: &[u8] = b"ciphr/token-pepper/v1";

/// The non-secret half of a token.
///
/// Appears in the database as a primary key and in the audit trail, so that an
/// access can be attributed to one credential of an identity — and so that "which
/// token was that?" has an answer after the token is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId([u8; TOKEN_ID_LEN]);

impl TokenId {
    /// Adopt existing identifier bytes.
    pub const fn from_bytes(bytes: [u8; TOKEN_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; TOKEN_ID_LEN] {
        &self.0
    }

    /// The eight-character text form, as it appears in a token string.
    pub fn as_text(&self) -> String {
        base64url::encode(&self.0)
    }

    /// Parse the text form.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::TokenFormat`] if the input is not eight base64url
    /// characters.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; TOKEN_ID_LEN];
        base64url::decode_into(input, &mut bytes).map_err(|_| CryptoError::TokenFormat)?;
        Ok(Self(bytes))
    }
}

impl core::fmt::Display for TokenId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.as_text())
    }
}

/// A complete token: what a client sends and what it must never write down.
///
/// Implements neither `Debug`, `Display` nor `Serialize`. The only way to get the
/// text form is [`Token::expose_text`], which returns a value that wipes itself —
/// the CLI prints it once, at issue time, and nothing else ever sees it.
pub struct Token {
    id: TokenId,
    secret: SecretBox<[u8; TOKEN_SECRET_LEN]>,
}

impl Token {
    /// Generate a token from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Entropy`] if the OS provides no randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut id = [0_u8; TOKEN_ID_LEN];
        let mut secret = [0_u8; TOKEN_SECRET_LEN];

        let outcome = getrandom::fill(&mut id).and_then(|()| getrandom::fill(&mut secret));
        let token = Self {
            id: TokenId(id),
            secret: SecretBox::new(Box::new(secret)),
        };
        secret.zeroize();

        outcome.map_err(|_| CryptoError::Entropy).map(|()| token)
    }

    /// Parse a token as presented by a client.
    ///
    /// Length, prefix, and alphabet are all checked. Nothing about *why* a token was
    /// rejected reaches the caller beyond [`CryptoError::TokenFormat`], and nothing
    /// about its content reaches an error message.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::TokenFormat`] for anything that is not exactly a ciphr
    /// token.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.len() != TOKEN_TEXT_LEN {
            return Err(CryptoError::TokenFormat);
        }
        let Some(body) = input.strip_prefix(TOKEN_PREFIX) else {
            return Err(CryptoError::TokenFormat);
        };
        let (id_text, secret_text) = body.split_at(8);

        let id = TokenId::parse(id_text)?;

        let mut secret = [0_u8; TOKEN_SECRET_LEN];
        let outcome = base64url::decode_into(secret_text, &mut secret);
        let token = Self {
            id,
            secret: SecretBox::new(Box::new(secret)),
        };
        secret.zeroize();

        match outcome {
            Ok(()) => Ok(token),
            Err(_) => Err(CryptoError::TokenFormat),
        }
    }

    /// The non-secret identifier.
    pub const fn id(&self) -> TokenId {
        self.id
    }

    /// The token as text, in a wrapper that wipes itself when dropped.
    ///
    /// Called exactly once per token, when it is issued. Everything after that point
    /// works with the identifier and the verifier.
    pub fn expose_text(&self) -> Zeroizing<String> {
        let mut text = String::with_capacity(TOKEN_TEXT_LEN);
        text.push_str(TOKEN_PREFIX);
        text.push_str(&self.id.as_text());
        text.push_str(&base64url::encode(self.secret.expose_secret()));
        Zeroizing::new(text)
    }

    /// The verifier to store for this token.
    pub fn verifier(&self, pepper: &TokenPepper) -> TokenVerifier {
        TokenVerifier::compute(pepper, self.secret.expose_secret())
    }
}

/// The pepper: a key derived from the root key, used to compute token verifiers.
///
/// Derived rather than stored, so it lives only in memory and only while the store
/// is unsealed. Its whole purpose is that a stolen database is not enough to test
/// guessed tokens offline.
pub struct TokenPepper(SecretBox<[u8; KEY_LEN]>);

impl TokenPepper {
    /// Derive the pepper from the root key.
    ///
    /// `HMAC-SHA256(root_key, "ciphr/token-pepper/v1")` — a single-step key
    /// derivation with a domain-separating label, so that this key and any future
    /// derived key cannot be each other even though both come from the root key.
    ///
    /// # Panics
    ///
    /// Cannot in practice. HMAC accepts a key of any length, so the fallible
    /// constructor has no failure mode for a 32-byte key; the alternative would be a
    /// `Result` that every caller has to handle for a case that cannot occur.
    pub fn derive(root: &RootKey) -> Self {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(root.expose())
            .expect("HMAC accepts a key of any length");
        mac.update(PEPPER_LABEL);

        let mut pepper = [0_u8; KEY_LEN];
        pepper.copy_from_slice(&mac.finalize().into_bytes());
        let derived = Self(SecretBox::new(Box::new(pepper)));
        pepper.zeroize();
        derived
    }
}

/// What is stored for a token: an HMAC of its secret half under the pepper.
///
/// Not secret in the sense the token is — it cannot be replayed — but it is a
/// verifier, so comparisons go through [`TokenVerifier::matches`] and never through
/// `==`.
#[derive(Clone)]
pub struct TokenVerifier([u8; 32]);

impl TokenVerifier {
    fn compute(pepper: &TokenPepper, secret: &[u8]) -> Self {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(pepper.0.expose_secret())
            .expect("HMAC accepts a key of any length");
        mac.update(secret);

        let mut verifier = [0_u8; 32];
        verifier.copy_from_slice(&mac.finalize().into_bytes());
        Self(verifier)
    }

    /// Adopt a stored verifier.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The stored form, as lower-case hexadecimal.
    pub fn to_hex(&self) -> String {
        ciphr_core::hex::encode(&self.0)
    }

    /// Parse the stored form.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if the input is not 64 hexadecimal
    /// characters.
    pub fn from_hex(input: &str) -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; 32];
        ciphr_core::hex::decode_into(input, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Whether two verifiers are equal, in constant time.
    ///
    /// The comparison examines every byte regardless of where the first difference
    /// is. An early exit would leak the position of that difference through timing,
    /// and a verifier can be reconstructed one byte at a time from that leak.
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(test)]
mod tests {
    use super::{TOKEN_PREFIX, TOKEN_TEXT_LEN, Token, TokenId, TokenPepper, TokenVerifier};
    use crate::error::CryptoError;
    use crate::key::RootKey;
    use secrecy::{ExposeSecret, SecretBox};

    fn pepper() -> TokenPepper {
        TokenPepper::derive(&RootKey::from_bytes([0x11; 32]))
    }

    #[test]
    fn a_generated_token_has_the_documented_shape() {
        let token = Token::generate().unwrap();
        let text = token.expose_text();

        assert_eq!(text.len(), TOKEN_TEXT_LEN);
        assert_eq!(text.len(), 55);
        assert!(text.starts_with(TOKEN_PREFIX));
        // The identifier is the visible part, and it is what the database and the
        // audit trail see.
        assert!(text[4..].starts_with(&token.id().as_text()));
        assert_eq!(token.id().as_text().len(), 8);
    }

    #[test]
    fn a_token_round_trips_through_its_text_form() {
        let original = Token::generate().unwrap();
        let text = original.expose_text();
        let parsed = Token::parse(&text).unwrap();

        assert_eq!(parsed.id(), original.id());
        // The secret half survives too, which is what makes the verifier match.
        let pepper = pepper();
        assert!(
            parsed
                .verifier(&pepper)
                .matches(&original.verifier(&pepper))
        );
    }

    #[test]
    fn generated_tokens_differ() {
        let first = Token::generate().unwrap();
        let second = Token::generate().unwrap();
        assert_ne!(first.id(), second.id());
        assert_ne!(first.expose_text().as_str(), second.expose_text().as_str());
    }

    #[test]
    fn rejects_anything_that_is_not_exactly_a_token() {
        let valid = Token::generate().unwrap().expose_text().to_string();

        let cases = [
            String::new(),
            "cph_".to_owned(),
            valid[..valid.len() - 1].to_owned(),
            format!("{valid}x"),
            valid.replacen("cph_", "cph-", 1),
            valid.replacen("cph_", "tok_", 1),
            // Right length, wrong alphabet.
            format!("cph_{}", "+".repeat(51)),
        ];

        for case in cases {
            assert!(
                matches!(Token::parse(&case), Err(CryptoError::TokenFormat)),
                "must reject {case:?}"
            );
        }
    }

    #[test]
    fn the_verifier_depends_on_the_pepper() {
        // The property that makes a database-only leak useless: without the master
        // key there is no pepper, and without the pepper the stored verifier cannot
        // be recomputed from a guess.
        let token = Token::generate().unwrap();
        let mine = TokenPepper::derive(&RootKey::from_bytes([0x11; 32]));
        let theirs = TokenPepper::derive(&RootKey::from_bytes([0x12; 32]));

        assert!(!token.verifier(&mine).matches(&token.verifier(&theirs)));
    }

    #[test]
    fn the_pepper_is_not_the_root_key() {
        // Domain separation: the derived key must not be the key it came from, or a
        // future second use of the root key would collide with this one. Checked
        // through a verifier rather than by reading the pepper, because the pepper
        // has no accessor — which is the point.
        let root = RootKey::from_bytes([0x11; 32]);
        let token = Token::generate().unwrap();

        let under_pepper = token.verifier(&TokenPepper::derive(&root));
        let under_root_directly = TokenVerifier::compute(
            &TokenPepper(SecretBox::new(Box::new(*root.expose()))),
            token.secret.expose_secret(),
        );
        assert!(!under_pepper.matches(&under_root_directly));
    }

    #[test]
    fn a_different_token_does_not_verify() {
        let pepper = pepper();
        let real = Token::generate().unwrap().verifier(&pepper);
        let other = Token::generate().unwrap().verifier(&pepper);
        assert!(!real.matches(&other));
    }

    #[test]
    fn verifier_comparison_examines_every_byte() {
        // A behavioural stand-in for the timing property. The comparison is
        // `subtle::ConstantTimeEq`, so it cannot short-circuit; what this test can
        // check is that a difference is found wherever it sits — a comparison that
        // bailed early would still be *correct*, which is exactly why correctness
        // tests cannot prove constant time. Measuring timing in a unit test produces
        // a flaky test rather than evidence, so this is deliberately not that.
        let base = [0x5a_u8; 32];
        let reference = TokenVerifier::from_bytes(base);

        for position in 0..32 {
            let mut altered = base;
            altered[position] ^= 0x01;
            assert!(
                !reference.matches(&TokenVerifier::from_bytes(altered)),
                "a difference at byte {position} must be detected"
            );
        }

        assert!(reference.matches(&TokenVerifier::from_bytes(base)));
    }

    #[test]
    fn the_verifier_round_trips_through_hexadecimal() {
        let stored = Token::generate().unwrap().verifier(&pepper());
        let text = stored.to_hex();
        assert_eq!(text.len(), 64);
        assert!(TokenVerifier::from_hex(&text).unwrap().matches(&stored));
    }

    #[test]
    fn token_identifiers_round_trip() {
        let id = TokenId::from_bytes([1, 2, 3, 4, 5, 6]);
        assert_eq!(TokenId::parse(&id.as_text()).unwrap(), id);
        assert!(matches!(
            TokenId::parse("short"),
            Err(CryptoError::TokenFormat)
        ));
    }
}
