//! Token storage and authentication.
//!
//! Authentication is one indexed lookup by the token's non-secret identifier,
//! followed by a constant-time comparison of the verifier. Two properties matter and
//! both are tested:
//!
//! - **The reason for a failure never reaches the caller.** An unknown identifier, a
//!   wrong secret, an expired token, and a revoked token all produce the same
//!   outcome. Distinguishing them would confirm to whoever is probing that an
//!   identifier exists, or that a token *used* to be valid.
//! - **A rejected token is never a partial success.** Expiry and revocation are
//!   checked after the verifier, so a wrong secret cannot learn anything from the
//!   difference either.

use ciphr_crypto::{Token, TokenPepper, TokenVerifier};
use rusqlite::{OptionalExtension, params};

use crate::error::StoreError;
use crate::sqlite::{SqliteStore, now_millis};

/// What a successful authentication establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The identity the token belongs to, as named in the policy file.
    pub identity: String,
    /// The token's non-secret identifier, for the audit trail.
    pub token_id: String,
}

/// A token as stored, without anything secret in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// The non-secret identifier.
    pub token_id: String,
    /// The identity the token belongs to.
    pub identity: String,
    /// When it was issued, in milliseconds since the Unix epoch, UTC.
    pub created_at: i64,
    /// Who issued it.
    pub created_by: String,
    /// When it expires, if it does.
    pub expires_at: Option<i64>,
    /// When it was last used successfully.
    pub last_used_at: Option<i64>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<i64>,
}

impl TokenRecord {
    /// Whether the token is usable at `now`.
    pub fn is_usable_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

impl SqliteStore {
    /// Store a freshly generated token for an identity.
    ///
    /// Takes the token so that the verifier is computed here rather than by a caller
    /// who might store the wrong thing. The token itself is not stored and cannot be
    /// recovered afterwards: what goes into the database is the verifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error, including the case where
    /// the identifier already exists — which would mean two tokens sharing one
    /// identity in the audit trail.
    pub fn issue_token(
        &mut self,
        identity: &str,
        token: &Token,
        pepper: &TokenPepper,
        created_by: &str,
        expires_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT INTO tokens (
                 token_id, identity_name, verifier, created_at, created_by, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                token.id().as_text(),
                identity,
                token.verifier(pepper).to_hex(),
                now_millis(),
                created_by,
                expires_at,
            ],
        )?;
        Ok(())
    }

    /// Authenticate a token string.
    ///
    /// `Ok(None)` means the token is not valid, for any reason. The reason is
    /// deliberately not reported: see the module documentation.
    ///
    /// On success the token's `last_used_at` is updated. That write is best-effort —
    /// a failure to record it does not fail the authentication, because refusing a
    /// valid credential over a bookkeeping error would turn a full disk into an
    /// outage twice over. The access itself is still audited, and the audit trail is
    /// the record that matters.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the lookup itself fails, or
    /// [`StoreError::Corrupt`] if a stored verifier is not readable.
    pub fn authenticate(
        &mut self,
        presented: &str,
        pepper: &TokenPepper,
    ) -> Result<Option<Authenticated>, StoreError> {
        let Ok(token) = Token::parse(presented) else {
            return Ok(None);
        };

        let now = now_millis();
        let Some(record) = self.token(&token.id().as_text())? else {
            return Ok(None);
        };

        let stored = self.verifier_for(&record.token_id)?;
        let Some(stored) = stored else {
            return Ok(None);
        };

        // Constant-time, and done before expiry and revocation are considered, so
        // that timing cannot distinguish "wrong secret" from "expired".
        if !stored.matches(&token.verifier(pepper)) {
            return Ok(None);
        }
        if !record.is_usable_at(now) {
            return Ok(None);
        }

        // Best-effort: see the note above.
        let _ = self.connection().execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE token_id = ?1",
            params![record.token_id, now],
        );

        Ok(Some(Authenticated {
            identity: record.identity,
            token_id: record.token_id,
        }))
    }

    /// One token's metadata, or `None` if there is no such identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error.
    pub fn token(&self, token_id: &str) -> Result<Option<TokenRecord>, StoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT token_id, identity_name, created_at, created_by,
                        expires_at, last_used_at, revoked_at
                 FROM tokens WHERE token_id = ?1",
                params![token_id],
                |row| {
                    Ok(TokenRecord {
                        token_id: row.get(0)?,
                        identity: row.get(1)?,
                        created_at: row.get(2)?,
                        created_by: row.get(3)?,
                        expires_at: row.get(4)?,
                        last_used_at: row.get(5)?,
                        revoked_at: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    /// Every token, or every token of one identity, newest first.
    ///
    /// Metadata only — no verifier leaves this module.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error.
    pub fn tokens(&self, identity: Option<&str>) -> Result<Vec<TokenRecord>, StoreError> {
        let mut statement = self.connection().prepare(
            "SELECT token_id, identity_name, created_at, created_by,
                    expires_at, last_used_at, revoked_at
             FROM tokens
             WHERE ?1 IS NULL OR identity_name = ?1
             ORDER BY created_at DESC, token_id",
        )?;
        let rows = statement.query_map(params![identity], |row| {
            Ok(TokenRecord {
                token_id: row.get(0)?,
                identity: row.get(1)?,
                created_at: row.get(2)?,
                created_by: row.get(3)?,
                expires_at: row.get(4)?,
                last_used_at: row.get(5)?,
                revoked_at: row.get(6)?,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Revoke a token. Idempotent: revoking a revoked token keeps the first time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TokenNotFound`] if there is no such identifier.
    pub fn revoke_token(&mut self, token_id: &str) -> Result<(), StoreError> {
        let changed = self.connection().execute(
            "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?2) WHERE token_id = ?1",
            params![token_id, now_millis()],
        )?;
        if changed == 0 {
            return Err(StoreError::TokenNotFound {
                token_id: token_id.to_owned(),
            });
        }
        Ok(())
    }

    /// Revoke every token of an identity, returning how many were affected.
    ///
    /// What to reach for when an identity is compromised: one call, rather than
    /// listing tokens and hoping the list was complete.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] on a database error.
    pub fn revoke_identity_tokens(&mut self, identity: &str) -> Result<usize, StoreError> {
        Ok(self.connection().execute(
            "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE identity_name = ?1 AND revoked_at IS NULL",
            params![identity, now_millis()],
        )?)
    }

    fn verifier_for(&self, token_id: &str) -> Result<Option<TokenVerifier>, StoreError> {
        let stored: Option<String> = self
            .connection()
            .query_row(
                "SELECT verifier FROM tokens WHERE token_id = ?1",
                params![token_id],
                |row| row.get(0),
            )
            .optional()?;

        match stored {
            None => Ok(None),
            Some(text) => Ok(Some(TokenVerifier::from_hex(&text).map_err(|_| {
                StoreError::Corrupt {
                    detail: "a stored token verifier is not readable".to_owned(),
                }
            })?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TokenRecord;
    use crate::sqlite::SqliteStore;
    use ciphr_crypto::{RootKey, Token, TokenPepper};

    fn store_and_pepper() -> (SqliteStore, TokenPepper) {
        let store = SqliteStore::open_in_memory().expect("open");
        let pepper = TokenPepper::derive(&RootKey::from_bytes([0x11; 32]));
        (store, pepper)
    }

    #[test]
    fn a_stored_token_authenticates() {
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();

        store
            .issue_token("deploy-runner", &token, &pepper, "operator", None)
            .expect("issue");

        let text = token.expose_text();
        let authenticated = store
            .authenticate(&text, &pepper)
            .expect("authenticate")
            .expect("must succeed");

        assert_eq!(authenticated.identity, "deploy-runner");
        assert_eq!(authenticated.token_id, token.id().as_text());

        // Using a token records that it was used.
        let record = store.token(&authenticated.token_id).unwrap().unwrap();
        assert!(record.last_used_at.is_some());
    }

    #[test]
    fn every_kind_of_invalid_token_looks_the_same() {
        let (mut store, pepper) = store_and_pepper();
        let known = Token::generate().unwrap();
        store
            .issue_token("deploy-runner", &known, &pepper, "operator", None)
            .expect("issue");

        // Not a token at all; a well-formed token that was never issued; a token
        // verified against the wrong pepper. All three must be indistinguishable.
        let unknown = Token::generate().unwrap();
        let other_pepper = TokenPepper::derive(&RootKey::from_bytes([0x22; 32]));

        for (what, outcome) in [
            ("garbage", store.authenticate("not-a-token", &pepper)),
            (
                "never issued",
                store.authenticate(&unknown.expose_text(), &pepper),
            ),
            (
                "wrong pepper",
                store.authenticate(&known.expose_text(), &other_pepper),
            ),
        ] {
            assert_eq!(outcome.expect("no error"), None, "{what} must be rejected");
        }
    }

    #[test]
    fn an_expired_token_stops_working() {
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();

        // Expired an hour ago.
        let past = super::now_millis() - 3_600_000;
        store
            .issue_token("deploy-runner", &token, &pepper, "operator", Some(past))
            .expect("issue");

        assert_eq!(
            store.authenticate(&token.expose_text(), &pepper).unwrap(),
            None
        );
    }

    #[test]
    fn a_revoked_token_stops_working_immediately() {
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();
        store
            .issue_token("deploy-runner", &token, &pepper, "operator", None)
            .expect("issue");

        assert!(
            store
                .authenticate(&token.expose_text(), &pepper)
                .unwrap()
                .is_some()
        );

        store.revoke_token(&token.id().as_text()).expect("revoke");
        assert_eq!(
            store.authenticate(&token.expose_text(), &pepper).unwrap(),
            None
        );

        // Revoking twice keeps the original time rather than moving it.
        let first = store
            .token(&token.id().as_text())
            .unwrap()
            .unwrap()
            .revoked_at;
        store.revoke_token(&token.id().as_text()).expect("again");
        let second = store
            .token(&token.id().as_text())
            .unwrap()
            .unwrap()
            .revoked_at;
        assert_eq!(first, second);
    }

    #[test]
    fn revoking_an_identity_covers_every_token_it_has() {
        let (mut store, pepper) = store_and_pepper();
        let mut tokens = Vec::new();
        for _ in 0..3 {
            let token = Token::generate().unwrap();
            store
                .issue_token("deploy-runner", &token, &pepper, "operator", None)
                .expect("issue");
            tokens.push(token);
        }
        let other = Token::generate().unwrap();
        store
            .issue_token("someone-else", &other, &pepper, "operator", None)
            .expect("issue");

        assert_eq!(store.revoke_identity_tokens("deploy-runner").unwrap(), 3);

        for token in &tokens {
            assert_eq!(
                store.authenticate(&token.expose_text(), &pepper).unwrap(),
                None
            );
        }
        // Another identity's token is untouched.
        assert!(
            store
                .authenticate(&other.expose_text(), &pepper)
                .unwrap()
                .is_some()
        );

        // A second call has nothing left to do.
        assert_eq!(store.revoke_identity_tokens("deploy-runner").unwrap(), 0);
    }

    #[test]
    fn listing_returns_metadata_and_never_a_verifier() {
        let (mut store, pepper) = store_and_pepper();
        for identity in ["a", "b"] {
            store
                .issue_token(
                    identity,
                    &Token::generate().unwrap(),
                    &pepper,
                    "operator",
                    Some(1),
                )
                .expect("issue");
        }

        assert_eq!(store.tokens(None).unwrap().len(), 2);
        let for_a = store.tokens(Some("a")).unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].identity, "a");
        assert_eq!(for_a[0].created_by, "operator");
        assert_eq!(for_a[0].expires_at, Some(1));
    }

    #[test]
    fn revoking_a_token_that_does_not_exist_is_an_error() {
        let (mut store, _pepper) = store_and_pepper();
        assert!(store.revoke_token("AAAAAAAA").is_err());
    }

    #[test]
    fn usability_is_decided_by_expiry_and_revocation() {
        let base = TokenRecord {
            token_id: "AAAAAAAA".to_owned(),
            identity: "a".to_owned(),
            created_at: 0,
            created_by: "operator".to_owned(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        };

        assert!(base.is_usable_at(1_000));
        assert!(
            TokenRecord {
                expires_at: Some(1_001),
                ..base.clone()
            }
            .is_usable_at(1_000)
        );
        assert!(
            !TokenRecord {
                expires_at: Some(1_000),
                ..base.clone()
            }
            .is_usable_at(1_000),
            "expiry is exclusive: a token is not valid at the instant it expires"
        );
        assert!(
            !TokenRecord {
                revoked_at: Some(1),
                ..base
            }
            .is_usable_at(1_000)
        );
    }
}
