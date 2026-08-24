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
//!
//! # Bait
//!
//! A honeypot token (ADR-15) is a third outcome and not a third code path. It is stored
//! by the same function, with the same generator and the same verifier derivation, and
//! it is recognized by reading a flag on the row the comparison already fetched — after
//! that comparison, so nothing about it is measurable. What differs is only what the
//! *trail* is told; the caller is refused identically.
//!
//! The recognition itself is unconditional, in every build, and the reason is worth
//! stating because ADR-20 would allow a feature here. Nothing in this module *behaves*
//! differently for bait: it reports a flag it read anyway, and reporting costs the same
//! whatever the flag says. The behaviour that differs — a distinct audit action, the
//! trip row, the marker file, the health flag — is composed in `ciphr-server` behind the
//! `honeypot_alert` entry. Keeping the recognition out of the feature means this path is
//! compiled and tested in every configuration, which for an authentication path is
//! worth more than the absence would be.

use ciphr_crypto::{Token, TokenPepper, TokenVerifier};
use rusqlite::{OptionalExtension, params};

use crate::error::StoreError;
use crate::sqlite::{SqliteStore, now_millis};

/// The verifier an unknown identifier is compared against.
///
/// Its value is irrelevant — no token can produce it, because a verifier is an HMAC
/// under a pepper the caller does not have. It exists so that the unknown-identifier
/// path performs the same work as the known one.
const ABSENT_VERIFIER: [u8; 32] = [0; 32];

/// What a successful authentication establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The identity the token belongs to, as named in the policy file.
    pub identity: String,
    /// The token's non-secret identifier, for the audit trail.
    pub token_id: String,
}

/// What a token being issued is for.
///
/// An argument rather than a second function, because ADR-15 requires bait to be
/// stored exactly as a real credential is: same generator, same verifier derivation,
/// same row. Two code paths would be two chances for the two to drift, and a honeypot
/// token that is distinguishable in the database is one an operator eventually
/// recognizes and deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPurpose {
    /// A real credential, for an identity that will use it.
    Credential,
    /// Bait. Authenticates nothing, and is planted where credentials should not be.
    Honeypot,
}

/// What a presented credential turned out to be.
///
/// Three outcomes rather than an `Option`, and the third one is why: bait has to be
/// *recognized* while being refused exactly as anything else is. Returning it as a
/// separate variant is what lets the caller keep one rejection path — the response is
/// built after the match and cannot differ, which is the structural version of ADR-15's
/// indistinguishability claim rather than the remembered version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// A valid credential.
    Valid(Authenticated),
    /// Not valid, for a reason deliberately not reported.
    Invalid,
    /// Not valid, and it matched a stored honeypot token.
    ///
    /// Recognized on the same code path, by the same constant-time comparison, as any
    /// other token: the difference is what the *trail* records, never what the caller
    /// is told.
    Bait {
        /// The bait's non-secret identifier.
        token_id: String,
        /// The identity it was issued for, which is what names *which* bait was taken.
        identity: String,
    },
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
    /// Whether this credential is bait (ADR-15).
    ///
    /// Bait is stored exactly like a real token and is refused exactly like an invalid
    /// one. This flag is what lets the *trail* say which of the two happened, and it is
    /// visible only on the administrative read path — never to whoever presented it.
    pub honeypot: bool,
}

impl TokenRecord {
    /// Whether the token is usable at `now`.
    pub fn is_usable_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expiry| expiry > now)
    }

    /// Why the token is unusable, or that it is not — as one word.
    ///
    /// **Here rather than in each reader**, which is the point: the CLI derived these
    /// three words inline and `GET /v1/tokens` would have derived them again, so a
    /// deployment could have got two answers to *"is this credential still valid"*
    /// depending on which one it asked. One derivation, two callers.
    ///
    /// `revoked` beats `expired` when a token is both, and that order is deliberate: a
    /// revocation is something somebody did, an expiry is something that happened. The
    /// question afterwards is almost always about the act.
    #[must_use]
    pub fn state_at(&self, now: i64) -> TokenState {
        if self.revoked_at.is_some() {
            TokenState::Revoked
        } else if self.expires_at.is_some_and(|expiry| expiry <= now) {
            TokenState::Expired
        } else {
            TokenState::Valid
        }
    }
}

/// What a token is, as far as authentication is concerned.
///
/// Three states and no fourth: bait is a separate flag on the record, because a honeypot
/// token is a *valid-looking* credential that authenticates nothing, and folding it in
/// here would put it in every listing as though it were a lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Not revoked, and not past its expiry.
    Valid,
    /// Past its expiry, and never revoked.
    Expired,
    /// Revoked, whether or not it has also expired.
    Revoked,
}

impl TokenState {
    /// The word a person reads and a job branches on. Stable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl core::fmt::Display for TokenState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
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
        purpose: TokenPurpose,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT INTO tokens (
                 token_id, identity_name, verifier, created_at, created_by, expires_at,
                 honeypot
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                token.id().as_text(),
                identity,
                token.verifier(pepper).to_hex(),
                now_millis(),
                created_by,
                expires_at,
                i64::from(purpose == TokenPurpose::Honeypot),
            ],
        )?;
        Ok(())
    }

    /// Authenticate a token string.
    ///
    /// [`Authentication::Invalid`] means the token is not valid, for any reason. The
    /// reason is deliberately not reported: see the module documentation.
    /// [`Authentication::Bait`] is also not valid — the caller must refuse it exactly
    /// as it refuses `Invalid`, and the variant exists so the *trail* can say which
    /// happened.
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
    ) -> Result<Authentication, StoreError> {
        let Ok(token) = Token::parse(presented) else {
            return Ok(Authentication::Invalid);
        };

        let now = now_millis();
        let record = self.token(&token.id().as_text())?;
        let stored = match &record {
            Some(record) => self.verifier_for(&record.token_id)?,
            None => None,
        };

        // An unknown identifier used to return here, before the HMAC and the
        // comparison. That made "this identifier exists" measurable even though the
        // return value is identical, in the one module whose subject is not leaking
        // which failure occurred. Both paths now do the same derivation and the same
        // constant-time comparison against a fixed stand-in.
        //
        // This narrows the difference rather than closing it: the known-identifier path
        // still performs one more database query. Equalising that would mean issuing a
        // query nobody needs, and the remaining signal is a lookup on a 48-bit
        // identifier that cannot be enumerated remotely.
        let expected = stored.unwrap_or_else(|| TokenVerifier::from_bytes(ABSENT_VERIFIER));
        let presented = token.verifier(pepper);
        let matched = expected.matches(&presented);

        let Some(record) = record else {
            return Ok(Authentication::Invalid);
        };

        // Constant-time, and evaluated before expiry and revocation are considered, so
        // that timing cannot distinguish "wrong secret" from "expired".
        if !matched {
            return Ok(Authentication::Invalid);
        }

        // Bait, and this is the whole of the recognition: a flag on a row that was
        // already fetched, read after the same comparison every other token gets. No
        // extra query, no extra derivation, and no branch before the comparison — so
        // there is nothing here for an attacker holding several credentials to measure.
        //
        // Placed before expiry and revocation on purpose. Bait is refused whatever its
        // dates say, and asking about them first would make an *expired* honeypot token
        // fail as an ordinary expired token and go unrecorded — which is the one way a
        // honeypot silently stops being one.
        if record.honeypot {
            return Ok(Authentication::Bait {
                token_id: record.token_id,
                identity: record.identity,
            });
        }

        if !record.is_usable_at(now) {
            return Ok(Authentication::Invalid);
        }

        // Best-effort: see the note above.
        let _ = self.connection().execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE token_id = ?1",
            params![record.token_id, now],
        );

        Ok(Authentication::Valid(Authenticated {
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
                        expires_at, last_used_at, revoked_at, honeypot
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
                        honeypot: row.get::<_, i64>(7)? != 0,
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
                    expires_at, last_used_at, revoked_at, honeypot
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
                honeypot: row.get::<_, i64>(7)? != 0,
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
    /// **Returns whether *this call* established the timestamp** — `true` the first
    /// time, `false` for a token that was already revoked. That is the whole reason
    /// this returns anything, and it is finding F8 of the review of 2026-08-24: the
    /// answer used to be derived from a read taken *before* the update, so two
    /// concurrent revocations both saw `revoked_at = NULL` and both claimed to be the
    /// one that stopped the credential. Only one of them was. A responder comparing
    /// notes with another responder needs that to be true.
    ///
    /// The write is the only thing consulted. `WHERE revoked_at IS NULL` makes the
    /// database decide, so the answer cannot be stale by construction; the second
    /// statement runs only when nothing was updated, and distinguishes "already
    /// revoked" from "no such token" — a distinction that cannot go stale either,
    /// because nothing in this system un-revokes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TokenNotFound`] if there is no such identifier.
    pub fn revoke_token(&mut self, token_id: &str) -> Result<bool, StoreError> {
        let changed = self.connection().execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE token_id = ?1 AND revoked_at IS NULL",
            params![token_id, now_millis()],
        )?;
        if changed > 0 {
            return Ok(true);
        }

        // Nothing was updated, which is two different situations. One indexed read
        // tells them apart.
        if self.token(token_id)?.is_some() {
            Ok(false)
        } else {
            Err(StoreError::TokenNotFound {
                token_id: token_id.to_owned(),
            })
        }
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
    use super::{Authentication, TokenPurpose, TokenRecord};
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
            .issue_token(
                "deploy-runner",
                &token,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");

        let text = token.expose_text();
        let Authentication::Valid(authenticated) =
            store.authenticate(&text, &pepper).expect("authenticate")
        else {
            panic!("a stored token must authenticate");
        };

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
            .issue_token(
                "deploy-runner",
                &known,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");

        // Not a token at all; a well-formed token that was never issued; a token
        // verified against the wrong pepper. All must be indistinguishable.
        let unknown = Token::generate().unwrap();
        let other_pepper = TokenPepper::derive(&RootKey::from_bytes([0x22; 32]));

        // Bait belongs *inside* this test rather than beside it — ADR-15 names this
        // test as the place. A honeypot token authenticates nothing, so it is one more
        // kind of invalid credential and has to be refused on the same terms as the
        // rest. What differs is only what the caller does with the third variant, and
        // no assertion about that belongs here.
        let bait = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &bait,
                &pepper,
                "operator",
                None,
                TokenPurpose::Honeypot,
            )
            .expect("plant bait");

        // An expired *and* revoked honeypot token: the dates must not be able to route
        // it back into an ordinary rejection, which is the one way bait stops being
        // recognized without anybody noticing.
        let stale_bait = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &stale_bait,
                &pepper,
                "operator",
                Some(super::now_millis() - 3_600_000),
                TokenPurpose::Honeypot,
            )
            .expect("plant stale bait");
        store
            .revoke_token(&stale_bait.id().as_text())
            .expect("revoke");

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
            ("bait", store.authenticate(&bait.expose_text(), &pepper)),
            (
                "expired and revoked bait",
                store.authenticate(&stale_bait.expose_text(), &pepper),
            ),
        ] {
            let outcome = outcome.expect("no error");
            assert!(
                !matches!(outcome, Authentication::Valid(_)),
                "{what} must be rejected"
            );
        }
    }

    /// The trail has to be able to say bait was taken, and to say *which* bait.
    ///
    /// Separate from the test above because it asserts the opposite kind of thing: that
    /// one of these rejections is distinguishable to the *process*, while the test above
    /// pins that none of them is distinguishable to the caller.
    #[test]
    fn bait_is_recognized_and_names_itself() {
        let (mut store, pepper) = store_and_pepper();
        let bait = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &bait,
                &pepper,
                "operator",
                None,
                TokenPurpose::Honeypot,
            )
            .expect("plant bait");

        match store
            .authenticate(&bait.expose_text(), &pepper)
            .expect("no error")
        {
            Authentication::Bait { token_id, identity } => {
                assert_eq!(token_id, bait.id().as_text());
                assert_eq!(identity, "deploy-runner");
            }
            other => panic!("bait must be recognized, got {other:?}"),
        }
    }

    /// Bait is stored as an ordinary token is, and only the flag tells them apart.
    ///
    /// An operator who can spot bait in the database by its shape is an operator who
    /// eventually tidies it away.
    #[test]
    fn bait_is_stored_like_any_other_token() {
        let (mut store, pepper) = store_and_pepper();
        let real = Token::generate().unwrap();
        let bait = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &real,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");
        store
            .issue_token(
                "deploy-runner",
                &bait,
                &pepper,
                "operator",
                None,
                TokenPurpose::Honeypot,
            )
            .expect("plant");

        let real = store.token(&real.id().as_text()).unwrap().expect("stored");
        let planted = store.token(&bait.id().as_text()).unwrap().expect("stored");

        assert!(!real.honeypot);
        assert!(planted.honeypot);
        // Everything else that is visible about the two is the same shape.
        assert_eq!(real.identity, planted.identity);
        assert_eq!(real.created_by, planted.created_by);
        assert_eq!(real.expires_at, planted.expires_at);
        assert_eq!(real.revoked_at, planted.revoked_at);
        assert_eq!(planted.last_used_at, None);
    }

    /// Presenting bait must not update `last_used_at`.
    ///
    /// Two reasons, and the second is the load-bearing one. Bait never authenticates, so
    /// there is no use to record; and the update is a write the ordinary rejection path
    /// does not perform, which would make taking the bait cost measurably more than
    /// failing on a wrong secret.
    #[test]
    fn taking_the_bait_writes_nothing_to_the_token_row() {
        let (mut store, pepper) = store_and_pepper();
        let bait = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &bait,
                &pepper,
                "operator",
                None,
                TokenPurpose::Honeypot,
            )
            .expect("plant");

        let before = store.token(&bait.id().as_text()).unwrap().expect("stored");
        let _ = store.authenticate(&bait.expose_text(), &pepper);
        let after = store.token(&bait.id().as_text()).unwrap().expect("stored");

        assert_eq!(before, after, "the row must be untouched");
    }

    #[test]
    fn an_expired_token_stops_working() {
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();

        // Expired an hour ago.
        let past = super::now_millis() - 3_600_000;
        store
            .issue_token(
                "deploy-runner",
                &token,
                &pepper,
                "operator",
                Some(past),
                TokenPurpose::Credential,
            )
            .expect("issue");

        assert_eq!(
            store.authenticate(&token.expose_text(), &pepper).unwrap(),
            Authentication::Invalid
        );
    }

    #[test]
    fn a_revoked_token_stops_working_immediately() {
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &token,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");

        assert!(matches!(
            store.authenticate(&token.expose_text(), &pepper).unwrap(),
            Authentication::Valid(_)
        ));

        assert!(
            store.revoke_token(&token.id().as_text()).expect("revoke"),
            "the first call is the one that revoked it"
        );
        assert_eq!(
            store.authenticate(&token.expose_text(), &pepper).unwrap(),
            Authentication::Invalid
        );

        // Revoking twice keeps the original time rather than moving it, and the second
        // call says it was not the one that did it. Finding F8 of the review of
        // 2026-08-24: two responders revoking the same leaked credential were both told
        // they had stopped it, which is false for one of them and is exactly the
        // question asked while comparing notes during an incident.
        let first = store
            .token(&token.id().as_text())
            .unwrap()
            .unwrap()
            .revoked_at;
        assert!(
            !store.revoke_token(&token.id().as_text()).expect("again"),
            "a second revocation did not establish the timestamp"
        );
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
                .issue_token(
                    "deploy-runner",
                    &token,
                    &pepper,
                    "operator",
                    None,
                    TokenPurpose::Credential,
                )
                .expect("issue");
            tokens.push(token);
        }
        let other = Token::generate().unwrap();
        store
            .issue_token(
                "someone-else",
                &other,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");

        assert_eq!(store.revoke_identity_tokens("deploy-runner").unwrap(), 3);

        for token in &tokens {
            assert_eq!(
                store.authenticate(&token.expose_text(), &pepper).unwrap(),
                Authentication::Invalid
            );
        }
        // Another identity's token is untouched.
        assert!(matches!(
            store.authenticate(&other.expose_text(), &pepper).unwrap(),
            Authentication::Valid(_)
        ));

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
                    TokenPurpose::Credential,
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
    fn a_revoked_token_is_not_confused_with_one_that_never_existed() {
        // The two cases that both leave the `UPDATE` having changed nothing. They must
        // not collapse into each other: `false` means the credential is dead and
        // somebody else killed it, the error means the id names nothing at all.
        let (mut store, pepper) = store_and_pepper();
        let token = Token::generate().unwrap();
        store
            .issue_token(
                "deploy-runner",
                &token,
                &pepper,
                "operator",
                None,
                TokenPurpose::Credential,
            )
            .expect("issue");

        assert!(store.revoke_token(&token.id().as_text()).expect("revoke"));
        assert!(
            !store.revoke_token(&token.id().as_text()).expect("again"),
            "already revoked"
        );
        assert!(
            store.revoke_token("AAAAAAAA").is_err(),
            "never existed, and that is a different answer"
        );
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
            honeypot: false,
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
