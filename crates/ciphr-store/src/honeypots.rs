//! Bait, and the trips it has produced (ADR-15).
//!
//! Two things live here and they are deliberately different in kind:
//!
//! - **The bait itself** is data: a tier on a secret, a flag on a token. Setting and
//!   reading it is ordinary store work.
//! - **A trip** is *derived* state. The authoritative record of a trip is the request's
//!   own audit entry, decided in ADR-15 on 2026-08-21, because an audit device and this
//!   store hold separate connections to the same file and therefore cannot be made to
//!   fail together. What the `tripwire` table holds is the **latch** — the thing that
//!   stops one piece of bait paging somebody every time it is touched — and what
//!   `/v1/health` reads `tripped` from.
//!
//! The table earns its place for the one thing the trail cannot do: survive
//! `ciphr audit cut`. Retention bounds the trail, and a latch derived from the trail
//! would un-latch itself when the entry holding it aged out.
//!
//! # Nothing here is behind a feature
//!
//! `honeypot_alert` is a build entry (ADR-20) and this module is not gated by it. These
//! are general functions on the store — set a tier, read a tier, latch a trip — and
//! nothing in them *behaves* differently depending on whether a deployment planted
//! anything. The behaviour that differs is composed in `ciphr-server`, which is the
//! crate whose job is composition. Keeping the store unconditional means this code is
//! compiled and tested in every configuration.
//!
//! # Why the caller is told whether it latched
//!
//! [`SqliteStore::latch_trip`] answers `true` only for the call that actually opened a
//! trip. A second read of the same bait gets `false`, from the database rather than from
//! a check the caller remembered to make: the latch is a partial unique index, so two
//! concurrent reads cannot both win. The caller uses the answer to decide whether to
//! touch the marker file, not whether to record — recording already happened, in the
//! audit entry, on its own terms.

use rusqlite::{OptionalExtension, params};

use ciphr_core::SecretPath;

use crate::error::StoreError;
use crate::sqlite::{SqliteStore, now_millis};

/// What a trip is allowed to do.
///
/// One variant. ADR-15 designed `disable-identity` and `freeze` and deliberately left
/// them unbuilt, and the database refuses any other value — so this enum is the whole
/// of what can be stored, not a subset of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotTier {
    /// A distinct audit action, a flag on `/v1/health`, and a marker file. A false
    /// positive costs a page and nothing else.
    Alert,
}

impl HoneypotTier {
    /// The stored label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
        }
    }

    /// Parse a stored or configured label.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] for anything else, including the tiers ADR-15
    /// designed and did not build: a database holding `freeze` was written by something
    /// that is not this build, and guessing what it meant is worse than refusing.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "alert" => Ok(Self::Alert),
            other => Err(StoreError::Corrupt {
                detail: format!("unknown honeypot tier {other:?}; only 'alert' is built"),
            }),
        }
    }
}

/// Which kind of bait a trip concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaitKind {
    /// A path holding a real-looking value nobody legitimately reads.
    Secret,
    /// A credential in the documented format that authenticates nothing.
    Token,
}

impl BaitKind {
    /// The stored label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Token => "token",
        }
    }
}

/// A piece of bait, for the administrative read.
///
/// Never on the value path: an operator has to be able to tell bait from a real secret,
/// and a caller must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Honeypot {
    /// Which kind.
    pub kind: BaitKind,
    /// The path, for a honeypot secret.
    pub path: Option<String>,
    /// The non-secret token identifier, for a honeypot token.
    pub token_id: Option<String>,
    /// The identity a honeypot token was issued for.
    pub identity: Option<String>,
    /// The tier. Always `alert` in this build.
    pub tier: HoneypotTier,
    /// Whether a trip on this bait is currently open.
    pub tripped: bool,
}

/// One recorded trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    /// When it fired, in milliseconds since the Unix epoch, UTC.
    pub tripped_at: i64,
    /// Which kind of bait.
    pub kind: BaitKind,
    /// The path, for a honeypot secret.
    pub path: Option<String>,
    /// The non-secret token identifier, for a honeypot token.
    pub token_id: Option<String>,
    /// Who took it, when there was an authenticated identity.
    ///
    /// `None` for a honeypot token: presenting bait authenticates nothing, so there is
    /// nobody to name — the same reason an unauthenticated audit entry has no principal.
    pub identity: Option<String>,
    /// The tier.
    pub tier: HoneypotTier,
    /// When it was cleared on the host, if it was.
    pub cleared_at: Option<i64>,
}

impl SqliteStore {
    /// Mark a secret as bait, or remove the mark.
    ///
    /// The path must already exist: bait is a real secret holding a real-looking value,
    /// and a tier on a path with nothing behind it is a honeypot that answers `404` to
    /// whoever takes it.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the path does not exist, or [`StoreError::Sqlite`] on
    /// a database error.
    pub fn set_honeypot(
        &mut self,
        path: &SecretPath,
        tier: Option<HoneypotTier>,
    ) -> Result<(), StoreError> {
        let changed = self.connection().execute(
            "UPDATE secrets SET honeypot_tier = ?2 WHERE path = ?1",
            params![path.as_str(), tier.map(HoneypotTier::as_str)],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                path: path.as_str().to_owned(),
            });
        }
        Ok(())
    }

    /// The tier for a path, or `None` if the path is not bait.
    ///
    /// Also `None` for a path that does not exist. The caller is on the value path and
    /// has already been told by the policy that it may read; "no such secret" is that
    /// path's answer to give, and distinguishing the two here would put a second opinion
    /// about existence in front of it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a database error, or [`StoreError::Corrupt`] if the
    /// stored tier is not one this build knows.
    pub fn honeypot_tier(&self, path: &SecretPath) -> Result<Option<HoneypotTier>, StoreError> {
        let stored: Option<Option<String>> = self
            .connection()
            .query_row(
                "SELECT honeypot_tier FROM secrets WHERE path = ?1",
                params![path.as_str()],
                |row| row.get(0),
            )
            .optional()?;

        match stored.flatten() {
            None => Ok(None),
            Some(text) => HoneypotTier::parse(&text).map(Some),
        }
    }

    /// Every piece of bait, secrets and tokens together.
    ///
    /// Two queries rather than a union: the two kinds carry different columns, and a
    /// union that pads each with the other's nulls is harder to read than the thing it
    /// saves.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a database error, or [`StoreError::Corrupt`] on an
    /// unknown stored tier.
    pub fn honeypots(&self) -> Result<Vec<Honeypot>, StoreError> {
        let connection = self.connection();
        let mut bait = Vec::new();

        let mut statement = connection.prepare(
            "SELECT s.path, s.honeypot_tier,
                    EXISTS (SELECT 1 FROM tripwire t
                            WHERE t.kind = 'secret' AND t.path = s.path
                              AND t.cleared_at IS NULL)
             FROM secrets s
             WHERE s.honeypot_tier IS NOT NULL
             ORDER BY s.path",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?;
        for row in rows {
            let (path, tier, tripped) = row?;
            bait.push(Honeypot {
                kind: BaitKind::Secret,
                path: Some(path),
                token_id: None,
                identity: None,
                tier: HoneypotTier::parse(&tier)?,
                tripped,
            });
        }

        let mut statement = connection.prepare(
            "SELECT k.token_id, k.identity_name,
                    EXISTS (SELECT 1 FROM tripwire t
                            WHERE t.kind = 'token' AND t.token_id = k.token_id
                              AND t.cleared_at IS NULL)
             FROM tokens k
             WHERE k.honeypot = 1
             ORDER BY k.created_at DESC, k.token_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?;
        for row in rows {
            let (token_id, identity, tripped) = row?;
            bait.push(Honeypot {
                kind: BaitKind::Token,
                path: None,
                token_id: Some(token_id),
                identity: Some(identity),
                // A honeypot token has no tier column: bait that never authenticates
                // cannot reach a tier that acts on an identity (ADR-15, property 4), so
                // every token trip is an alert by construction rather than by storage.
                tier: HoneypotTier::Alert,
                tripped,
            });
        }

        Ok(bait)
    }

    /// Open a trip on one piece of bait, unless one is already open.
    ///
    /// Returns `true` only for the call that opened it. `false` means the latch was
    /// already closed on this bait, which is not an error — it is the ordinary answer for
    /// the second and every later touch, and the reason ADR-15 wanted a latch at all.
    ///
    /// The uniqueness comes from a partial index rather than from a check here, so two
    /// concurrent reads of the same bait cannot both open one. That is why the
    /// constraint violation is translated instead of avoided.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] for any database failure that is *not* the latch.
    pub fn latch_trip(
        &mut self,
        kind: BaitKind,
        reference: &str,
        identity: Option<&str>,
        tier: HoneypotTier,
    ) -> Result<bool, StoreError> {
        let (path, token_id) = match kind {
            BaitKind::Secret => (Some(reference), None),
            BaitKind::Token => (None, Some(reference)),
        };

        let result = self.connection().execute(
            "INSERT INTO tripwire (tripped_at, kind, path, token_id, identity, tier)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                now_millis(),
                kind.as_str(),
                path,
                token_id,
                identity,
                tier.as_str(),
            ],
        );

        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // The latch, and only the latch. Every other constraint on this table
                // states something about the row's shape, which this function builds
                // itself -- so a violation of one of those is a defect here and must not
                // be swallowed as "already tripped".
                //
                // Distinguished by asking the database, rather than by parsing the
                // message: SQLite's extended codes do not separate a unique index from a
                // CHECK, and matching on English is how this stops working after an
                // upgrade.
                if self.trip_is_open(kind, reference)? {
                    Ok(false)
                } else {
                    Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                        error,
                        Some("a tripwire row was refused and no trip is open".to_owned()),
                    )))
                }
            }
            Err(other) => Err(StoreError::Sqlite(other)),
        }
    }

    /// Whether a trip is currently open on one piece of bait.
    fn trip_is_open(&self, kind: BaitKind, reference: &str) -> Result<bool, StoreError> {
        let column = match kind {
            BaitKind::Secret => "path",
            BaitKind::Token => "token_id",
        };
        // The column name is chosen from the match above and never from input.
        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM tripwire
                            WHERE kind = ?1 AND {column} = ?2 AND cleared_at IS NULL)"
        );
        let open: i64 =
            self.connection()
                .query_row(&sql, params![kind.as_str(), reference], |row| row.get(0))?;
        Ok(open != 0)
    }

    /// Every trip that has not been cleared, newest first.
    ///
    /// What `/v1/health` reduces to a boolean, and what the administrative read shows in
    /// full.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a database error, or [`StoreError::Corrupt`] on an
    /// unknown stored tier.
    pub fn open_trips(&self) -> Result<Vec<Trip>, StoreError> {
        self.open_trips_inner()
    }

    /// How many tripwires are open, without building any of them.
    ///
    /// What `/v1/health` asks, and the reason it is a separate query: that endpoint
    /// wanted a boolean and a count, and got them by materializing every open trip --
    /// seven columns and several allocations per row, on a route something polls every
    /// few seconds, under the process-wide store mutex. Finding F9 of the review of
    /// 2026-08-24. An aggregate answers the same question and allocates nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a database error. **Not swallowed by the caller**: an
    /// unanswerable question is not the same answer as zero.
    pub fn open_trip_count(&self) -> Result<usize, StoreError> {
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM tripwire WHERE cleared_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    fn open_trips_inner(&self) -> Result<Vec<Trip>, StoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT tripped_at, kind, path, token_id, identity, tier, cleared_at
             FROM tripwire WHERE cleared_at IS NULL
             ORDER BY tripped_at DESC, id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?;

        let mut trips = Vec::new();
        for row in rows {
            let (tripped_at, kind, path, token_id, identity, tier, cleared_at) = row?;
            trips.push(Trip {
                tripped_at,
                kind: match kind.as_str() {
                    "secret" => BaitKind::Secret,
                    "token" => BaitKind::Token,
                    other => {
                        return Err(StoreError::Corrupt {
                            detail: format!("unknown tripwire kind {other:?}"),
                        });
                    }
                },
                path,
                token_id,
                identity,
                tier: HoneypotTier::parse(&tier)?,
                cleared_at,
            });
        }
        Ok(trips)
    }

    /// Clear every open trip, and say how many there were.
    ///
    /// On the host and nowhere else — ADR-15 rejects a route that clears a tripwire for
    /// the same reason ADR-3 keeps policies out of the API: a guard reachable through the
    /// door it guards is not a guard. Nothing here enforces that; the absence of a route
    /// does.
    ///
    /// Clearing sets `cleared_at` rather than deleting the row. A tripwire that resets
    /// quietly has, in effect, not fired, and the history of what was taken and when is
    /// the part an investigation needs.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] on a database error.
    pub fn clear_trips(&mut self) -> Result<usize, StoreError> {
        Ok(self.connection().execute(
            "UPDATE tripwire SET cleared_at = ?1 WHERE cleared_at IS NULL",
            params![now_millis()],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::{BaitKind, HoneypotTier};
    use crate::sqlite::SqliteStore;
    use crate::store::Store;
    use ciphr_core::{Plaintext, SecretPath};
    use ciphr_crypto::{RootKey, encrypt};

    fn store_with(path: &str) -> (SqliteStore, SecretPath) {
        let mut store = SqliteStore::open_in_memory().expect("open");
        let root = RootKey::from_bytes([0x33; 32]);
        let parsed = SecretPath::parse(path).expect("valid path");
        let value = Plaintext::from(&b"real-looking"[..]);
        store
            .put(&parsed, "operator", &mut |version| {
                encrypt(&root, &parsed, version, &value)
            })
            .expect("put");
        (store, parsed)
    }

    #[test]
    fn a_secret_is_not_bait_until_it_is_marked() {
        let (mut store, path) = store_with("infra/_runner/DEPLOY_KEY");
        assert_eq!(store.honeypot_tier(&path).unwrap(), None);

        store
            .set_honeypot(&path, Some(HoneypotTier::Alert))
            .expect("mark");
        assert_eq!(
            store.honeypot_tier(&path).unwrap(),
            Some(HoneypotTier::Alert)
        );

        store.set_honeypot(&path, None).expect("unmark");
        assert_eq!(store.honeypot_tier(&path).unwrap(), None);
    }

    /// A tier on a path with nothing behind it is bait that answers 404 to whoever
    /// takes it, which is bait that catches nobody.
    #[test]
    fn a_path_that_does_not_exist_cannot_be_marked() {
        let (mut store, _) = store_with("infra/_runner/DEPLOY_KEY");
        let missing = SecretPath::parse("infra/_runner/NOTHING").expect("valid");
        assert!(
            store
                .set_honeypot(&missing, Some(HoneypotTier::Alert))
                .is_err()
        );
    }

    /// The value path asks this question after the policy has already allowed the read,
    /// so "no such secret" is not this function's answer to give.
    #[test]
    fn an_unknown_path_is_simply_not_bait() {
        let (store, _) = store_with("infra/_runner/DEPLOY_KEY");
        let missing = SecretPath::parse("infra/_runner/NOTHING").expect("valid");
        assert_eq!(store.honeypot_tier(&missing).unwrap(), None);
    }

    #[test]
    fn the_first_touch_latches_and_the_second_does_not() {
        let (mut store, path) = store_with("infra/_runner/DEPLOY_KEY");
        store
            .set_honeypot(&path, Some(HoneypotTier::Alert))
            .expect("mark");

        assert!(
            store
                .latch_trip(
                    BaitKind::Secret,
                    path.as_str(),
                    Some("deploy-runner"),
                    HoneypotTier::Alert
                )
                .expect("latch"),
            "the first touch opens a trip"
        );
        assert!(
            !store
                .latch_trip(
                    BaitKind::Secret,
                    path.as_str(),
                    Some("deploy-runner"),
                    HoneypotTier::Alert
                )
                .expect("no error"),
            "the second touch must not open a second one"
        );

        assert_eq!(store.open_trips().unwrap().len(), 1);
    }

    #[test]
    fn clearing_frees_the_latch_and_keeps_the_history() {
        let (mut store, path) = store_with("infra/_runner/DEPLOY_KEY");
        store
            .set_honeypot(&path, Some(HoneypotTier::Alert))
            .expect("mark");

        store
            .latch_trip(BaitKind::Secret, path.as_str(), None, HoneypotTier::Alert)
            .expect("latch");
        assert_eq!(store.clear_trips().expect("clear"), 1);
        assert!(store.open_trips().unwrap().is_empty());

        // The same bait can trip again, and the first trip is still on record.
        assert!(
            store
                .latch_trip(BaitKind::Secret, path.as_str(), None, HoneypotTier::Alert)
                .expect("latch again")
        );
        assert_eq!(store.open_trips().unwrap().len(), 1);
    }

    /// Two pieces of bait latch independently — a latch that was per-table rather than
    /// per-bait would hide every trip after the first.
    #[test]
    fn each_piece_of_bait_has_its_own_latch() {
        let (mut store, first) = store_with("infra/_runner/DEPLOY_KEY");
        let second = SecretPath::parse("infra/_runner/REGISTRY_TOKEN").expect("valid");
        let root = RootKey::from_bytes([0x33; 32]);
        let value = Plaintext::from(&b"also-real-looking"[..]);
        store
            .put(&second, "operator", &mut |version| {
                encrypt(&root, &second, version, &value)
            })
            .expect("put");
        for path in [&first, &second] {
            store
                .set_honeypot(path, Some(HoneypotTier::Alert))
                .expect("mark");
        }

        assert!(
            store
                .latch_trip(BaitKind::Secret, first.as_str(), None, HoneypotTier::Alert)
                .unwrap()
        );
        assert!(
            store
                .latch_trip(BaitKind::Secret, second.as_str(), None, HoneypotTier::Alert)
                .unwrap()
        );
        assert_eq!(store.open_trips().unwrap().len(), 2);
    }

    #[test]
    fn a_tier_this_build_does_not_have_is_refused_rather_than_guessed() {
        assert!(HoneypotTier::parse("freeze").is_err());
        assert!(HoneypotTier::parse("disable-identity").is_err());
        assert_eq!(HoneypotTier::parse("alert").unwrap(), HoneypotTier::Alert);
    }

    /// The administrative view is the only place bait is visible, so it has to show
    /// both kinds and whether each is currently tripped.
    #[test]
    fn the_administrative_view_shows_both_kinds() {
        let (mut store, path) = store_with("infra/_runner/DEPLOY_KEY");
        store
            .set_honeypot(&path, Some(HoneypotTier::Alert))
            .expect("mark");

        let pepper = ciphr_crypto::TokenPepper::derive(&RootKey::from_bytes([0x44; 32]));
        let bait = ciphr_crypto::Token::generate().expect("entropy");
        store
            .issue_token(
                "deploy-runner",
                &bait,
                &pepper,
                "operator",
                None,
                crate::TokenPurpose::Honeypot,
            )
            .expect("plant");

        store
            .latch_trip(BaitKind::Secret, path.as_str(), None, HoneypotTier::Alert)
            .expect("latch");

        let listed = store.honeypots().expect("list");
        assert_eq!(listed.len(), 2);

        let secret = listed
            .iter()
            .find(|entry| entry.kind == BaitKind::Secret)
            .expect("the secret");
        assert_eq!(secret.path.as_deref(), Some(path.as_str()));
        assert!(secret.tripped, "this one has been taken");

        let token = listed
            .iter()
            .find(|entry| entry.kind == BaitKind::Token)
            .expect("the token");
        assert_eq!(token.identity.as_deref(), Some("deploy-runner"));
        assert!(!token.tripped, "this one has not");
    }
}
