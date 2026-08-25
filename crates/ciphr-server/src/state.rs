//! Shared state, and the two things every request goes through.
//!
//! # When the audit entry is written
//!
//! The rule is that no response leaves the process before its audit entry is stored,
//! and no *change* is made before it either. Those two pull in different directions,
//! so reads and writes differ deliberately:
//!
//! **Both record the authorization decision before doing the work.** Reads and writes
//! differ only in what happens afterwards:
//!
//! - **Reads** record the decision, then read, then respond. If the audit fails nothing
//!   is read and the client gets `503`; the value never left the process. When the read
//!   then finds nothing, or fails, a *second* entry records the real outcome, so the
//!   trail does not imply a value was served.
//! - **Writes** record the decision before touching the store, because the alternative
//!   is mutating it and then discovering the audit trail is unavailable — exactly the
//!   unlogged access this project exists to prevent. If the mutation then fails, a
//!   second entry records that, sharing the request id so the two read as one event.
//!
//! An earlier version of this paragraph said reads do the work *first* and audit
//! afterwards. They never did. The wording is corrected rather than the code, because
//! recording first is the stronger property — and someone "fixing" the code to match
//! the old sentence would open the unlogged-read window it was describing.
//!
//! Either way, a request whose entry no device accepted is refused. That is
//! fail-closed, and it is the reason a full audit volume is an outage rather than a
//! logging gap.
//!
//! # Blocking work in async handlers
//!
//! SQLite calls run inline rather than on a blocking pool. They are microseconds at
//! this data volume, and the store is behind a mutex anyway because SQLite serializes
//! writes — moving the work to another thread would add a hop without removing the
//! contention. The locks are never held across an `await`.

#[cfg(feature = "honeypot_alert")]
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ciphr_audit::{Action, AuditError, AuditSink, Entry, Principal, RequestContext};
use ciphr_core::{Capability, SecretPath};
use ciphr_crypto::{RootKey, TokenPepper};
use ciphr_policy::{Decision, PolicySet};
use ciphr_store::{Authentication, SqliteStore};
use serde::Serialize;

use crate::error::ApiError;

/// Everything a handler needs, cheap to clone.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    store: Mutex<SqliteStore>,
    audit: Mutex<AuditSink>,
    policies: PolicySet,
    root: RootKey,
    pepper: TokenPepper,
    seal_id: String,
    key_source: String,
    /// Resolved at startup and immutable afterwards — not behind a `Mutex`, and that is
    /// the point rather than an optimization. ADR-20 rejects a route that flips an
    /// entry, and interior mutability here is what such a route would need.
    surface: crate::surface::Active,
    devices: Mutex<Vec<DeviceHealth>>,
    /// Which bait already has a latch pending or open, so that one piece of bait
    /// schedules one write and not one per touch (finding F5). Present only with the
    /// entry: without it nothing plants bait, and a set nothing ever inserts into is
    /// a field a later reader has to rule out.
    #[cfg(feature = "honeypot_alert")]
    latching: LatchClaims,
}

/// Which pieces of bait already have a latch pending or open.
///
/// A cache in front of an authoritative constraint, never the constraint itself: the
/// partial unique index on `tripwire` is what makes a second open trip impossible, and
/// this only decides whether it is worth asking. That order matters for every judgement
/// below — being wrong here costs duplicate work, and cannot produce a duplicate row.
///
/// Keyed by the pair the database is keyed by, the stored kind label and the reference, so
/// this set cannot disagree with the table about what one piece of bait is. It holds only
/// references that were planted, which is why it is bounded by the bait rather than by the
/// traffic.
#[cfg(feature = "honeypot_alert")]
#[derive(Default)]
struct LatchClaims {
    held: Mutex<HashSet<(&'static str, String)>>,
}

#[cfg(feature = "honeypot_alert")]
impl LatchClaims {
    /// Take the claim for one piece of bait, or report that something else holds it.
    ///
    /// `true` means this caller is the one that should schedule the latch write. `false`
    /// means a write is already pending or has already opened the trip, so there is
    /// nothing left to write and nothing worth queueing.
    ///
    /// A poisoned lock is answered by granting the claim rather than by refusing it: a
    /// task panicked while holding the set, and the safe direction is the one that still
    /// writes the trip. The duplicate work is what this type exists to avoid, not what it
    /// exists to prevent.
    fn claim(&self, kind: ciphr_store::BaitKind, reference: &str) -> bool {
        let mut held = match self.held.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        held.insert((kind.as_str(), reference.to_owned()))
    }

    /// Give a claim back, for a latch that was scheduled and could not be written.
    ///
    /// Only that case. Releasing after a *successful* write would let the next touch
    /// queue a task for a trip that is already open, which is the whole of F5.
    fn release(&self, kind: ciphr_store::BaitKind, reference: &str) {
        let mut held = match self.held.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        held.remove(&(kind.as_str(), reference.to_owned()));
    }
}

/// Whether one audit device accepted the most recent record.
///
/// Reported by `/v1/health`, which is why it carries a name and a boolean and nothing
/// else. The reason a device gave for refusing belongs in the operator's logs, not on
/// an unauthenticated endpoint: a device failure message names a path or a database.
///
/// **The name is a label and not the configured path**, which is finding F14 of the
/// review of 2026-08-24. A device names itself `sqlite:/var/lib/ciphr/ciphr.db` or
/// `file:/var/log/ciphr/audit.log`, and publishing that on an unauthenticated endpoint
/// hands anyone who can reach the port the location of the database and the audit file.
/// Those are not secrets, but they are free reconnaissance, and the sentence directly
/// above — that a *failure reason* is withheld because it names a path — was being
/// contradicted two fields away.
///
/// `accepting` is `None` until the first record is written. "Nothing has been recorded
/// yet" and "the last record was accepted" are different states, and a monitor that
/// cannot tell them apart reports a healthy second device on a service that has never
/// written to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceHealth {
    /// The published label: `sqlite-1`, `file-1`, `file-2`, in configuration order.
    ///
    /// Numbered within its kind **even when there is one of that kind**. A monitor keys
    /// on this string, and a label that gained a suffix the day a second file device was
    /// configured would break the rule that was watching the first one.
    pub name: String,
    /// What the device calls itself, carrying the configured path.
    ///
    /// The key `note_device_outcome` matches a [`ciphr_audit::DeviceFailure`] against,
    /// and a [`ciphr_audit::Quarantined`] against, and the reason this is a separate field
    /// rather than the one above. Never serialized.
    #[serde(skip)]
    pub source: String,
    /// Whether it accepted the last record it was asked to store. `None` before the
    /// first one, and frozen at `false` once the device is quarantined — from then on it
    /// is not asked, and reporting `true` for a device nobody wrote to would be the
    /// clearest possible way to hide this.
    pub accepting: Option<bool>,
    /// The first sequence number this device is known to have missed, if it has missed
    /// one. `None` for a device that is still being written to.
    ///
    /// **This is the field to alert on.** A deployment runs two devices so that it has
    /// two copies; a value here means it has one, and the second is frozen at whatever it
    /// held. Finding F6 of the review of 2026-08-24.
    ///
    /// A number and never a reason: a device failure message names a path, and this route
    /// is unauthenticated — the same rule the failure reasons already follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_from: Option<u64>,
}

/// Turn the devices' own names into stable published labels.
///
/// The kind is the part before the first `:` — how both device constructors build their
/// names — and anything unexpected becomes `device`, so a device kind added later is
/// labelled rather than leaking whatever it called itself.
fn device_labels(names: &[&str]) -> Vec<String> {
    let mut seen: Vec<(String, usize)> = Vec::new();
    names
        .iter()
        .map(|name| {
            let kind = match name.split_once(':') {
                Some((kind, _)) if !kind.is_empty() => kind,
                _ => "device",
            };
            let count = if let Some((_, count)) = seen.iter_mut().find(|(known, _)| known == kind) {
                *count += 1;
                *count
            } else {
                seen.push((kind.to_owned(), 1));
                1
            };
            format!("{kind}-{count}")
        })
        .collect()
}

/// A honeypot token that was presented (ADR-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bait {
    /// The bait's non-secret identifier.
    pub token_id: String,
    /// The identity it was issued for — which bait was taken.
    pub identity: String,
}

/// Why a request has no caller.
///
/// Carries the error *and*, separately, whether the credential was bait. The split is
/// the point: the error is what the client is told and is produced without consulting
/// the credential's nature, so a caller cannot accidentally answer bait differently.
/// [`Bait`] only ever reaches the audit trail.
///
/// `Debug` only: [`ApiError`] is not `Clone` or `Eq`, and giving it those to make this
/// comparable would widen a type on the response path for a test's convenience.
#[derive(Debug)]
pub struct Rejection {
    /// What the client is told. Identical for bait and for anything else invalid.
    pub error: ApiError,
    /// Set when the presented credential matched a stored honeypot token.
    pub bait: Option<Bait>,
}

impl Rejection {
    /// A rejection with no bait involved.
    pub fn plain(error: ApiError) -> Self {
        Self { error, bait: None }
    }
}

/// Who is making a request, once their token has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The identity name, as it appears in the policy file.
    pub identity: String,
    /// The non-secret identifier of the token used.
    pub token_id: String,
    /// `machine` or `human`, if the policy file says.
    pub kind: Option<String>,
}

impl Caller {
    fn as_principal(&self) -> Principal {
        Principal {
            name: self.identity.clone(),
            kind: self.kind.clone(),
            token_id: Some(self.token_id.clone()),
        }
    }
}

impl AppState {
    /// Assemble the state. The root key and pepper are held for the process lifetime;
    /// there is no re-seal in v1.
    pub fn new(
        store: SqliteStore,
        audit: AuditSink,
        policies: PolicySet,
        root: RootKey,
        seal_id: String,
        key_source: String,
        surface: crate::surface::Active,
    ) -> Self {
        let pepper = TokenPepper::derive(&root);
        // Both asked before the sink is moved. The quarantine list matters at startup
        // because a device can be stopped before this process writes anything:
        // `AuditSink::new` compares each device with the chain it resumed from, so one
        // that missed records while an earlier process ran is stopped before the first
        // request arrives. Health has to say that from the start rather than from the
        // first write.
        let sources = audit.device_names();
        let stopped = audit.quarantined();
        let devices = device_labels(&sources)
            .into_iter()
            .zip(sources.iter())
            .map(|(name, source)| DeviceHealth {
                // Matched on the device's own name, which is what the sink reports --
                // never on the published label.
                quarantined_from: stopped
                    .iter()
                    .find(|one| one.device == *source)
                    .map(|one| one.missed_from),
                name,
                source: (*source).to_owned(),
                // `None` and not `false`: nothing has been written yet, so "did not
                // accept the last record" is not a fact about any device here -- a
                // quarantined one missed records that somebody else wrote.
                accepting: None,
            })
            .collect();

        Self {
            inner: Arc::new(Inner {
                store: Mutex::new(store),
                audit: Mutex::new(audit),
                policies,
                root,
                pepper,
                seal_id,
                key_source,
                surface,
                devices: Mutex::new(devices),
                #[cfg(feature = "honeypot_alert")]
                latching: LatchClaims::default(),
            }),
        }
    }

    /// The policy set, for the read-only administrative endpoints.
    pub fn policies(&self) -> &PolicySet {
        &self.inner.policies
    }

    /// The root key, for decrypting a value that has just been read.
    pub fn root_key(&self) -> &RootKey {
        &self.inner.root
    }

    /// Which seal mechanism this store uses, for the health endpoint.
    /// Where *this process* read its master key: `env`, `file`, or `supplied`.
    ///
    /// Reported separately from the stored seal identifier, because the two legitimately
    /// differ while a deployment is moving from one source to the other — and that is
    /// exactly when an operator needs to see which one is actually in use.
    pub fn key_source(&self) -> &str {
        &self.inner.key_source
    }

    /// The seal mechanism recorded in the store — what sealed it, rather than what this
    /// process is configured with. See [`AppState::key_source`] for the difference.
    pub fn seal_id(&self) -> &str {
        &self.inner.seal_id
    }

    /// The optional surface this process is running (ADR-20).
    ///
    /// Resolved once at startup and never afterwards: an entry is a decision recorded
    /// on the host, and a process that could change its own surface would be a process
    /// whose surface an adversary can change.
    pub fn surface(&self) -> &crate::surface::Active {
        &self.inner.surface
    }

    /// What each audit device did with the most recent record, for the health endpoint.
    ///
    /// A snapshot rather than a borrow, because the state changes on every request. If
    /// the lock is poisoned the names are still reported, with `accepting` unknown:
    /// health is the endpoint an operator reaches for when something is wrong, so it
    /// answers as much as it can rather than failing.
    pub fn audit_devices(&self) -> Vec<DeviceHealth> {
        self.inner
            .devices
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Record what the sink reported, so `/v1/health` can be asked about it.
    ///
    /// Called on both paths. A partial failure is the case this exists for: the record
    /// was stored somewhere, the request succeeds, and without this the fact that one
    /// device refused would be discarded — which is how a second device that has been
    /// failing for a month becomes a second device that does not exist.
    fn note_device_outcome(
        &self,
        failures: &[ciphr_audit::DeviceFailure],
        quarantined: &[ciphr_audit::Quarantined],
    ) {
        let Ok(mut guard) = self.inner.devices.lock() else {
            return;
        };
        for device in guard.iter_mut() {
            // Both matched on `source`, the name the sink reports, and never on the
            // published label -- the label is for whoever reads health, this is the join
            // key.
            if let Some(stopped) = quarantined
                .iter()
                .find(|stopped| stopped.device == device.source)
            {
                device.quarantined_from = Some(stopped.missed_from);
            }

            // **A quarantined device is not asked, and therefore does not report `true`.**
            // Without this the next successful record would find it absent from the
            // failure list -- because it was skipped -- and mark it as accepting again,
            // which is precisely the "green health over a broken copy" half of F6.
            if device.quarantined_from.is_some() {
                device.accepting = Some(false);
                continue;
            }
            device.accepting = Some(!failures.iter().any(|f| f.device == device.source));
        }
    }

    /// Run something against the store.
    ///
    /// # Errors
    ///
    /// Whatever the closure returns, plus [`ApiError::Internal`] if the store lock is
    /// poisoned — which means another request panicked while holding it, and
    /// continuing would be operating on unknown state.
    pub fn with_store<T>(
        &self,
        work: impl FnOnce(&mut SqliteStore) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let mut guard = self.inner.store.lock().map_err(|_| ApiError::Internal {
            detail: "the store lock is poisoned".to_owned(),
        })?;
        work(&mut guard)
    }

    /// Authenticate a bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Unauthenticated`] for a missing, malformed, unknown,
    /// expired, or revoked token — all of them identical, so that probing learns
    /// nothing.
    pub fn authenticate(&self, bearer: Option<&str>) -> Result<Caller, Rejection> {
        let Some(presented) = bearer else {
            return Err(Rejection::plain(ApiError::Unauthenticated));
        };

        let outcome = self
            .with_store(|store| {
                store
                    .authenticate(presented, &self.inner.pepper)
                    .map_err(ApiError::from)
            })
            .map_err(Rejection::plain)?;

        let authenticated = match outcome {
            Authentication::Valid(authenticated) => authenticated,
            Authentication::Invalid => return Err(Rejection::plain(ApiError::Unauthenticated)),
            // The one place bait is distinguished, and it decides only what is
            // recorded. The error is the same value the line above returns, produced
            // here rather than derived from anything about the credential.
            Authentication::Bait { token_id, identity } => {
                return Err(Rejection {
                    error: ApiError::Unauthenticated,
                    bait: Some(Bait { token_id, identity }),
                });
            }
        };

        let kind = self
            .inner
            .policies
            .identity(&authenticated.identity)
            .map(|identity| identity.kind().as_str().to_owned());

        Ok(Caller {
            identity: authenticated.identity,
            token_id: authenticated.token_id,
            kind,
        })
    }

    /// Ask the policy evaluator. Records nothing — auditing is the caller's next step.
    pub fn authorize(
        &self,
        caller: &Caller,
        capability: Capability,
        path: &SecretPath,
    ) -> Decision {
        self.inner
            .policies
            .evaluate(&caller.identity, path, capability)
    }

    /// Store one audit entry.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::AuditUnavailable`] if no device accepted the record. The
    /// caller must abandon the request: this is the fail-closed path.
    pub fn record(&self, entry: &Entry) -> Result<(), ApiError> {
        let mut sink = self.inner.audit.lock().map_err(|_| ApiError::Internal {
            detail: "the audit lock is poisoned".to_owned(),
        })?;

        let outcome = sink.record(entry, now_millis());
        // The sink's lock is released before the device state is touched, so the two
        // are never held at once and cannot deadlock against each other.
        drop(sink);

        match outcome {
            Ok(written) => {
                self.note_device_outcome(&written.failures, &written.quarantined);
                self.explain_the_gap(&written.failures);
                Ok(())
            }
            Err(AuditError::AllDevicesFailed { failures }) => {
                // No quarantine: nothing was committed, so no device missed anything.
                self.note_device_outcome(&failures, &[]);
                Err(ApiError::AuditUnavailable)
            }
            Err(_) => Err(ApiError::AuditUnavailable),
        }
    }

    /// Authorize an access and audit the decision in one step.
    ///
    /// Returns `Ok(())` only if the policy allows it *and* the decision was recorded.
    /// A denial is audited and then reported as [`ApiError::Forbidden`]; an audit
    /// failure is reported as [`ApiError::AuditUnavailable`] whichever way the
    /// decision went.
    ///
    /// This is the gate for operations that change something, where the record has to
    /// exist before the change does.
    ///
    /// # Errors
    ///
    /// [`ApiError::Forbidden`] or [`ApiError::AuditUnavailable`], as above.
    pub fn authorize_and_record(
        &self,
        caller: &Caller,
        action: Action,
        capability: Capability,
        path: &SecretPath,
        request: &RequestContext,
    ) -> Result<(), ApiError> {
        self.authorize_and_record_subject(caller, action, capability, path, None, request)
    }

    /// The same gate, naming what the operation was performed *on*.
    ///
    /// One caller today: revoking a token (ADR-24). The principal is who acted and the
    /// subject is whose credential stopped working, and the trail needs both — a revoke
    /// entry that does not name the token cannot answer "when did *this* credential stop
    /// working", which is the question `Action::RevokeToken` exists for.
    ///
    /// The shape matches what the CLI already records for the same operation, so a trail
    /// reader does not have to know whether a revocation came from the host or over the
    /// API to find the token id.
    ///
    /// # Errors
    ///
    /// As [`Self::authorize_and_record`].
    pub fn authorize_and_record_subject(
        &self,
        caller: &Caller,
        action: Action,
        capability: Capability,
        path: &SecretPath,
        subject: Option<Principal>,
        request: &RequestContext,
    ) -> Result<(), ApiError> {
        let decision = self.authorize(caller, capability, path);

        // Bait, asked about *after* the decision and never inside it (ADR-15 property
        // 2). The evaluator was handed the same question it always gets; there is no
        // honeypot branch in `ciphr-policy`, no new capability, and nothing here can
        // change what the policy decided.
        //
        // Only for an allowed read. A denial means nobody reached the bait, and ADR-15
        // is explicit that a denial trips nothing; a write or a delete reads no value.
        // `Capability::Read` is exactly "this route serves a value" in this system,
        // since listing and version history authorize as `Capability::List`.
        //
        // The lookup costs one indexed row for every allowed read, bait or not, which
        // is the point rather than an accident: property 1's second sanctioned option is
        // that the path absorbs the same cost either way. In a build without the entry
        // there is no lookup at all, which is what "a deployment that plants none pays
        // nothing" means.
        #[cfg(feature = "honeypot_alert")]
        let bait = if decision.is_allowed() && capability == Capability::Read {
            self.with_store(|store| store.honeypot_tier(path).map_err(ApiError::from))?
        } else {
            None
        };

        let mut entry = if decision.is_allowed() {
            #[cfg(feature = "honeypot_alert")]
            match bait {
                // The trip *replaces* this entry's action rather than adding a second
                // entry, so a request that takes bait writes exactly what any other
                // request writes. The attempted action moves into `detail`, because
                // "they read" and "they exported" are different facts about a
                // compromise and the action field can only hold one of them.
                Some(_) => Entry::allowed(Action::HoneypotTriggered)
                    .with_detail(format!("attempted: {action}")),
                None => Entry::allowed(action),
            }
            #[cfg(not(feature = "honeypot_alert"))]
            Entry::allowed(action)
        } else {
            Entry::denied(
                action,
                decision
                    .reason
                    .map_or_else(|| "denied".to_owned(), |reason| reason.as_str().to_owned()),
            )
        };
        entry = entry.with_principal(caller.as_principal()).with_path(path);
        if let Some(subject) = subject {
            entry = entry.with_subject(subject);
        }
        if let Some(rule) = &decision.rule {
            entry = entry.with_rule(rule.policy.clone(), rule.pattern.clone());
        }

        let status = if decision.is_allowed() { 200 } else { 403 };
        entry = entry.with_request(RequestContext {
            http_status: Some(status),
            ..request.clone()
        });

        self.record(&entry)?;

        // The derived state, and only after the record is stored. If the trail refused
        // the entry the request is about to fail, and latching a trip nobody can read
        // about would leave `/v1/health` claiming something the trail cannot confirm.
        #[cfg(feature = "honeypot_alert")]
        if let Some(tier) = bait {
            self.latch_off_the_request_path(
                ciphr_store::BaitKind::Secret,
                path.as_str().to_owned(),
                Some(caller.identity.clone()),
                tier,
            );
        }

        if decision.is_allowed() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// Open a trip on one piece of bait without making the request wait for it.
    ///
    /// ADR-15's property 1 covers what follows the decision as well as the decision
    /// itself: a row is work an ordinary read does not do, so it must not sit on the path
    /// the caller can time. The write therefore moves to a blocking task and the handler
    /// returns without it.
    ///
    /// **A weaker claim than "after the response is flushed", stated rather than
    /// implied.** axum offers no post-flush hook here, so what is guaranteed is that the
    /// request no longer waits for the write — not that the write happens afterwards. The
    /// residue is contention: a caller who immediately issues a second request could in
    /// principle meet the store mutex held by this task. That is one lock acquisition
    /// against a millisecond-scale insert, and it is the honest limit of this approach.
    ///
    /// **One task per piece of bait, and not one per touch.** Finding F5 of
    /// `docs/assurance/reviews/review-2026-08-21-current-tree.md`: every touch used to schedule a task,
    /// including touches of bait whose trip is already open, and those tasks serialize on
    /// the store mutex — so anyone who could reach known bait could queue work against
    /// authentication, reads and health checks. The database's partial index stopped the
    /// duplicate *rows* and bounded nothing else. [`LatchClaims`] is what bounds it now:
    /// the first touch of a reference schedules, every later one returns here after a set
    /// lookup.
    ///
    /// What that bound is worth saying plainly, because it is not a queue length: work in
    /// flight is limited by the number of distinct pieces of bait, which is a number an
    /// operator chose when planting them. It is not limited by how often anybody touches
    /// them — and that is the half which is reachable from outside, without authenticating
    /// at all once token bait latches.
    ///
    /// Failures are swallowed here and visible in the trail instead. This is outside the
    /// fail-closed contract by the dated decision in ADR-15: the authoritative record is
    /// the entry that was already stored above, and refusing the request because a
    /// *derived* row could not be written would make bait and non-bait answer
    /// differently — the one thing property 1 forbids.
    #[cfg(feature = "honeypot_alert")]
    fn latch_off_the_request_path(
        &self,
        kind: ciphr_store::BaitKind,
        reference: String,
        identity: Option<String>,
        tier: ciphr_store::HoneypotTier,
    ) {
        if !self.inner.latching.claim(kind, &reference) {
            return;
        }

        let state = self.clone();
        let work = move || {
            let latched = state.with_store(|store| {
                store
                    .latch_trip(kind, &reference, identity.as_deref(), tier)
                    .map_err(ApiError::from)
            });
            // `Ok(false)` -- already open -- is not an error and needs no branch. It is
            // the latch doing its job, which ADR-15 asked for so that one piece of bait
            // cannot page somebody on a schedule.
            //
            // A failure does get one: the trail says the latch is missing rather than
            // the state going quietly wrong, which is the same shape as the entry a
            // refusing audit device produces. The claim goes back with it, so a transient
            // database failure costs this latch and not every later one on the same bait:
            // a claim kept after a failed write would suppress exactly the retry the
            // bait still needs.
            if latched.is_err() {
                state.inner.latching.release(kind, &reference);
                let entry = Entry::denied(Action::HoneypotTriggered, "latch-failed")
                    .with_detail("the trip was recorded and the latch was not");
                let _ = state.record(&entry);
            }
        };

        // No runtime means no request path to keep clear, so the work is done inline.
        // That is the case in a test that drives the state directly rather than through
        // the router, and doing it inline there is what makes such a test able to see
        // the result at all.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(work);
            }
            Err(_) => work(),
        }
    }

    /// Whether any tripwire is currently open, for `/v1/health`.
    ///
    /// A boolean and a count, never which bait: plan section 10 lets an unauthenticated
    /// endpoint say what the process is doing and not what is stored. *That* a tripwire
    /// fired is the first; *which* bait was taken is the second, and it stays behind the
    /// administrative read and the audit trail.
    ///
    /// **`None` when the store cannot be asked**, which is finding F9 of the review of
    /// 2026-08-24. This used to answer `(false, 0)` on any store or lock error, so a
    /// database failure *during an incident* produced an affirmative "nothing has been
    /// taken" from an endpoint that could establish no such thing — the one moment the
    /// answer matters, answered wrongly and confidently. Health is still the endpoint an
    /// operator reaches for when something is wrong and it still answers as much as it
    /// can; what it may not do is invent the part it cannot reach.
    ///
    /// The trail is where a trip is authoritative; this is a convenience over it.
    #[cfg(feature = "honeypot_alert")]
    pub fn tripwire_state(&self) -> Option<(bool, usize)> {
        // A count, not the trips themselves: see `open_trip_count`.
        let open = self
            .with_store(|store| store.open_trip_count().map_err(ApiError::from))
            .ok()?;
        Some((open > 0, open))
    }

    /// Record that an authenticated caller's completed read had a different outcome
    /// than `200` — a path that turned out not to exist, for instance.
    ///
    /// Used where the work happens before the audit, so that the recorded status is
    /// the real one rather than the one the decision implied.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record.
    pub fn record_outcome(
        &self,
        caller: &Caller,
        action: Action,
        path: Option<&SecretPath>,
        request: &RequestContext,
        status: u16,
        reason: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut entry = match reason {
            None => Entry::allowed(action),
            Some(reason) => Entry::denied(action, reason),
        };
        entry = entry.with_principal(caller.as_principal());
        if let Some(path) = path {
            entry = entry.with_path(path);
        }
        entry = entry.with_request(RequestContext {
            http_status: Some(status),
            ..request.clone()
        });

        self.record(&entry)
    }

    /// Record that an authenticated caller was refused before any decision was reached.
    ///
    /// Finding F12 of the review of 2026-08-24. The trail had an inversion in it: an
    /// *invalid* credential produced an entry, by [`Self::record_rejection`], because
    /// that is how a brute-force attempt becomes visible at all — while a *valid*
    /// credential doing something malformed produced none. Somebody holding a stolen
    /// token and probing paths, routes or methods worked in silence, and the failed guess
    /// from outside did not.
    ///
    /// [`Action::RequestRefused`] and not a denial, because nothing was authorized and
    /// nothing was attempted against a path. A denial says the evaluator considered a
    /// request and said no; this says the request never reached it.
    ///
    /// **`attempted` goes in the detail and the input does not go anywhere.** The thing
    /// that was malformed is exactly the thing a caller controls, and putting unparseable
    /// bytes into the one artefact this project keeps tamper-evident is how a trail
    /// becomes an injection surface — the same argument F11 made about a parse error on
    /// the way out. Who, what they were attempting, and that it was refused is what the
    /// question afterwards is about.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record. Fail-closed like
    /// every other entry: a refusal nobody could record is not a refusal this service
    /// reports quietly.
    pub fn record_refusal(
        &self,
        caller: &Caller,
        attempted: Action,
        request: &RequestContext,
        status: u16,
        reason: &str,
    ) -> Result<(), ApiError> {
        let entry = Entry::denied(Action::RequestRefused, reason)
            .with_principal(caller.as_principal())
            .with_detail(format!("attempted: {attempted}"))
            .with_request(RequestContext {
                http_status: Some(status),
                ..request.clone()
            });

        self.record(&entry)
    }

    /// Run the work an allowed decision authorized, and record that it did not happen
    /// if it did not.
    ///
    /// The counterpart of [`Self::authorize_and_record`], and the reason it exists is
    /// finding F4 of the review of 2026-08-21: the correcting second entry was a rule
    /// each handler remembered for itself, so `read` and `write` had it and `delete`,
    /// `export`, and the version listing did not. Their trails said an authorized
    /// operation happened at `200` when it had not. The direction was conservative —
    /// over-claiming access, never under-claiming it — which is exactly why nobody
    /// noticed.
    ///
    /// `reason` is the label the second entry carries. `error.status()` is the status,
    /// so a call site cannot record one status while returning another.
    ///
    /// Note what a failure to record does here: it replaces the caller's error with
    /// [`ApiError::AuditUnavailable`]. That is deliberate and matches `write_secret`'s
    /// long-standing shape — a trail left over-claiming is the failure this whole
    /// module exists to prevent, so it is worth a different status code.
    ///
    /// # Errors
    ///
    /// Whatever `work` returned, or [`ApiError::AuditUnavailable`] if the correcting
    /// entry could not be stored.
    pub fn complete_or_record<T>(
        &self,
        caller: &Caller,
        action: Action,
        path: &SecretPath,
        request: &RequestContext,
        reason: &str,
        work: impl FnOnce() -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        match work() {
            Ok(value) => Ok(value),
            Err(error) => {
                self.record_outcome(
                    caller,
                    action,
                    Some(path),
                    request,
                    error.status().as_u16(),
                    Some(reason),
                )?;
                Err(error)
            }
        }
    }

    /// Record a listing, which authorizes **per returned path** rather than once.
    ///
    /// Deliberately not `record_outcome`: there is no decision to attach here, and an
    /// entry that looked like an allow while carrying no rule was a finding. The count
    /// is what the trail can honestly say about a listing — how much was revealed —
    /// and its presence is what marks the entry as not being a decision.
    ///
    /// Called *after* the listing is produced and *before* it is serialized, so a
    /// failure to record means nothing was revealed.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record.
    pub fn record_listing(
        &self,
        caller: &Caller,
        prefix: &SecretPath,
        request: &RequestContext,
        returned: usize,
    ) -> Result<(), ApiError> {
        let entry = Entry::allowed(Action::List)
            .with_principal(caller.as_principal())
            .with_path(prefix)
            .with_results(returned)
            .with_request(RequestContext {
                http_status: Some(200),
                ..request.clone()
            });
        self.record(&entry)
    }

    /// Write one entry per device that refused a record the others accepted.
    ///
    /// The chain advances when **any** device accepts, so a refusing device is missing
    /// that sequence number for good. Verifying its copy later reports a gap, which is
    /// the same signal the design defines as tampering — and the recovery procedure that
    /// follows from it commits whoever finds it to treating the surrounding accesses as
    /// unlogged. For a disk that was briefly full, that is an expensive wrong answer.
    ///
    /// These entries are what make the difference recoverable afterwards: the devices
    /// that *did* accept carry the reason the other one did not.
    ///
    /// Deliberately infallible and deliberately not recursive. It writes through the
    /// sink once and ignores the outcome — if that write also fails there is nothing
    /// further to try, and retrying or reporting would turn a degraded audit trail into
    /// a failed request that had already succeeded. The device state on `/v1/health` is
    /// the other half of this, and it does not depend on this write.
    fn explain_the_gap(&self, failures: &[ciphr_audit::DeviceFailure]) {
        if failures.is_empty() {
            return;
        }
        let Ok(mut sink) = self.inner.audit.lock() else {
            return;
        };
        for failure in failures {
            // The device name goes in the reason, because the name is what a later
            // reader needs: it identifies which copy has the gap. Not in `channel`,
            // which means where a request came from -- api, cli, mcp -- and would stop
            // being filterable if device names were mixed into it.
            //
            // The device's own error message is left out. It is an I/O string that
            // belongs in the operator's logs; the trail needs to say which copy is
            // incomplete, not why the disk was unhappy.
            let entry = Entry::denied(
                Action::AuditDeviceFailed,
                format!("device-refused: {}", failure.device),
            );
            let _ = sink.record(&entry, now_millis());
        }
    }

    /// Record which optional surface entries this process started with (ADR-20).
    ///
    /// One entry, at startup, before the listener is bound. `none` when a deployment
    /// turned nothing on — an empty string there would leave a reader unable to tell
    /// "nothing was active" from "this version did not record it", which is the same
    /// distinction the trail keeps everywhere else by writing nulls out.
    ///
    /// Inside the fail-closed contract on purpose: this is the entry that says what the
    /// process offers, and serving requests while unable to record that is the state the
    /// audit requirement exists to prevent.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record, which the
    /// caller turns into a refusal to start.
    pub fn record_surface(&self) -> Result<(), ApiError> {
        let entry = Entry::allowed(Action::SurfaceActive).with_detail(self.surface().summary());
        self.record(&entry)
    }

    /// Record an attempt that failed before any identity was established.
    ///
    /// A rejected credential is worth a line: it is how a brute-force attempt becomes
    /// visible. The entry has no principal, because there is nobody to name.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record.
    pub fn record_unauthenticated(
        &self,
        action: Action,
        request: &RequestContext,
    ) -> Result<(), ApiError> {
        let entry = Entry::denied(action, "unauthenticated").with_request(RequestContext {
            http_status: Some(401),
            ..request.clone()
        });
        self.record(&entry)
    }

    /// Record a rejected credential, saying so if it was bait.
    ///
    /// One entry either way, and the same one: for bait the *action* becomes
    /// `honeypot-triggered` and the attempted action moves into `detail`. Nothing is
    /// written beside the ordinary entry, because a second write is work an ordinary
    /// rejected credential does not cause and is therefore measurable — ADR-15's
    /// property 1 covers what follows the decision as well as the decision itself.
    ///
    /// Where `honeypot_alert` is not in the build this is `record_unauthenticated` with
    /// an argument it ignores, so a deployment that plants no bait runs exactly the code
    /// the accepted review read.
    ///
    /// # Errors
    ///
    /// [`ApiError::AuditUnavailable`] if no device accepted the record.
    pub fn record_rejection(
        &self,
        action: Action,
        request: &RequestContext,
        bait: Option<&Bait>,
    ) -> Result<(), ApiError> {
        #[cfg(feature = "honeypot_alert")]
        if let Some(bait) = bait {
            let entry = Entry::denied(Action::HoneypotTriggered, "unauthenticated")
                // Which bait, by the identity it was issued for and its non-secret id.
                // `subject` rather than `principal`: nobody authenticated, so there is
                // no actor to name, and the credential is what the entry is *about*.
                .with_subject(Principal {
                    name: bait.identity.clone(),
                    kind: None,
                    token_id: Some(bait.token_id.clone()),
                })
                // The route the bait was presented to. "They tried to read" and "they
                // tried to write" are different facts about a compromise, and replacing
                // the action would otherwise discard the difference.
                .with_detail(format!("attempted: {action}"))
                .with_request(RequestContext {
                    http_status: Some(401),
                    ..request.clone()
                });
            // The entry first and the derived state after it, the same order the secret
            // path uses and for the same reason: a latch nobody can read about would
            // leave `/v1/health` claiming something the trail cannot confirm.
            self.record(&entry)?;

            // Finding F1 of `docs/assurance/reviews/review-2026-08-21-current-tree.md`: this used to return
            // above, so a honeypot *token* wrote its entry and latched nothing.
            // `/v1/health` kept answering `tripped: false` with `open_tripwires: 0`, and
            // `/v1/honeypots` kept calling the credential untripped — so a deployment that
            // did all three things `honeypots.md` asks for still missed the event, and the
            // runbook's own sentence applied to the implementation rather than to a
            // misconfiguration: bait that cannot fire looks exactly like bait nobody took.
            //
            // The token id is the reference, because that is the column `tripwire` keys a
            // token trip on. **The identity is `None`, and that is not an omission:** the
            // column means who took the bait, and presenting a honeypot token authenticates
            // nobody -- which is what `TripResponse::identity` documents. Which bait it was
            // is the token id, and `/v1/honeypots` maps that to the identity it was issued
            // for. Writing that identity here instead would make the trip read as "deploy
            // took it", which is the one thing that did not happen.
            //
            // `Alert` by construction rather than by storage: a token row has no tier
            // column, because bait that authenticates nothing can never reach a tier that
            // acts on an identity (ADR-15, property 4).
            self.latch_off_the_request_path(
                ciphr_store::BaitKind::Token,
                bait.token_id.clone(),
                None,
                ciphr_store::HoneypotTier::Alert,
            );
            return Ok(());
        }

        // Named `_bait` in a build without the entry so the signature stays one shape:
        // the caller has one rejection path in both configurations, which is the point.
        let _ = bait;
        self.record_unauthenticated(action, request)
    }
}

/// Milliseconds since the Unix epoch, UTC.
pub(crate) fn now_millis() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The claim set, on its own.
///
/// It is a private type with three lines of logic, and it is tested here rather than
/// through the router for a reason worth stating: from the outside, deduplicating the
/// latch write is *invisible*. The end state is identical either way, because the
/// database's partial index already refused the second row — what changed is the work
/// that is no longer queued, and the only place to assert that is here.
#[cfg(all(test, feature = "honeypot_alert"))]
mod tests {
    use super::LatchClaims;
    use ciphr_store::BaitKind;

    #[test]
    fn one_claim_per_reference() {
        let claims = LatchClaims::default();

        assert!(
            claims.claim(BaitKind::Secret, "infra/db/PASSWORD"),
            "the first touch schedules the latch"
        );
        assert!(
            !claims.claim(BaitKind::Secret, "infra/db/PASSWORD"),
            "the second touch must not queue a second write -- this is finding F5"
        );
    }

    #[test]
    fn a_failed_write_can_be_retried() {
        let claims = LatchClaims::default();

        assert!(claims.claim(BaitKind::Token, "cph_id"));
        // What the task does when `latch_trip` fails: a claim kept here would suppress
        // every later attempt on bait whose trip was never actually opened.
        claims.release(BaitKind::Token, "cph_id");
        assert!(
            claims.claim(BaitKind::Token, "cph_id"),
            "a released claim can be taken again"
        );
    }

    #[test]
    fn the_two_kinds_do_not_share_a_reference() {
        let claims = LatchClaims::default();

        // `tripwire` keys a secret trip on `path` and a token trip on `token_id`, so the
        // same text in the two columns is two different pieces of bait. Keying this set
        // by the reference alone would silently drop one of them.
        assert!(claims.claim(BaitKind::Secret, "same-text"));
        assert!(claims.claim(BaitKind::Token, "same-text"));
    }
}

/// The labels `/v1/health` publishes for the audit devices.
///
/// Tested here rather than through the router because the interesting cases are shapes a
/// harness cannot easily configure: two devices of one kind, and a device whose name has
/// no `kind:` prefix at all.
#[cfg(test)]
mod label_tests {
    use super::device_labels;

    #[test]
    fn a_label_names_the_kind_and_never_the_path() {
        let labels = device_labels(&[
            "sqlite:/var/lib/ciphr/ciphr.db",
            "file:/var/log/ciphr/audit.jsonl",
            "file:/mnt/audit/audit.jsonl",
        ]);
        assert_eq!(labels, vec!["sqlite-1", "file-1", "file-2"]);
        assert!(
            !labels.iter().any(|label| label.contains('/')),
            "finding F14: no path reaches an unauthenticated endpoint"
        );
    }

    #[test]
    fn one_device_of_a_kind_is_still_numbered() {
        // The point of the suffix. A rule written against `file-1` today must not break
        // the day a second file device is configured and the label would otherwise have
        // to grow one.
        assert_eq!(
            device_labels(&["file:/var/log/audit.jsonl"]),
            vec!["file-1"]
        );
    }

    #[test]
    fn a_name_without_a_kind_still_gets_a_label() {
        // A device kind added later, or a test double. It is labelled rather than having
        // whatever it calls itself published -- which is the failure mode the whole
        // change exists to close.
        assert_eq!(
            device_labels(&["always-fails", "sqlite:/db", "also-odd"]),
            vec!["device-1", "sqlite-1", "device-2"]
        );
    }
}
