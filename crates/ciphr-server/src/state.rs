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

use std::sync::{Arc, Mutex};

use ciphr_audit::{Action, AuditError, AuditSink, Entry, Principal, RequestContext};
use ciphr_core::{Capability, SecretPath};
use ciphr_crypto::{RootKey, TokenPepper};
use ciphr_policy::{Decision, PolicySet};
use ciphr_store::SqliteStore;
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
}

/// Whether one audit device accepted the most recent record.
///
/// Reported by `/v1/health`, which is why it carries a name and a boolean and nothing
/// else. The reason a device gave for refusing belongs in the operator's logs, not on
/// an unauthenticated endpoint: a device failure message names a path or a database.
///
/// `accepting` is `None` until the first record is written. "Nothing has been recorded
/// yet" and "the last record was accepted" are different states, and a monitor that
/// cannot tell them apart reports a healthy second device on a service that has never
/// written to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceHealth {
    /// The device name, as configured.
    pub name: String,
    /// Whether it accepted the last record. `None` before the first one.
    pub accepting: Option<bool>,
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
        let devices = audit
            .device_names()
            .into_iter()
            .map(|name| DeviceHealth {
                name: name.to_owned(),
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
    fn note_device_outcome(&self, failures: &[ciphr_audit::DeviceFailure]) {
        let Ok(mut guard) = self.inner.devices.lock() else {
            return;
        };
        for device in guard.iter_mut() {
            device.accepting = Some(!failures.iter().any(|f| f.device == device.name));
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
    pub fn authenticate(&self, bearer: Option<&str>) -> Result<Caller, ApiError> {
        let Some(presented) = bearer else {
            return Err(ApiError::Unauthenticated);
        };

        let authenticated = self.with_store(|store| {
            store
                .authenticate(presented, &self.inner.pepper)
                .map_err(ApiError::from)
        })?;

        let Some(authenticated) = authenticated else {
            return Err(ApiError::Unauthenticated);
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
                self.note_device_outcome(&written.failures);
                self.explain_the_gap(&written.failures);
                Ok(())
            }
            Err(AuditError::AllDevicesFailed { failures }) => {
                self.note_device_outcome(&failures);
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
        let decision = self.authorize(caller, capability, path);

        let mut entry = if decision.is_allowed() {
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
        if let Some(rule) = &decision.rule {
            entry = entry.with_rule(rule.policy.clone(), rule.pattern.clone());
        }

        let status = if decision.is_allowed() { 200 } else { 403 };
        entry = entry.with_request(RequestContext {
            http_status: Some(status),
            ..request.clone()
        });

        self.record(&entry)?;

        if decision.is_allowed() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
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
}

/// Milliseconds since the Unix epoch, UTC.
pub(crate) fn now_millis() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}
