//! Shared state, and the two things every request goes through.
//!
//! # When the audit entry is written
//!
//! The rule is that no response leaves the process before its audit entry is stored,
//! and no *change* is made before it either. Those two pull in different directions,
//! so reads and writes differ deliberately:
//!
//! - **Reads** do the work, then audit with the real outcome, then respond. If the
//!   audit fails the value is dropped and the client gets `503` — it never left the
//!   process, so nothing was served unlogged.
//! - **Writes** audit the authorized intent *first*, because the alternative is
//!   mutating the store and then discovering the audit trail is unavailable, which is
//!   exactly the unlogged access this project exists to prevent. If the mutation then
//!   fails, a second entry records that, sharing the request id so the two read as
//!   one event.
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

use ciphr_audit::{Action, AuditSink, Entry, Principal, RequestContext};
use ciphr_core::{Capability, SecretPath};
use ciphr_crypto::{RootKey, TokenPepper};
use ciphr_policy::{Decision, PolicySet};
use ciphr_store::SqliteStore;

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
    audit_devices: Vec<String>,
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
    ) -> Self {
        let pepper = TokenPepper::derive(&root);
        let audit_devices = audit
            .device_names()
            .into_iter()
            .map(str::to_owned)
            .collect();

        Self {
            inner: Arc::new(Inner {
                store: Mutex::new(store),
                audit: Mutex::new(audit),
                policies,
                root,
                pepper,
                seal_id,
                audit_devices,
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
    pub fn seal_id(&self) -> &str {
        &self.inner.seal_id
    }

    /// The configured audit device names, for the health endpoint.
    pub fn audit_devices(&self) -> &[String] {
        &self.inner.audit_devices
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

        match sink.record(entry, now_millis()) {
            Ok(_written) => Ok(()),
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
