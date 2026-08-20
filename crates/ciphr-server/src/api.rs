//! The HTTP API: routes, handlers, and the shapes on the wire.
//!
//! Every route except `/v1/health` requires an authenticated identity, and every
//! authorization decision goes through the one evaluator in `ciphr-policy`. There is
//! no second mechanism for administrative endpoints: `/v1/audit`, `/v1/identities`,
//! and `/v1/policies` are authorized as the virtual paths `sys/audit`,
//! `sys/identities`, and `sys/policies`, which is why no `admin` capability exists to
//! be obtained by trickery (ADR-3).
//!
//! # Values are text
//!
//! A secret value is a UTF-8 string on the wire and in the store. That is a real
//! limitation, stated rather than worked around: a binary secret has to be encoded by
//! whoever stores it. The alternative — two representations, one text and one
//! base64 — means every client has to handle both, and the one that only handles text
//! fails on the value it was never tested with. One representation, no ambiguity.
//!
//! # Path routing
//!
//! Catch-all routes are never parsed for suffixes. `/v1/versions/{*path}` exists
//! instead of `/v1/secrets/{*path}/versions`, because a secret literally named
//! `foo/versions` would otherwise be indistinguishable from the version listing for
//! `foo` — the exact routing-versus-policy divergence ADR-9 warns about. Every
//! operation gets its own prefix.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use ciphr_audit::{Action, RequestContext};
use ciphr_core::{Capability, Plaintext, SecretPath, SecretVersion};
use ciphr_policy::IdentityKind;
use ciphr_store::{AuditFilter, Store};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::{AppState, Caller, DeviceHealth};

/// Paths under this prefix are virtual: they authorize administrative reads and can
/// never be secrets.
const RESERVED_PREFIX: &str = "sys";

/// The most audit entries one request will return.
const AUDIT_LIMIT_MAX: u32 = 1000;
/// How many audit entries a request returns if it does not say.
const AUDIT_LIMIT_DEFAULT: u32 = 100;

/// Build the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/secrets/{*path}", get(read_secret))
        .route("/v1/secrets/{*path}", put(write_secret))
        .route("/v1/secrets/{*path}", delete(delete_secret))
        .route("/v1/versions/{*path}", get(list_versions))
        .route("/v1/list/{*prefix}", get(list_paths))
        .route("/v1/export", post(export))
        .route("/v1/audit", get(read_audit))
        .route("/v1/identities", get(read_identities))
        .route("/v1/policies", get(read_policies))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// What `GET /v1/health` returns.
///
/// No inventory counts: an unauthenticated endpoint does not reveal how many secrets
/// exist, or whether any do.
#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    sealed: bool,
    seal: String,
    /// Where this process read its master key: `env`, `file`, or `supplied`.
    ///
    /// Not secret, and worth exposing: a deployment that means to keep its key out of
    /// the container configuration can check that it actually did, rather than assuming
    /// the configuration file it edited is the one in effect.
    key_source: String,
    audit_devices: Vec<DeviceHealth>,
    api_version: &'static str,
}

/// A secret value, on the way in or out.
#[derive(Debug, Deserialize, Serialize)]
struct SecretBody {
    /// The value, as UTF-8 text.
    value: String,
}

/// What `GET /v1/secrets/{path}` returns.
#[derive(Debug, Serialize)]
struct SecretResponse {
    path: String,
    version: u32,
    value: String,
    created_at: i64,
    created_by: String,
}

/// What `PUT /v1/secrets/{path}` returns.
#[derive(Debug, Serialize)]
struct WriteResponse {
    path: String,
    version: u32,
}

/// What `GET /v1/versions/{path}` returns.
///
/// An object rather than the bare array this used to be. The rotation class is a
/// property of the secret and not of any one version, so it has nowhere to live in
/// an array of versions — and a top-level JSON array cannot grow a field at all,
/// ever, which means the next piece of per-secret metadata would hit the same wall.
/// Changing the shape once, while there are two known consumers, is cheaper than
/// changing it every later time.
#[derive(Debug, Serialize)]
struct VersionsResponse {
    path: String,
    rotation: RotationResponse,
    versions: Vec<VersionResponse>,
}

/// How safe the secret is recorded to be to rotate.
///
/// Three fields rather than the class alone, and each earns its place. `needs_care`
/// keeps the rule about which classes are dangerous in one implementation instead of
/// being re-derived by every consumer -- a client that decided "anything but
/// `rotatable`" would be right today and wrong the moment a class is added. `advice`
/// is prose in a JSON payload, which is unusual and deliberate: the text is defined
/// next to the classification precisely so that whoever shows it shows it at the
/// moment of the decision, and a second copy in the viewer's TypeScript is a copy
/// that drifts silently from the one the CLI prints.
#[derive(Debug, Serialize)]
struct RotationResponse {
    class: String,
    needs_care: bool,
    advice: String,
}

/// One entry of `GET /v1/versions/{path}`.
#[derive(Debug, Serialize)]
struct VersionResponse {
    version: u32,
    created_at: i64,
    created_by: String,
    deleted: bool,
    destroyed: bool,
}

/// What `GET /v1/list/{prefix}` returns.
#[derive(Debug, Serialize)]
struct ListResponse {
    prefix: String,
    paths: Vec<String>,
}

/// What `POST /v1/export` accepts.
#[derive(Debug, Deserialize)]
struct ExportRequest {
    /// The paths to export. Explicit rather than a prefix: an export is the operation
    /// most likely to hand over more than intended, so it says what it wants.
    paths: Vec<String>,
}

/// What `POST /v1/export` returns.
#[derive(Debug, Serialize)]
struct ExportResponse {
    secrets: Vec<ExportedSecret>,
}

/// One exported secret.
#[derive(Debug, Serialize)]
struct ExportedSecret {
    path: String,
    version: u32,
    value: String,
}

/// Query parameters of `GET /v1/audit`.
#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
    after_seq: Option<u64>,
    since: Option<i64>,
    identity: Option<String>,
    path: Option<String>,
    decision: Option<String>,
}

/// What `GET /v1/audit` returns.
#[derive(Debug, Serialize)]
struct AuditResponse {
    /// Entries as stored: each `record` is the exact JSON that was hashed, so a client
    /// can verify the chain itself rather than trusting this endpoint.
    entries: Vec<AuditEntryResponse>,
}

/// One audit entry, as stored.
///
/// `record` is a raw value rather than a `serde_json::Value` on purpose, and the
/// difference is the whole promise of this endpoint. A `Value` is a sorted map, so
/// re-serializing one produces the record with its fields in alphabetical order — not the
/// order they were written and hashed in. The hash would then be unreproducible from what
/// this endpoint returns, while the documentation said a client could recompute it. A raw
/// value passes the stored bytes through untouched.
#[derive(Debug, Serialize)]
struct AuditEntryResponse {
    seq: u64,
    hash: String,
    record: Box<serde_json::value::RawValue>,
}

/// What `GET /v1/identities` returns.
#[derive(Debug, Serialize)]
struct IdentitiesResponse {
    identities: Vec<IdentityResponse>,
}

/// One identity, without anything secret.
#[derive(Debug, Serialize)]
struct IdentityResponse {
    name: String,
    kind: String,
    policies: Vec<String>,
}

/// What `GET /v1/policies` returns.
#[derive(Debug, Serialize)]
struct PoliciesResponse {
    policies: Vec<PolicyResponse>,
}

/// One policy and its rules.
#[derive(Debug, Serialize)]
struct PolicyResponse {
    name: String,
    rules: Vec<RuleResponse>,
}

/// One rule.
#[derive(Debug, Serialize)]
struct RuleResponse {
    path: String,
    capabilities: Vec<String>,
    /// Number of literal segments, which is what decides between two matching rules.
    specificity: usize,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/health` — the only route without authentication.
///
/// Returns seal and audit state, because an HTTP 200 alone cannot distinguish a
/// healthy service from a sealed one that answers but can serve nothing.
async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        // v1 unseals at startup or refuses to start, so a reachable server is an
        // unsealed one. The field exists because a Shamir or HSM seal (ADR-5) makes it
        // meaningful, and a client should not have to change shape when it does.
        sealed: false,
        seal: state.seal_id().to_owned(),
        key_source: state.key_source().to_owned(),
        audit_devices: state.audit_devices(),
        api_version: "v1",
    })
}

/// `GET /v1/secrets/{path}` — read a value.
///
/// The authorization decision is recorded first, then the read happens, then the
/// response is produced. If the audit fails nothing is read and the client gets `503`:
/// no value ever left the process. Any outcome other than a served value — not found,
/// undecryptable, not UTF-8 — gets a second entry, so the trail never implies a value
/// was served when none was.
async fn read_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<VersionQuery>,
) -> Result<Json<SecretResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let path = parse_path(&path)?;

    state.authorize_and_record(&caller, Action::Read, Capability::Read, &path, &request)?;

    let version = query.version()?;
    let stored = match state.with_store(|store| store.get(&path, version).map_err(ApiError::from)) {
        Ok(stored) => stored,
        Err(error) => {
            // The decision was allowed and is already recorded; this entry records
            // that the read found nothing, so the trail does not imply a value was
            // served.
            if matches!(error.status(), StatusCode::NOT_FOUND) {
                state.record_outcome(
                    &caller,
                    Action::Read,
                    Some(&path),
                    &request,
                    404,
                    Some("not-found"),
                )?;
            }
            return Err(error);
        }
    };

    // The same reasoning as the not-found branch above: the trail already says this
    // read was authorized, and without a second entry it would imply a value was
    // served. A read that could not be decrypted, or is not UTF-8, served nothing.
    let value = match decrypt_to_text(&state, &stored) {
        Ok(value) => value,
        Err(error) => {
            state.record_outcome(
                &caller,
                Action::Read,
                Some(&path),
                &request,
                error.status().as_u16(),
                Some("not-served"),
            )?;
            return Err(error);
        }
    };

    Ok(Json(SecretResponse {
        path: stored.path.as_str().to_owned(),
        version: stored.version.get(),
        value,
        created_at: stored.created_at,
        created_by: stored.created_by,
    }))
}

/// `PUT /v1/secrets/{path}` — write a new version.
///
/// The audit entry is written **before** the store changes. Mutating first and
/// discovering afterwards that nothing could be logged would be exactly the unlogged
/// access this project exists to prevent.
async fn write_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(body): Json<SecretBody>,
) -> Result<Json<WriteResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Write, &request)?;
    let path = parse_path(&path)?;
    reject_reserved(&path)?;

    state.authorize_and_record(&caller, Action::Write, Capability::Write, &path, &request)?;

    let plaintext = Plaintext::from(body.value.into_bytes());
    let root = state.root_key();
    let outcome = state.with_store(|store| {
        store
            .put(&path, &caller.identity, &mut |version| {
                ciphr_crypto::encrypt(root, &path, version, &plaintext)
            })
            .map_err(ApiError::from)
    });

    match outcome {
        Ok(version) => Ok(Json(WriteResponse {
            path: path.as_str().to_owned(),
            version: version.get(),
        })),
        Err(error) => {
            // The trail already says the write was authorized; this says it did not
            // happen. Two entries rather than one that over-claims.
            state.record_outcome(
                &caller,
                Action::Write,
                Some(&path),
                &request,
                error.status().as_u16(),
                Some("write-failed"),
            )?;
            Err(error)
        }
    }
}

/// `DELETE /v1/secrets/{path}` — soft-delete the current version.
///
/// Reversible, and audited before it happens. Destroying a version is not exposed
/// over HTTP at all: crypto-shredding is irreversible and belongs to the CLI on the
/// host (ADR-3).
async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<VersionQuery>,
) -> Result<StatusCode, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Delete, &request)?;
    let path = parse_path(&path)?;
    reject_reserved(&path)?;

    state.authorize_and_record(&caller, Action::Delete, Capability::Delete, &path, &request)?;

    let version = match query.version()? {
        Some(version) => version,
        None => state
            .with_store(|store| store.metadata(&path).map_err(ApiError::from))?
            .current_version
            .ok_or(ApiError::NotFound)?,
    };

    state.with_store(|store| store.delete(&path, version).map_err(ApiError::from))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/versions/{path}` — the version history of a secret, without values.
async fn list_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Json<VersionsResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::List, &request)?;
    let path = parse_path(&path)?;

    state.authorize_and_record(&caller, Action::List, Capability::List, &path, &request)?;

    // Both reads in one borrow of the store, and both fail identically for a path
    // that does not exist -- each goes through `require_secret` -- so carrying the
    // classification here changes no error behaviour.
    let (metadata, versions) = state.with_store(|store| {
        let metadata = store.metadata(&path)?;
        let versions = store.versions(&path)?;
        Ok::<_, ApiError>((metadata, versions))
    })?;

    Ok(Json(VersionsResponse {
        path: path.as_str().to_owned(),
        rotation: RotationResponse {
            class: metadata.rotation.as_str().to_owned(),
            needs_care: metadata.rotation.needs_care(),
            advice: metadata.rotation.advice().to_owned(),
        },
        versions: versions
            .into_iter()
            .map(|summary| VersionResponse {
                version: summary.version.get(),
                created_at: summary.created_at,
                created_by: summary.created_by,
                deleted: summary.deleted_at.is_some(),
                destroyed: summary.destroyed_at.is_some(),
            })
            .collect(),
    }))
}

/// `GET /v1/list/{prefix}` — the paths under a prefix.
///
/// # Why `list` is checked per result and not on the prefix
///
/// A prefix is not a path anyone holds a rule about. `infra/**` grants `list` on
/// everything *inside* `infra` and deliberately not on `infra` itself, because a rule
/// about a subtree should not silently be a rule about its parent. Authorizing the
/// prefix would therefore refuse `/v1/list/infra` to an identity that may list every
/// secret under it — which is either surprising or leads to policies that spell out
/// every intermediate node.
///
/// So the operation needs authentication, and **every returned path is authorized
/// individually**. A caller sees exactly the names they hold `list` on, and nothing
/// else: an empty array is what "you may list nothing here" looks like, and it is
/// indistinguishable from "there is nothing here" — which is the right answer to give
/// someone who is not allowed to know the difference.
///
/// The alternative considered and rejected was a special case in the evaluator, so
/// that a subtree grant would also authorize its prefix. Path-based authorization is
/// worth having only if there is one rule for how a decision is made, and a capability
/// with its own exception is the beginning of not having that.
async fn list_paths(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<Json<ListResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::List, &request)?;
    let prefix = parse_path(&prefix)?;

    // There is no single decision to record here: authorization runs per returned path,
    // so the listing is produced first and the entry carries how many paths it revealed.
    // Recording still happens before anything is serialized, so a failure to record
    // means nothing left the process.
    let paths = state.with_store(|store| store.list(Some(&prefix)).map_err(ApiError::from))?;
    let visible: Vec<String> = paths
        .into_iter()
        .filter(|path| {
            state
                .authorize(&caller, Capability::List, path)
                .is_allowed()
        })
        .map(|path| path.as_str().to_owned())
        .collect();

    state.record_listing(&caller, &prefix, &request, visible.len())?;

    Ok(Json(ListResponse {
        prefix: prefix.as_str().to_owned(),
        paths: visible,
    }))
}

/// `POST /v1/export` — several secrets in one call.
///
/// Produces **one audit entry per secret served**, never one per call. A collective
/// entry for a bulk read is exactly the blind spot that disqualified other candidates
/// during the evaluation, so it is authorized and recorded path by path.
async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;

    if body.paths.is_empty() {
        return Err(ApiError::BadRequest {
            reason: "no paths requested".to_owned(),
        });
    }

    let mut secrets = Vec::with_capacity(body.paths.len());
    for raw in body.paths {
        let path = parse_path(&raw)?;

        // Per path: authorize, record, then read. A single refusal fails the whole
        // export rather than returning a partial answer, so a caller cannot use it to
        // map which paths they may read.
        state.authorize_and_record(&caller, Action::Read, Capability::Read, &path, &request)?;

        let stored = state.with_store(|store| store.get(&path, None).map_err(ApiError::from))?;
        let plaintext = ciphr_crypto::decrypt(
            state.root_key(),
            &stored.path,
            stored.version,
            &stored.value,
        )?;
        let value =
            String::from_utf8(plaintext.expose().to_vec()).map_err(|_| ApiError::Internal {
                detail: "a stored value is not valid UTF-8; read it with the CLI".to_owned(),
            })?;

        secrets.push(ExportedSecret {
            path: stored.path.as_str().to_owned(),
            version: stored.version.get(),
            value,
        });
    }

    Ok(Json(ExportResponse { secrets }))
}

/// `GET /v1/audit` — read the audit trail.
///
/// Authorized as the virtual path `sys/audit` through the ordinary evaluator. Returns
/// each entry as the exact stored JSON plus its hash, so a client can verify the chain
/// rather than trusting this endpoint to have told the truth about it.
async fn read_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("audit");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Read,
        &virtual_path,
        &request,
    )?;

    let allowed = match query.decision.as_deref() {
        None => None,
        Some("allow") => Some(true),
        Some("deny") => Some(false),
        Some(_) => {
            return Err(ApiError::BadRequest {
                reason: "decision must be 'allow' or 'deny'".to_owned(),
            });
        }
    };

    let filter = AuditFilter {
        limit: query
            .limit
            .unwrap_or(AUDIT_LIMIT_DEFAULT)
            .clamp(1, AUDIT_LIMIT_MAX),
        after_seq: query.after_seq,
        since: query.since,
        identity: query.identity,
        path: query.path,
        allowed,
    };

    let rows = state.with_store(|store| store.audit_query(&filter).map_err(ApiError::from))?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        // `from_string` validates that the stored text is JSON and then keeps it exactly
        // as it is. Nothing here parses the record into fields: this endpoint's job is to
        // hand over the bytes that were hashed, and any structure it imposed on the way
        // would be structure a client has to undo before it can verify anything.
        let record = serde_json::value::RawValue::from_string(row.payload).map_err(|error| {
            ApiError::Internal {
                detail: format!("a stored audit record is not readable: {error}"),
            }
        })?;
        entries.push(AuditEntryResponse {
            seq: row.seq,
            hash: ciphr_core::hex::encode(&row.hash),
            record,
        });
    }

    Ok(Json(AuditResponse { entries }))
}

/// `GET /v1/identities` — who exists and what they hold.
///
/// Read-only, and authorized as `sys/identities`. Making misconfiguration visible
/// without making it creatable (ADR-3).
async fn read_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<IdentitiesResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("identities");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Read,
        &virtual_path,
        &request,
    )?;

    let identities = state
        .policies()
        .identities()
        .map(|identity| IdentityResponse {
            name: identity.name().to_owned(),
            kind: match identity.kind() {
                IdentityKind::Machine => "machine".to_owned(),
                IdentityKind::Human => "human".to_owned(),
            },
            policies: identity.policies().to_vec(),
        })
        .collect();

    Ok(Json(IdentitiesResponse { identities }))
}

/// `GET /v1/policies` — the rules, as loaded.
async fn read_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PoliciesResponse>, ApiError> {
    let request = request_context(&headers);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("policies");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Read,
        &virtual_path,
        &request,
    )?;

    let policies = state
        .policies()
        .policies()
        .map(|policy| PolicyResponse {
            name: policy.name().to_owned(),
            rules: policy
                .rules()
                .iter()
                .map(|rule| RuleResponse {
                    path: rule.pattern().as_str().to_owned(),
                    capabilities: rule
                        .capabilities()
                        .iter()
                        .map(|capability| capability.as_str().to_owned())
                        .collect(),
                    specificity: rule.pattern().specificity(),
                })
                .collect(),
        })
        .collect();

    Ok(Json(PoliciesResponse { policies }))
}

// ---------------------------------------------------------------------------
// Shared request handling
// ---------------------------------------------------------------------------

/// `?version=` on the routes that accept one.
#[derive(Debug, Default, Deserialize)]
struct VersionQuery {
    version: Option<u32>,
}

impl VersionQuery {
    fn version(&self) -> Result<Option<SecretVersion>, ApiError> {
        match self.version {
            None => Ok(None),
            Some(number) => {
                SecretVersion::new(number)
                    .map(Some)
                    .ok_or_else(|| ApiError::BadRequest {
                        reason: "version must be greater than zero".to_owned(),
                    })
            }
        }
    }
}

/// Authenticate, recording the attempt if it fails.
fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    action: Action,
    request: &RequestContext,
) -> Result<Caller, ApiError> {
    match state.authenticate(bearer_token(headers)) {
        Ok(caller) => Ok(caller),
        Err(error) => {
            // A rejected credential is worth a line: it is how a brute-force attempt
            // becomes visible at all. If even that cannot be recorded, the request
            // fails as unavailable rather than as unauthenticated — the audit trail
            // being down is the more important fact.
            state.record_unauthenticated(action, request)?;
            Err(error)
        }
    }
}

/// The bearer token, if the request carries one.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// What the audit trail records about where a request came from.
///
/// `client_ip` comes from the connection, not from a forwarded header: a header a
/// client controls is a header a client can lie in, and an audit trail full of
/// attacker-chosen addresses is worse than one with none. A reverse proxy in front
/// therefore shows up as the client address, which is the truth about this hop.
fn request_context(headers: &HeaderMap) -> RequestContext {
    RequestContext {
        request_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(128).collect()),
        client_ip: None,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            // Truncated: a user agent is client-controlled, and an audit record should
            // not be a place to store a kilobyte of it.
            .map(|value| value.chars().take(256).collect()),
        http_status: None,
        channel: None,
    }
}

/// Decrypt a stored value and return it as text.
///
/// Split out so that both call sites treat "could not be served" as one case. The two
/// failures differ in cause and not in consequence: nothing reaches the client either
/// way, and the audit trail has to say so.
///
/// # Errors
///
/// Whatever `decrypt` returns, or [`ApiError::Internal`] if the plaintext is not UTF-8.
fn decrypt_to_text(
    state: &AppState,
    stored: &ciphr_store::StoredVersion,
) -> Result<String, ApiError> {
    let plaintext = ciphr_crypto::decrypt(
        state.root_key(),
        &stored.path,
        stored.version,
        &stored.value,
    )?;
    String::from_utf8(plaintext.expose().to_vec()).map_err(|_| ApiError::Internal {
        detail: "a stored value is not valid UTF-8; read it with the CLI".to_owned(),
    })
}

/// Parse a path from the route, mapping a rejection to `400` with the reason.
///
/// The reason is safe to return: it describes the request, and the rules are public.
fn parse_path(raw: &str) -> Result<SecretPath, ApiError> {
    SecretPath::parse(raw).map_err(|error| ApiError::BadRequest {
        reason: error.to_string(),
    })
}

/// Refuse writes and deletes under the reserved prefix.
///
/// `sys/**` names the virtual paths the administrative endpoints authorize against.
/// If a real secret could live there, a write would change what an authorization
/// decision means.
fn reject_reserved(path: &SecretPath) -> Result<(), ApiError> {
    if path.segments().next() == Some(RESERVED_PREFIX) {
        return Err(ApiError::BadRequest {
            reason: format!("'{RESERVED_PREFIX}/' is reserved and cannot hold secrets"),
        });
    }
    Ok(())
}

/// One of the virtual administrative paths.
///
/// # Panics
///
/// Cannot: the inputs are literals in this file, and they satisfy the path rules.
fn reserved_path(name: &str) -> SecretPath {
    SecretPath::parse(&format!("{RESERVED_PREFIX}/{name}"))
        .expect("the reserved paths are valid by construction")
}

#[cfg(test)]
mod tests {
    use super::{parse_path, reject_reserved, reserved_path};

    #[test]
    fn the_reserved_prefix_cannot_hold_secrets() {
        for path in ["sys/audit", "sys/anything/deeper"] {
            let parsed = parse_path(path).expect("valid path");
            assert!(
                reject_reserved(&parsed).is_err(),
                "{path} must be refused for writes"
            );
        }

        // Segment-aware: `system/...` is not under `sys/`.
        let ordinary = parse_path("system/config").expect("valid");
        assert!(reject_reserved(&ordinary).is_ok());
    }

    #[test]
    fn the_virtual_paths_are_the_documented_ones() {
        assert_eq!(reserved_path("audit").as_str(), "sys/audit");
        assert_eq!(reserved_path("identities").as_str(), "sys/identities");
        assert_eq!(reserved_path("policies").as_str(), "sys/policies");
    }

    #[test]
    fn a_malformed_path_is_a_bad_request_with_a_usable_reason() {
        let error = parse_path("infra//a").expect_err("must be refused");
        let reason = format!("{error:?}");
        assert!(reason.contains("empty segment"), "got {reason}");
    }
}
