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

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::{
    ConnectInfo, FromRef, FromRequest, FromRequestParts, Path, Query, Request, State,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use ciphr_audit::{Action, RequestContext};
use ciphr_core::path::RESERVED_PREFIX;
use ciphr_core::{Capability, Plaintext, Rotation, SecretPath, SecretVersion};
use ciphr_policy::IdentityKind;
use ciphr_store::{AuditFilter, Store};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::{AppState, Caller, DeviceHealth};

/// The most paths one `POST /v1/export` request may name.
///
/// Finding F5 of the review of 2026-08-24: `ExportRequest.paths` had no bound at all, so
/// one authenticated request could name a path ten thousand times and buy ten thousand
/// authorizations, durable audit writes, store reads and decryptions — each holding the
/// process-wide store and audit mutexes, and each keeping another plaintext copy for the
/// response. A late failure then added a *correcting* audit write per path already
/// processed. Denial of service by load is an accepted boundary here; supplying that much
/// amplification inside one request is not the same thing.
///
/// **256 is generous rather than tight**, and deliberately so. A container's environment
/// is a few dozen variables, and the fetching consumers — `ciphr-run` and `ciphr-ci` —
/// name one path per variable. A deployment that exceeds this is fetching a prefix wide
/// enough that it should say so in more than one request, and the refusal names the
/// limit so the remedy is obvious rather than a guess.
const EXPORT_PATHS_MAX: usize = 256;

/// The most plaintext one export response may carry, in bytes.
///
/// The other half of F5: the request body is bounded by the extractor, and that bounds
/// nothing about the response when a short path names a large value. Checked as the
/// values are read, so the process stops accumulating rather than discovering the total
/// while serializing it.
const EXPORT_BYTES_MAX: usize = 1024 * 1024;

/// The most audit entries one request will return.
const AUDIT_LIMIT_MAX: u32 = 1000;
/// How many audit entries a request returns if it does not say.
const AUDIT_LIMIT_DEFAULT: u32 = 100;

/// Build the router.
pub fn router(state: AppState) -> Router {
    // The routes every deployment gets. Everything below is a surface entry (ADR-20),
    // registered only where the configuration named it -- so "off" is a route axum
    // answers from the fallback rather than a handler that decides to refuse. An
    // `if enabled { … } else { 404 }` inside a live handler leaves it compiled, wired
    // and one boolean from serving, and makes the off state invisible to everything
    // except whoever can read the configuration file.
    let mut router = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/secrets/{*path}", get(read_secret))
        .route("/v1/secrets/{*path}", put(write_secret))
        .route("/v1/secrets/{*path}", delete(delete_secret))
        .route("/v1/versions/{*path}", get(list_versions))
        .route("/v1/list/{*prefix}", get(list_paths))
        // Always present, and deliberately not itself an entry: the mechanism is what
        // lists the entries, and a route that vanished when the list was empty would
        // make "nothing is on" and "this build has no surface mechanism" one answer.
        .route("/v1/surface", get(read_surface));

    // `viewer_api` -- the three routes that exist for a component which is already
    // optional (ADR-11). They put the policy structure and the identity inventory on
    // the network for anyone holding any token, and a deployment without the viewer has
    // been serving them to nobody. The CLI reads all three straight from the store, so
    // turning this off costs the viewer and nothing else.
    if state.surface().has("viewer_api") {
        router = router
            .route("/v1/audit", get(read_audit))
            .route("/v1/identities", get(read_identities))
            .route("/v1/policies", get(read_policies));
    }

    // `bulk_export` -- several named paths in one call, one audit entry each. Turning it
    // off costs `ciphr-run` entirely (both `--prefix` and `--path` fetch through here, so
    // it refuses with 125) and costs an SDK consumer one request per path.
    //
    // It does *not* decide whether this deployment has fetched prefixes for bait to stay
    // out of, and an earlier version of this comment said it did. `POST /v1/export` reads
    // the paths a caller names -- `ExportRequest` has no prefix -- so covering a prefix is
    // a property of the fetching code: a caller that lists `GET /v1/list/{prefix}`, which
    // is not an entry, and then reads each path covers the same prefix with this route off.
    // ADR-15's placement rule is therefore settled by reading the consumer, which is what
    // `docs/operations/honeypots.md` says.
    if state.surface().has("bulk_export") {
        router = router.route("/v1/export", post(export));
    }

    // `token_status` -- the authenticated answer to "is this credential still valid".
    // ADR-22 gave the host a read-only path to it, so this is not about answerability:
    // it is about the caller being an identity rather than `cli:$USER`, and the read
    // being in the trail. Its own entry rather than part of `viewer_api`, because which
    // credentials exist and which were never used is its own cost.
    if state.surface().has("token_status") {
        router = router.route("/v1/tokens", get(read_tokens));
    }

    // `token_revoke` -- the one write this API may do (ADR-24), and an entry because a
    // deployment that does not want a privileged write path over HTTP should not have
    // one. Off, revoking a leaked credential means stopping the service, which is what
    // the entry's cost sentence says and what `honeypots.md` step 3 describes.
    if state.surface().has("token_revoke") {
        router = router.route("/v1/tokens/{token_id}/revoke", post(revoke_token));
    }

    // `honeypot_alert` is a *build* entry, so the route hangs on the `cfg` and not on the
    // surface list. That asymmetry with the two above is the decision, not an oversight:
    // for a build entry there is no configuration-level off. `resolve` refuses to start a
    // service whose binary has the feature and whose configuration does not declare it, so
    // `has("honeypot_alert")` cannot be false where it would matter -- and a check that is
    // never false is worse than none, because a reader has to work out when it fires.
    //
    // The behaviour this route reports on is gated the same way, in
    // `AppState::authorize_and_record`. One condition for both, or the route and the
    // tripwire could disagree about whether bait is being watched.
    #[cfg(feature = "honeypot_alert")]
    {
        router = router.route("/v1/honeypots", get(read_honeypots));
    }

    // The two ways a request reaches no handler at all: a path no route matches, and a
    // method a matched route does not have. Both answered here rather than by axum's
    // silent defaults, so that an authenticated caller probing them leaves a trace
    // (finding F12). See `refused_request`.
    router
        .fallback(unmatched_route)
        .method_not_allowed_fallback(unmatched_method)
        // One response-header layer, over everything above: see `no_store`. Applied after
        // the routes rather than per route, so a route added later cannot forget it.
        .layer(axum::middleware::map_response(no_store))
        .with_state(state)
}

/// A path no route matches.
async fn unmatched_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    body: Body,
) -> ApiError {
    drain(body).await;
    refused_request(&state, &headers, origin, "unmatched-route")
}

/// A method the matched route does not have.
async fn unmatched_method(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    body: Body,
) -> ApiError {
    drain(body).await;
    refused_request(&state, &headers, origin, "unmatched-method")
}

/// Read and discard a request body a fallback is not going to look at.
///
/// **Answering a request without reading its body costs the connection.** The server
/// cannot keep a connection whose request it never finished reading, so it closes one it
/// would otherwise have kept. A client that has already returned that connection to its
/// pool can hand it out again before it sees the close, and the request that draws it
/// reports `Peer disconnected` -- a failure on a request that had nothing wrong with it.
///
/// One CI run failed with exactly that shape: `read_all` on a deployment without
/// `bulk_export` posts to an absent `/v1/export`, and the error landed two requests
/// later, on the prefix listing. It has not reproduced -- the same run was green on a
/// re-run of the same commit, and it does not reproduce locally with this code removed.
/// The change is here because the hazard is real whether or not it explains that run,
/// and reading a few kilobytes nobody wants is cheaper than a connection nobody can
/// keep.
///
/// **Bounded, because the alternative is a place to send gigabytes to.** A body past the
/// limit is left unread and the connection closes, which is the right answer for a
/// request that was going nowhere anyway — the bound is there so an unmatched route
/// cannot be turned into a way to make this process read for as long as somebody wants
/// to write.
async fn drain(body: Body) {
    const DRAIN_MAX: usize = 64 * 1024;
    let _ = axum::body::to_bytes(body, DRAIN_MAX).await;
}

/// Answer a request that reached no handler, and record it if it carried a valid token.
///
/// Finding F12 of the review of 2026-08-24. Route and method probing produced no entry
/// whatsoever, so somebody with a stolen credential mapping this API's shape did it in
/// silence — while a *failed* authentication attempt was recorded, which is the wrong way
/// round.
///
/// **Only an authenticated caller is recorded, and that is a decision rather than an
/// oversight.** The trail is fail-closed: a full audit volume takes the service down. If
/// anonymous traffic wrote entries, anyone who can reach the listener could take the
/// deployment down by asking for pages that do not exist — turning a `404` into an
/// outage. An authenticated caller can already fill the trail with legitimate reads, so
/// recording them adds no capability that a valid token did not already carry.
///
/// The answer is `404` either way, and identical for both. Whether the path matched a
/// route is not something this API tells an unauthenticated caller.
fn refused_request(
    state: &AppState,
    headers: &HeaderMap,
    origin: Origin,
    reason: &str,
) -> ApiError {
    let request = request_context(headers, origin);
    let refused = ApiError::NotFound;

    // A credential that does not authenticate is treated exactly as an absent one: the
    // trail is fail-closed, so letting anybody write to it by making up a token and a URL
    // would turn a `404` into an outage. On a route that *exists*, a failed
    // authentication is still recorded -- that path predates this and is bounded by
    // having to know a route.
    //
    // The `Err` arm returns the audit failure rather than the `404`, which is
    // fail-closed like everywhere else: a refusal nobody could record must not be
    // answered quietly.
    if let Ok(caller) = state.authenticate(bearer_token(headers))
        && let Err(error) = state.record_refusal(
            &caller,
            Action::Read,
            &request,
            refused.status().as_u16(),
            reason,
        )
    {
        return error;
    }

    refused
}

/// Put `Cache-Control: no-store` on one response.
///
/// The router's only response-header layer, and it applies to every `/v1` response
/// including the errors and the fallbacks. Finding F3 of
/// `docs/assurance/reviews/review-2026-08-21-current-tree.md`: the server emitted no cache directive at all,
/// for plaintext reads and exports as much as for anything else. The viewer asked Fetch not
/// to cache *its own* request; the SDK, the CLI, browser private caches, reverse proxies and
/// everything else in the path were left with their defaults.
///
/// Caches usually treat an authenticated response conservatively. "Usually" is a
/// convention, and the argument against relying on it is already written one layer up, in
/// `docs/ui.md`: **a cached response to a secret read is a secret without an expiry date** —
/// which is why no service worker is allowed anywhere near the viewer. Until now the server
/// made that argument only in the browser, and only for one client.
///
/// **Everything, not only the value routes.** A `404` says a path does not exist and a `403`
/// says an identity may not read it; both are worth keeping out of a shared cache, and a
/// list of which routes deserve the header is a list somebody has to maintain correctly
/// forever. `no-store` and not `no-cache`: the first says do not write it down, the second
/// says revalidate before reuse, and the second is not the property wanted here.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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
    /// Which optional surface entries are active (ADR-20).
    ///
    /// Names only. Which entries are active is what the process *enforces*, so plan
    /// section 10 permits it here; the date and the reason are prose an operator wrote
    /// about their own environment and stay behind an authenticated read.
    ///
    /// Empty is the ordinary answer, and a monitor that cannot see the shape of the
    /// thing it monitors is watching a different system.
    surface: Vec<&'static str>,
    /// Whether a tripwire is open, and how many (ADR-15).
    ///
    /// `None` in a build without the `honeypot_alert` entry — absent rather than
    /// `false`, because "this build cannot detect bait" and "nothing has been taken" are
    /// different facts and a monitor that conflates them reports a working tripwire on a
    /// service that has none.
    ///
    /// A count and never a name. Plan section 10 lets an unauthenticated endpoint report
    /// what the process is doing, which is *that* something fired; *which* bait was taken
    /// is stored, and stays behind the administrative read and the trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    tripped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    open_tripwires: Option<usize>,
    /// What this process could not establish, by name. Empty and omitted in the ordinary
    /// case.
    ///
    /// Finding F9 of the review of 2026-08-24, and it exists because `tripped` is an
    /// `Option` that already means something: absent is "this build has no tripwire
    /// mechanism". A store failure would have had to borrow that absence and would have
    /// made the two indistinguishable — a monitor cannot tell "no such feature" from
    /// "the feature could not be read" if both are a missing field.
    ///
    /// So the absence keeps its meaning, `status` turns `degraded`, and this says which
    /// part is missing. A name and never a reason: a store error message names a
    /// database file, and this endpoint is unauthenticated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    degraded: Vec<&'static str>,
    api_version: &'static str,
}

/// A secret value, on the way in or out.
#[derive(Debug, Deserialize, Serialize)]
struct SecretBody {
    /// The value, as UTF-8 text.
    value: String,
    /// The rotation class to record, if the caller names one.
    ///
    /// `None` means unchanged, and that is the whole point of it being optional: a new
    /// path written without this field still lands `unclassified`, so the pessimistic
    /// default of section 8 is untouched by the existence of this field.
    ///
    /// A `String` rather than a `Rotation`, because rejecting an unknown class has to
    /// produce a `400` that names it rather than serde's own message about an untagged
    /// enum — and because the parse belongs beside the other request checks, before
    /// anything is recorded.
    #[serde(default)]
    rotation: Option<String>,
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

/// `?rotation=` on `GET /v1/list/{prefix}`.
#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    rotation: Option<String>,
}

/// What `GET /v1/list/{prefix}` returns.
///
/// `paths` and `entries` carry the same set in the same order. The duplication is
/// deliberate and it is compatibility, not indecision: `paths` is the v1 shape, and
/// `ciphr-run` is bind-mounted into images this project does not own (ADR-14), so a
/// wrapper on a host is routinely older than the service it calls. Turning `paths`
/// into a list of objects would break exactly that pair, at the moment a service is
/// starting and its secrets are not there. Adding a field breaks nobody — the SDK
/// does not set `deny_unknown_fields`.
#[derive(Debug, Serialize)]
struct ListResponse {
    prefix: String,
    paths: Vec<String>,
    entries: Vec<ListEntry>,
}

/// One row of `GET /v1/list/{prefix}`.
///
/// The class and nothing else. `needs_care` and `advice` are pure functions of it
/// ([`Rotation::needs_care`], [`Rotation::advice`]), so a client derives them instead
/// of receiving a paragraph of prose on every row of a listing.
///
/// This discloses nothing a caller could not already obtain. Every path here survived
/// a `list` check, and `GET /v1/versions/{path}` returns the same class against the
/// same capability — so this saves one request per secret rather than opening a door.
#[derive(Debug, Serialize)]
struct ListEntry {
    path: String,
    rotation: &'static str,
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

/// `?identity=` on `GET /v1/tokens`.
#[derive(Debug, Default, Deserialize)]
struct TokenQuery {
    identity: Option<String>,
}

/// What `GET /v1/tokens` returns.
#[derive(Debug, Serialize)]
struct TokensResponse {
    tokens: Vec<TokenResponse>,
}

/// One token, as the administrative read path may see it.
///
/// Timestamps are milliseconds since the Unix epoch, like every other timestamp on this
/// API. `state` is the derived word — `valid`, `expired`, `revoked` — and the three
/// timestamps it is derived from are here as well, so a consumer that wants to say "in
/// four days" rather than "valid" does not have to ask twice.
#[derive(Debug, Serialize)]
struct TokenResponse {
    token_id: String,
    identity: String,
    state: &'static str,
    created_at: i64,
    created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
    honeypot: bool,
}

/// What `POST /v1/tokens/{token_id}/revoke` returns.
///
/// The identity is in it because the caller revoked a token id and the question afterwards
/// is whose credential that was. `revoked_now` distinguishes the call that revoked from a
/// retry that found it already revoked — the store's `COALESCE` makes both succeed, and a
/// caller logging the difference can tell a repeat from a first attempt.
#[derive(Debug, Serialize)]
struct RevokeResponse {
    token_id: String,
    identity: String,
    revoked_now: bool,
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
    // Asked once. Two calls would be two store queries on a route something polls every
    // few seconds, which is the kind of cost that is invisible until it is the only
    // thing holding the store's mutex.
    //
    // Three states and not two. `Some(_)` is an answer; `None` in a build with the entry
    // means the store could not be asked; `None` in a build without it means there is
    // nothing to ask. The first two used to be the same value -- `(false, 0)` -- which is
    // finding F9: a store failure reported "nothing has been taken" rather than "I
    // cannot tell you", and it did it under `status: "ok"`.
    #[cfg(feature = "honeypot_alert")]
    let (tripwire, watching) = (state.tripwire_state(), true);
    #[cfg(not(feature = "honeypot_alert"))]
    let (tripwire, watching): (Option<(bool, usize)>, bool) = (None, false);

    let mut degraded = Vec::new();
    if watching && tripwire.is_none() {
        degraded.push("tripwires");
    }

    Json(Health {
        // `degraded` rather than a failing status code: the process is serving, and a
        // load balancer must not pull it out of rotation because one query failed. What
        // changes is what a *monitor* is told, which is the thing that was wrong.
        status: if degraded.is_empty() {
            "ok"
        } else {
            "degraded"
        },
        // v1 unseals at startup or refuses to start, so a reachable server is an
        // unsealed one. The field exists because a Shamir or HSM seal (ADR-5) makes it
        // meaningful, and a client should not have to change shape when it does.
        sealed: false,
        seal: state.seal_id().to_owned(),
        key_source: state.key_source().to_owned(),
        audit_devices: state.audit_devices(),
        surface: state.surface().names(),
        tripped: tripwire.map(|(any, _)| any),
        open_tripwires: tripwire.map(|(_, count)| count),
        degraded,
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
    origin: Origin,
    Path(path): Path<String>,
    Query(query): Query<VersionQuery>,
) -> Result<Json<SecretResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let path = parse_path_recorded(&state, &caller, Action::Read, &request, &path)?;

    state.authorize_and_record(&caller, Action::Read, Capability::Read, &path, &request)?;

    let version = query.version()?;
    let stored = match state.with_store(|store| store.get(&path, version).map_err(ApiError::from)) {
        Ok(stored) => stored,
        Err(error) => {
            // The decision was allowed and is already recorded; this entry records
            // that the read found nothing, so the trail does not imply a value was
            // served. Every error takes this branch, not only the 404: a store that
            // could not answer served no value either, and the narrower version of
            // this check was the residue named in finding F4.
            let reason = if matches!(error.status(), StatusCode::NOT_FOUND) {
                "not-found"
            } else {
                "not-served"
            };
            state.record_outcome(
                &caller,
                Action::Read,
                Some(&path),
                &request,
                error.status().as_u16(),
                Some(reason),
            )?;
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

/// `PUT /v1/secrets/{path}` — write a new version, and optionally record its class.
///
/// The audit entry is written **before** the store changes. Mutating first and
/// discovering afterwards that nothing could be logged would be exactly the unlogged
/// access this project exists to prevent.
///
/// # Why the class may be set here
///
/// `PUT` works against a running service; `ciphr rotation` needs the store lock and
/// therefore the service stopped. Without this field a no-downtime import lands an
/// estate in which every path says `unclassified` — nobody has looked at this — and
/// making that honest costs exactly the downtime the API path avoided. The two features
/// pulled against each other, and the pessimistic default is what made it visible.
///
/// It is not a wider privilege. `write` on the path is the capability for both, because
/// naming what a value is safe for is not more than setting the value, and the class
/// never reaches an authorization decision (section 8).
///
/// # Why it is a second audit entry
///
/// `classify`, beside the `write`, exactly as the CLI records it — see `classify` in
/// `ciphr-cli`, which exists because this drifted once already in the direction that
/// matters: a class that moves inside a `write` entry is a `breaks-data` downgraded to
/// `rotatable` with nothing in the trail saying so, immediately before the rotation that
/// destroys the data.
async fn write_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Path(path): Path<String>,
    AuditedJson(body): AuditedJson<SecretBody>,
) -> Result<Json<WriteResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Write, &request)?;
    let path = parse_path_recorded(&state, &caller, Action::Write, &request, &path)?;
    reject_reserved(&path)?;
    // Parsed here, with the other request checks: an unknown class is a fault in the
    // request, and refusing it before the authorization entry keeps the trail from
    // carrying an allowed write that was never going to happen. Unknown is never
    // defaulted -- defaulting to `rotatable` would turn a typo into "safe to rotate".
    let rotation = parse_rotation(body.rotation.as_deref())?;

    state.authorize_and_record(&caller, Action::Write, Capability::Write, &path, &request)?;

    // **Both decisions before the one mutation, and one mutation for both.** Finding F13
    // of the review of 2026-08-24. The class used to be a second store write after the
    // version had been committed, justified by the store answering `NotFound` for a class
    // on a path that does not exist yet -- true between two transactions, false inside
    // one. So a failure in the second write left the value stored, the class unset and an
    // error on the wire: automation reads an HTTP failure as "the requested state was not
    // established", and here it was established by half, missing the half that *says a
    // secret is unclassified*. A retry then wrote a second version of the same value.
    //
    // Recording the classify decision here rather than after the write keeps the house
    // rule that the decision precedes the change it authorizes. It costs an entry for a
    // classification that then does not happen -- which is exactly what the correcting
    // entry below is for, and what every other write on this route already does.
    if rotation.is_some() {
        // Through the same evaluator, so the entry carries its own decision and the
        // rule that allowed it. `write` again: this is the capability the field costs.
        state.authorize_and_record(
            &caller,
            Action::Classify,
            Capability::Write,
            &path,
            &request,
        )?;
    }

    let plaintext = Plaintext::from(body.value.into_bytes());
    let root = state.root_key();
    let outcome = state.with_store(|store| {
        store
            .put_with_rotation(&path, &caller.identity, rotation, &mut |version| {
                ciphr_crypto::encrypt(root, &path, version, &plaintext)
            })
            .map_err(ApiError::from)
    });

    let version = match outcome {
        Ok(version) => version,
        Err(error) => {
            // The trail already says the write was authorized; this says it did not
            // happen. Two entries rather than one that over-claims -- and where a class
            // was named, its decision needs the same correction, because nothing was
            // written for either. Same request id, so the entries read as one event.
            state.record_outcome(
                &caller,
                Action::Write,
                Some(&path),
                &request,
                error.status().as_u16(),
                Some("write-failed"),
            )?;
            if rotation.is_some() {
                state.record_outcome(
                    &caller,
                    Action::Classify,
                    Some(&path),
                    &request,
                    error.status().as_u16(),
                    Some("classify-failed"),
                )?;
            }
            return Err(error);
        }
    };

    Ok(Json(WriteResponse {
        path: path.as_str().to_owned(),
        version: version.get(),
    }))
}

/// `DELETE /v1/secrets/{path}` — soft-delete the current version.
///
/// Reversible, and audited before it happens. Destroying a version is not exposed
/// over HTTP at all: crypto-shredding is irreversible and belongs to the CLI on the
/// host (ADR-3).
///
/// A delete that does not happen — no such path, no current version, a store that
/// refuses — gets a second entry saying so, the way a failed write does. Without it the
/// trail claimed an authorized deletion at `200` for a secret that is still there
/// (finding F4).
async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Path(path): Path<String>,
    Query(query): Query<VersionQuery>,
) -> Result<StatusCode, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Delete, &request)?;
    let path = parse_path_recorded(&state, &caller, Action::Delete, &request, &path)?;
    reject_reserved(&path)?;

    state.authorize_and_record(&caller, Action::Delete, Capability::Delete, &path, &request)?;

    // Everything that can still fail goes inside, including the version query: a
    // malformed `?version=` is refused after the decision was recorded, so it needs the
    // correction as much as a missing path does.
    state.complete_or_record(
        &caller,
        Action::Delete,
        &path,
        &request,
        "delete-failed",
        || {
            let version = match query.version()? {
                Some(version) => version,
                None => state
                    .with_store(|store| store.metadata(&path).map_err(ApiError::from))?
                    .current_version
                    .ok_or(ApiError::NotFound)?,
            };

            state.with_store(|store| store.delete(&path, version).map_err(ApiError::from))
        },
    )?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/versions/{path}` — the version history of a secret, without values.
async fn list_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Path(path): Path<String>,
) -> Result<Json<VersionsResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::List, &request)?;
    let path = parse_path_recorded(&state, &caller, Action::List, &request, &path)?;

    state.authorize_and_record(&caller, Action::List, Capability::List, &path, &request)?;

    // Both reads in one borrow of the store, and both fail identically for a path
    // that does not exist -- each goes through `require_secret` -- so carrying the
    // classification here changes no error behaviour.
    //
    // The correction is the same rule as on reads and deletes. This handler was not in
    // finding F4's list, and it has F4's shape: a 404 here used to leave a lone
    // "allowed list, 200" behind.
    let (metadata, versions) =
        state.complete_or_record(&caller, Action::List, &path, &request, "not-listed", || {
            state.with_store(|store| {
                let metadata = store.metadata(&path)?;
                let versions = store.versions(&path)?;
                Ok::<_, ApiError>((metadata, versions))
            })
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
    origin: Origin,
    Path(prefix): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::List, &request)?;
    let prefix = parse_path_recorded(&state, &caller, Action::List, &request, &prefix)?;
    let wanted = parse_rotation(query.rotation.as_deref())?;

    // There is no single decision to record here: authorization runs per returned path,
    // so the listing is produced first and the entry carries how many paths it revealed.
    // Recording still happens before anything is serialized, so a failure to record
    // means nothing left the process.
    let listed = state.with_store(|store| {
        store
            .list_with_rotation(Some(&prefix))
            .map_err(ApiError::from)
    })?;
    let visible: Vec<ListEntry> = listed
        .into_iter()
        .filter(|secret| {
            state
                .authorize(&caller, Capability::List, &secret.path)
                .is_allowed()
        })
        // The class filter runs *after* authorization and never before it. The two
        // answer different questions -- what this caller may see, and what they asked
        // for -- and running the cheap one first would make the count below describe a
        // set that was never authorized.
        .filter(|secret| wanted.is_none_or(|class| secret.rotation == class))
        .map(|secret| ListEntry {
            path: secret.path.as_str().to_owned(),
            rotation: secret.rotation.as_str(),
        })
        .collect();

    // What was revealed, not what the caller was entitled to. A filtered listing
    // reveals the filtered set, so recording the count before the filter would
    // overstate every filtered read for as long as the trail is kept.
    state.record_listing(&caller, &prefix, &request, visible.len())?;

    Ok(Json(ListResponse {
        prefix: prefix.as_str().to_owned(),
        paths: visible.iter().map(|entry| entry.path.clone()).collect(),
        entries: visible,
    }))
}

/// `POST /v1/export` — several secrets in one call.
///
/// Produces **one audit entry per secret served**, never one per call. A collective
/// entry for a bulk read is exactly the blind spot that disqualified other candidates
/// during the evaluation, so it is authorized and recorded path by path.
///
/// # Why a failure corrects *every* entry this request wrote
///
/// One refusal or one missing path fails the whole export — a partial answer would let a
/// caller map which paths they may read, one call at a time. But the entries for the
/// paths that already succeeded are written by then, each saying "allowed read, 200",
/// and **not one of those values left the process**. Finding F4 of the review of
/// 2026-08-21: for a nine-path export that fails on the ninth, the trail claimed nine
/// reads that never happened.
///
/// So on any failure each path recorded by this request gets a second entry. That is
/// more entries than the alternative of correcting only the path that failed, and it is
/// the only version a reader can trust without knowing that this handler aborts as a
/// unit. The correction is bounded by the request: nothing loops beyond the paths asked
/// for.
async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    AuditedJson(body): AuditedJson<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;

    // **Every structural check before the first audit or store operation.** Finding F5
    // of the review of 2026-08-24. Parsing used to happen inside the loop, interleaved
    // with authorization and durable writes, so a request that was malformed in its
    // ninth path had already bought eight audit entries and eight decryptions -- and
    // then eight correcting entries on the way out. A request that this server will not
    // serve should cost it a parse and nothing else.
    // Recorded like every other refusal an authenticated caller earns (F12): the
    // structural check is still first and still costs a parse, but the caller no longer
    // gets to make this request in silence.
    let paths = match validate_export_paths(&body.paths) {
        Ok(paths) => paths,
        Err(refused) => {
            state.record_refusal(
                &caller,
                Action::Read,
                &request,
                refused.status().as_u16(),
                "malformed-export",
            )?;
            return Err(refused);
        }
    };

    // Every path whose decision is on the trail already. Recorded before the read it
    // authorizes, so a path is in here whether or not its value was produced.
    let mut recorded: Vec<SecretPath> = Vec::with_capacity(paths.len());

    match export_secrets(&state, &caller, &request, paths, &mut recorded) {
        Ok(secrets) => Ok(Json(ExportResponse { secrets })),
        Err(error) => {
            for path in &recorded {
                state.record_outcome(
                    &caller,
                    Action::Read,
                    Some(path),
                    &request,
                    error.status().as_u16(),
                    Some("not-served"),
                )?;
            }
            Err(error)
        }
    }
}

/// Every structural check an export request has to pass, before it costs anything.
///
/// Finding F5 of the review of 2026-08-24. Three rules, and the order matters only in
/// that all of them run before the first audit write:
///
/// - **Not empty.** The one check that was already here.
/// - **At most [`EXPORT_PATHS_MAX`].** See that constant for why the number is what it
///   is.
/// - **No duplicates, compared after parsing.** `a/b/C` and `a/b/C` are the obvious case;
///   the reason this compares the *parsed* form is that two spellings normalizing to one
///   path would otherwise slip past a textual check and buy the amplification anyway. A
///   duplicate is refused rather than deduplicated: a caller asking twice for one secret
///   has a bug, and quietly returning fewer entries than it asked for is how that bug
///   reaches production.
///
/// # Errors
///
/// [`ApiError::BadRequest`], naming the rule that refused and the path where relevant.
fn validate_export_paths(raw: &[String]) -> Result<Vec<SecretPath>, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::BadRequest {
            reason: "no paths requested".to_owned(),
        });
    }

    if raw.len() > EXPORT_PATHS_MAX {
        return Err(ApiError::BadRequest {
            reason: format!(
                "{} paths requested; at most {EXPORT_PATHS_MAX} in one export",
                raw.len()
            ),
        });
    }

    let mut paths: Vec<SecretPath> = Vec::with_capacity(raw.len());
    for one in raw {
        let path = parse_path(one)?;
        if paths.iter().any(|seen| seen.as_str() == path.as_str()) {
            return Err(ApiError::BadRequest {
                reason: format!("{} is requested more than once", path.as_str()),
            });
        }
        paths.push(path);
    }

    Ok(paths)
}

/// The body of [`export`], separated so that a failure anywhere in it has one place to
/// be caught.
///
/// `recorded` grows as decisions reach the trail. On the error path the caller uses it to
/// correct them; on the success path it is discarded, because every entry in it described
/// something that then happened.
fn export_secrets(
    state: &AppState,
    caller: &Caller,
    request: &RequestContext,
    paths: Vec<SecretPath>,
    recorded: &mut Vec<SecretPath>,
) -> Result<Vec<ExportedSecret>, ApiError> {
    let mut secrets = Vec::with_capacity(paths.len());
    let mut bytes = 0usize;
    for path in paths {
        // Per path: authorize, record, then read.
        state.authorize_and_record(caller, Action::Read, Capability::Read, &path, request)?;
        recorded.push(path.clone());

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

        // Checked as the values accumulate rather than after the last one: the point is
        // to stop holding plaintext, and a total discovered while serializing is a total
        // that is already in memory.
        bytes = bytes.saturating_add(value.len());
        if bytes > EXPORT_BYTES_MAX {
            return Err(ApiError::BadRequest {
                reason: format!(
                    "this export exceeds {EXPORT_BYTES_MAX} bytes of values; \
                     request fewer paths"
                ),
            });
        }

        secrets.push(ExportedSecret {
            path: stored.path.as_str().to_owned(),
            version: stored.version.get(),
            value,
        });
    }
    Ok(secrets)
}

/// What `GET /v1/surface` returns.
///
/// The record behind each active entry, in full: which entry, how it is switched on,
/// when the deployment accepted the cost, why, and what its absence would have cost.
///
/// Authenticated, unlike the names on `/v1/health`. Plan section 10's rule: an
/// unauthenticated endpoint may report what the process *enforces* and never what is
/// stored. Which entries are active is enforcement; the reason is prose an operator
/// wrote about their own environment.
#[derive(Debug, Serialize)]
struct SurfaceResponse {
    entries: Vec<SurfaceEntryResponse>,
}

/// `GET /v1/surface` — which optional surface this deployment turned on, and why.
///
/// Authorized as the virtual path `sys/surface`, through the ordinary evaluator (ADR-20).
/// No new capability: `read` on a virtual path, exactly as `sys/audit` works.
///
/// Not gated by any entry. The mechanism is always present — what is optional is what it
/// lists, and a deployment that turned nothing on gets an empty array rather than a 404.
/// A route that disappeared when the list was empty would make "nothing is on" and "this
/// build has no surface mechanism" the same answer.
async fn read_surface(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
) -> Result<Json<SurfaceResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("surface");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
        &virtual_path,
        &request,
    )?;

    let entries = state
        .surface()
        .entries()
        .iter()
        .map(SurfaceEntryResponse::from)
        .collect();
    Ok(Json(SurfaceResponse { entries }))
}

/// One active surface entry, as `GET /v1/surface` returns it.
#[derive(Debug, Serialize)]
struct SurfaceEntryResponse {
    /// The entry name, as a configuration writes it.
    entry: &'static str,
    /// `build` or `runtime`.
    kind: &'static str,
    /// The date the deployment accepted the cost.
    accepted: String,
    /// Why, in the operator's own words.
    reason: String,
    /// What its absence would cost.
    ///
    /// Ships with the binary rather than living in documentation, because ADR-20 asks
    /// for exactly that: the operator writes why they said yes, and the software says
    /// what they said yes to.
    cost: &'static str,
}

impl From<&crate::surface::ActiveEntry> for SurfaceEntryResponse {
    fn from(active: &crate::surface::ActiveEntry) -> Self {
        Self {
            entry: active.name,
            // Not a `match` on the two variants. That is what this was, and it made
            // `Kind::as_str` -- added so the host and the wire could not disagree -- the
            // second spelling rather than the only one.
            kind: active.kind.as_str(),
            accepted: active.accepted.clone(),
            reason: active.reason.clone(),
            cost: active.cost,
        }
    }
}

/// What `GET /v1/honeypots` returns.
#[cfg(feature = "honeypot_alert")]
#[derive(Debug, Serialize)]
struct HoneypotsResponse {
    /// Every piece of bait, secrets and tokens together.
    honeypots: Vec<HoneypotResponse>,
    /// Every trip that has not been cleared, newest first.
    open_trips: Vec<TripResponse>,
}

/// One piece of bait.
#[cfg(feature = "honeypot_alert")]
#[derive(Debug, Serialize)]
struct HoneypotResponse {
    /// `secret` or `token`.
    kind: &'static str,
    /// The path, for a honeypot secret.
    path: Option<String>,
    /// The non-secret token identifier, for a honeypot token. Never the token.
    token_id: Option<String>,
    /// The identity a honeypot token was issued for.
    identity: Option<String>,
    /// The tier. Always `alert` in this build.
    tier: &'static str,
    /// Whether a trip on this bait is currently open.
    tripped: bool,
}

/// One open trip.
#[cfg(feature = "honeypot_alert")]
#[derive(Debug, Serialize)]
struct TripResponse {
    tripped_at: i64,
    kind: &'static str,
    path: Option<String>,
    token_id: Option<String>,
    /// Who took it, when there was an authenticated identity.
    ///
    /// Null for a honeypot token: presenting bait authenticates nothing, so there is
    /// nobody to name.
    identity: Option<String>,
    tier: &'static str,
}

/// `GET /v1/honeypots` — which paths and tokens are bait, and what has been taken.
///
/// Authorized as the virtual path `sys/honeypots` (plan section 22). **This is the only
/// place the honeypot flag is ever visible.** It does not appear on a secret read, in
/// `/v1/list`, or in `/v1/versions`, because bait that announces itself to a caller is
/// not bait — and an operator who cannot tell bait from a real secret eventually rotates
/// it or builds a service on it, which destroys it just as thoroughly.
#[cfg(feature = "honeypot_alert")]
async fn read_honeypots(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
) -> Result<Json<HoneypotsResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("honeypots");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
        &virtual_path,
        &request,
    )?;

    // F4's shape once more, on the route whose subject is the bait inventory. Finding F8:
    // these two queries ran after an entry that already said "allowed read, 200" on
    // `sys/honeypots`, and nothing corrected it when either failed — so the trail could
    // claim the inventory was returned while the client got an error. No privilege
    // escalation, and still worth the fix: the entry that would be read while
    // reconstructing an incident is the one this route writes.
    let (bait, trips) = state.complete_or_record(
        &caller,
        Action::Read,
        &virtual_path,
        &request,
        "not-served",
        || {
            state.with_store(|store| {
                let bait = store.honeypots().map_err(ApiError::from)?;
                let trips = store.open_trips().map_err(ApiError::from)?;
                Ok((bait, trips))
            })
        },
    )?;

    let kind_of = |kind: ciphr_store::BaitKind| match kind {
        ciphr_store::BaitKind::Secret => "secret",
        ciphr_store::BaitKind::Token => "token",
    };

    Ok(Json(HoneypotsResponse {
        honeypots: bait
            .into_iter()
            .map(|entry| HoneypotResponse {
                kind: kind_of(entry.kind),
                path: entry.path,
                token_id: entry.token_id,
                identity: entry.identity,
                tier: entry.tier.as_str(),
                tripped: entry.tripped,
            })
            .collect(),
        open_trips: trips
            .into_iter()
            .map(|trip| TripResponse {
                tripped_at: trip.tripped_at,
                kind: kind_of(trip.kind),
                path: trip.path,
                token_id: trip.token_id,
                identity: trip.identity,
                tier: trip.tier.as_str(),
            })
            .collect(),
    }))
}

/// `GET /v1/audit` — read the audit trail.
///
/// Authorized as the virtual path `sys/audit` through the ordinary evaluator. Returns
/// each entry as the exact stored JSON plus its hash, so a client can verify the chain
/// rather than trusting this endpoint to have told the truth about it.
async fn read_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("audit");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
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

    // F4's shape again, on the endpoint whose own trail is the subject: a store that
    // cannot answer, or a record that is not readable, served nothing, and the decision
    // above already says "allowed read, 200" on `sys/audit`.
    let entries = state.complete_or_record(
        &caller,
        Action::Read,
        &virtual_path,
        &request,
        "not-served",
        || {
            let rows =
                state.with_store(|store| store.audit_query(&filter).map_err(ApiError::from))?;
            let mut entries = Vec::with_capacity(rows.len());
            for row in rows {
                // `from_string` validates that the stored text is JSON and then keeps it
                // exactly as it is. Nothing here parses the record into fields: this
                // endpoint's job is to hand over the bytes that were hashed, and any
                // structure it imposed on the way would be structure a client has to undo
                // before it can verify anything.
                let record =
                    serde_json::value::RawValue::from_string(row.payload).map_err(|error| {
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
            Ok(entries)
        },
    )?;

    Ok(Json(AuditResponse { entries }))
}

/// `GET /v1/identities` — who exists and what they hold.
///
/// Read-only, and authorized as `sys/identities`. Making misconfiguration visible
/// without making it creatable (ADR-3).
async fn read_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
) -> Result<Json<IdentitiesResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("identities");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
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
    origin: Origin,
) -> Result<Json<PoliciesResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("policies");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
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

/// `GET /v1/tokens` — the token inventory, without any token in it.
///
/// **What this adds is the authenticated answer, not the answer.** ADR-22 already made
/// `ciphr token list` read-only, so expiry, revocation state and last use are readable on
/// the host while the service runs. What the host path cannot do is name *who asked*: it
/// records nothing, and its principal would be `cli:$USER`, self-declared. Here the caller
/// is an authenticated identity, the read needs `inspect` on `sys/tokens` (ADR-23), and the
/// entry says so.
///
/// **Nothing secret is in the response and nothing derived from a secret.** `tokens()`
/// returns metadata columns only — no verifier — and the fields below are the record's own.
/// The `honeypot` flag is included because this is the administrative read path, which is
/// the one place ADR-15 allows bait to be visible: whoever presented it must not be able to
/// tell, and whoever operates the deployment has to be able to.
///
/// `?identity=` narrows it, the same argument `ciphr token list` takes.
async fn read_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Query(query): Query<TokenQuery>,
) -> Result<Json<TokensResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::Read, &request)?;
    let virtual_path = reserved_path("tokens");

    state.authorize_and_record(
        &caller,
        Action::Read,
        Capability::Inspect,
        &virtual_path,
        &request,
    )?;

    let now = crate::state::now_millis();
    let records = state.with_store(|store| {
        store
            .tokens(query.identity.as_deref())
            .map_err(ApiError::from)
    })?;

    let tokens = records
        .into_iter()
        .map(|record| TokenResponse {
            // Derived in `ciphr-store`, so this and `ciphr token list` cannot come to
            // disagree about what "valid" means.
            state: record.state_at(now).as_str(),
            token_id: record.token_id,
            identity: record.identity,
            created_at: record.created_at,
            created_by: record.created_by,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            revoked_at: record.revoked_at,
            honeypot: record.honeypot,
        })
        .collect();

    Ok(Json(TokensResponse { tokens }))
}

/// `POST /v1/tokens/{token_id}/revoke` — the one write this API may do (ADR-24).
///
/// **Why it exists at all.** Revoking a leaked credential otherwise means stopping the
/// service: `ciphr token revoke` takes the exclusive store lock the running server
/// holds, so the host path is stop, revoke, start — an outage at the one moment nobody
/// planned for, and `docs/operations/honeypots.md` fires exactly then. The server
/// already checks revocation live on every request (`AppState::authenticate`), so the
/// mechanism for instant revocation was built and only the path that writes the row was
/// missing.
///
/// **What keeps it narrow**, and each of these is a line ADR-24 drew rather than an
/// implementation detail: one token per request, authorized as `revoke` on `sys/tokens`
/// (ADR-23) and reachable through no other capability, behind a surface entry that is
/// off until a deployment names it, and **no master key involved** — a revocation sets
/// `revoked_at` and decrypts nothing. Issuing stays on the host, where a planned window
/// is an adequate answer, and `revoke-all` stays there too because one request that
/// invalidates every credential of an identity is an availability weapon.
///
/// **Idempotent**, by the SQL that was already there: `revoke_token` writes
/// `COALESCE(revoked_at, now)`, so a retry after a network failure cannot move the
/// timestamp. `revoked_now` in the response says which call did it.
async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    origin: Origin,
    Path(token_id): Path<String>,
) -> Result<Json<RevokeResponse>, ApiError> {
    let request = request_context(&headers, origin);
    let caller = authenticate(&state, &headers, Action::RevokeToken, &request)?;
    let virtual_path = reserved_path("tokens");

    // **Looked up before the decision is recorded, and the reason is not the CLI's.**
    // There the same order exists so that a revocation of a token that does not exist is
    // not recorded as one that did; the operator is trusted with the master key anyway.
    // Here the caller is not, so what matters is that the *outcome* of this read is not
    // observable before the capability check — the `404` below is returned only after
    // `authorize_and_record_subject` allowed the call, so whether a token id exists stays
    // unanswerable without `revoke` on `sys/tokens`. Reading first is what lets the entry
    // name the credential that stopped working.
    //
    // **One indexed row, not the inventory.** This used to be `tokens(None)` followed
    // by a linear search, so an identity without `revoke` still made the server
    // materialize every token in the deployment -- while holding the store's mutex --
    // before being told `403`. Finding F7 of the review of 2026-08-24. The ordering
    // above is unchanged and still correct; what was wrong was doing O(inventory) work
    // to answer a question the primary key answers.
    let record = state.with_store(|store| store.token(&token_id).map_err(ApiError::from))?;

    state.authorize_and_record_subject(
        &caller,
        Action::RevokeToken,
        Capability::Revoke,
        &virtual_path,
        record.as_ref().map(|found| ciphr_audit::Principal {
            name: found.identity.clone(),
            kind: None,
            token_id: Some(found.token_id.clone()),
        }),
        &request,
    )?;

    // An authorized request that named nothing. The entry above stands and carries no
    // subject, which is exactly the shape of "this id matched no credential" — worth
    // knowing that nobody should read such an entry as evidence the token existed.
    let Some(found) = record else {
        return Err(ApiError::NotFound);
    };

    // **The trail says the revocation was authorized; this makes sure it never says it
    // happened when it did not.** Finding F8 of the review of 2026-08-24: the store
    // write used to be a bare `?`, so a disk or lock failure returned `503` to the
    // caller and left an entry claiming an allowed revocation at `200` behind. An
    // incident responder reading that trail would be told a live credential was dead.
    //
    // `revoked_now` comes from the write itself for the other half of the same finding:
    // it used to be `found.revoked_at.is_none()`, read *before* the mutation, so two
    // concurrent calls both claimed to be the one that stopped the credential.
    let revoked_now = state.complete_or_record(
        &caller,
        Action::RevokeToken,
        &virtual_path,
        &request,
        "revoke-failed",
        || state.with_store(|store| store.revoke_token(&token_id).map_err(ApiError::from)),
    )?;

    Ok(Json(RevokeResponse {
        token_id,
        identity: found.identity,
        revoked_now,
    }))
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
        Err(rejection) => {
            // A rejected credential is worth a line: it is how a brute-force attempt
            // becomes visible at all. If even that cannot be recorded, the request
            // fails as unavailable rather than as unauthenticated — the audit trail
            // being down is the more important fact.
            //
            // **One rejection path, and bait does not get its own.** The recording is
            // told whether the credential was bait; the response is `rejection.error`
            // either way, and there is no second `return` for a honeypot to take. That
            // is ADR-15's indistinguishability as a property of the code's shape rather
            // than of somebody remembering it here.
            state.record_rejection(action, request, rejection.bait.as_ref())?;
            Err(rejection.error)
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

/// The address the listener saw, if it was told one.
///
/// An extractor rather than a parameter on every handler, and one that cannot fail: a
/// router driven without connection information -- every test in this crate uses
/// `oneshot` -- has no address to offer, and that is a missing field rather than a
/// failed request. `Infallible` says so in the type instead of in a comment.
/// `Copy`, because an extractor that holds one optional address is a value and not a
/// thing to borrow -- and because passing it by reference to read one field is what
/// `needless_pass_by_value` correctly objects to.
#[derive(Clone, Copy)]
pub(crate) struct Origin(Option<SocketAddr>);

impl<S> FromRequestParts<S> for Origin
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(address)| *address),
        ))
    }
}

/// `Json`, and an authenticated caller who sends a body it cannot parse leaves a trace.
///
/// The last gap F12 left open, and it was left open because it is the one refusal that
/// happens **outside** the handler entirely: axum runs the body extractor before the
/// handler and answers its rejection before the router fallback sees anything, so
/// neither of the two places that record a refused request could see it. A valid token
/// sending broken JSON was the last way to be turned away in silence.
///
/// # What it costs, and who pays
///
/// **Nothing on the path that works.** The body is parsed exactly once and the caller is
/// authenticated exactly once — in the handler, as before. Only a *failed* parse
/// authenticates here, which is a second authentication for a request that was never
/// going to be served.
///
/// **An anonymous caller still writes nothing**, the same rule the router fallback
/// follows and for the same reason: the trail is fail-closed, so letting anybody write to
/// it by posting garbage would turn a `400` into an outage.
///
/// # What the entry says
///
/// `request-refused`, reason `malformed-body`, and **not** what was in the body. That is
/// the whole point of the reason label: a body is caller-controlled bytes, and this is
/// the one artefact the project keeps tamper-evident. The rejection message still goes to
/// the caller, who sent it and already knows.
pub(crate) struct AuditedJson<T>(pub(crate) T);

/// What a request carrying this body was trying to do.
///
/// The extractor cannot know which route it is on, and the entry has to say `read` for a
/// malformed export and `write` for a malformed secret. Guessing one for both would put a
/// small untruth in the one artefact this project keeps tamper-evident -- and "attempted:
/// write" on a read is exactly the kind of thing a reader would later have to un-learn.
pub(crate) trait Attempted {
    /// The action the caller was attempting.
    const ACTION: Action;
}

impl Attempted for SecretBody {
    const ACTION: Action = Action::Write;
}

impl Attempted for ExportRequest {
    const ACTION: Action = Action::Read;
}

impl<T, S> FromRequest<S> for AuditedJson<T>
where
    T: serde::de::DeserializeOwned + Attempted,
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Kept before the body is consumed: the rejection path needs the headers to
        // authenticate and to build the request context, and `Json` takes the request
        // whole.
        let (mut parts, body) = request.into_parts();
        let origin = Origin::from_request_parts(&mut parts, state)
            .await
            .unwrap_or(Origin(None));
        let headers = parts.headers.clone();
        let request = Request::from_parts(parts, body);

        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let refused = ApiError::BadRequest {
                    reason: rejection.body_text(),
                };
                let state = AppState::from_ref(state);
                let context = request_context(&headers, origin);

                // As the router fallback: a credential that authenticates nobody is
                // treated as an absent one, and an audit failure is answered rather than
                // swallowed.
                if let Ok(caller) = state.authenticate(bearer_token(&headers))
                    && let Err(error) = state.record_refusal(
                        &caller,
                        T::ACTION,
                        &context,
                        refused.status().as_u16(),
                        "malformed-body",
                    )
                {
                    return Err(error);
                }

                Err(refused)
            }
        }
    }
}

/// What the audit trail records about where a request came from.
///
/// `client_ip` comes from the connection, not from a forwarded header: a header a
/// client controls is a header a client can lie in, and an audit trail full of
/// attacker-chosen addresses is worse than one with none. A reverse proxy in front
/// therefore shows up as the client address, which is the truth about this hop.
///
/// The address is the peer IP without the port, canonicalized so that an IPv4-mapped
/// IPv6 address is recorded the way an operator would search for it. The port is
/// per-connection noise, and a trail is read by grepping for a host.
fn request_context(headers: &HeaderMap, origin: Origin) -> RequestContext {
    RequestContext {
        request_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(128).collect()),
        client_ip: origin
            .0
            .map(|address| canonical_ip(address.ip()).to_string()),
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

/// `::ffff:10.0.0.7` and `10.0.0.7` are the same host, and only one of them is what
/// somebody types into a search. A dual-stack listener produces the mapped form for an
/// IPv4 peer, so without this the same client appears under two spellings in one trail.
fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
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

/// The same, for a caller who has already authenticated — and it leaves a trace.
///
/// Finding F12 of the review of 2026-08-24. Every handler authenticates and *then*
/// parses, so a valid token naming a path that is not a path produced a `400` and no
/// entry at all: the request got past authentication, did real work in the process, and
/// left nothing behind. An invalid token in the same position produces an entry, which
/// made the trail quieter about the credential that works than about the one that does
/// not.
///
/// Deliberately not folded into [`parse_path`]: that one is also used where nobody has
/// authenticated yet, and a function that sometimes writes to the audit trail depending
/// on which arguments it was handed is a function whose callers stop knowing what it
/// does.
///
/// # Errors
///
/// [`ApiError::BadRequest`] naming what was wrong with the path — the error describes the
/// request, so it is safe to return — or [`ApiError::AuditUnavailable`] if the refusal
/// could not be recorded, which is fail-closed like every other entry.
fn parse_path_recorded(
    state: &AppState,
    caller: &Caller,
    attempted: Action,
    request: &RequestContext,
    raw: &str,
) -> Result<SecretPath, ApiError> {
    match SecretPath::parse(raw) {
        Ok(path) => Ok(path),
        Err(error) => {
            let refused = ApiError::BadRequest {
                reason: error.to_string(),
            };
            state.record_refusal(
                caller,
                attempted,
                request,
                refused.status().as_u16(),
                "malformed-path",
            )?;
            Err(refused)
        }
    }
}

/// Parse an optional rotation class from a request body or a query parameter.
///
/// Absent stays absent — "unchanged" and not "the default", which is what keeps a write
/// without this field landing `unclassified` on a new path and leaving an existing class
/// alone. An unknown class is a `400` naming what was sent and what the classes are:
/// the error describes the request, so it is safe to return.
///
/// Note the asymmetry with the way out, which is deliberate. `Classification.class` is
/// an open string in every response, so a client is never broken by a class a later
/// service added; an input is closed, because accepting a class this build cannot
/// interpret would store a word that means nothing here.
fn parse_rotation(raw: Option<&str>) -> Result<Option<Rotation>, ApiError> {
    raw.map(|class| {
        Rotation::parse(class).map_err(|error| ApiError::BadRequest {
            reason: error.to_string(),
        })
    })
    .transpose()
}

/// Refuse writes and deletes under the reserved prefix.
///
/// `sys/**` names the virtual paths the administrative endpoints authorize against.
/// If a real secret could live there, a write would change what an authorization
/// decision means.
///
/// **This is not where the rule is enforced.** `ciphr-store` refuses the same paths,
/// so the CLI and any other caller are covered as well; until the review of
/// 2026-08-21 (finding F2) this check was the only one, and `ciphr put sys/audit`
/// walked past it. What it still buys is a `400` that names the reason before a
/// request does any work, rather than the same refusal surfacing from storage.
fn reject_reserved(path: &SecretPath) -> Result<(), ApiError> {
    ciphr_store::reject_reserved(path).map_err(|_| ApiError::BadRequest {
        reason: format!("'{RESERVED_PREFIX}/' is reserved and cannot hold secrets"),
    })
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
