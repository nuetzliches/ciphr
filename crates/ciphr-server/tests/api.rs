//! End-to-end tests of the HTTP API, through the real router.
//!
//! No mocks and no test mode: these drive the same routes, the same authentication,
//! the same evaluator, and the same audit sink that a deployment does. The one thing
//! they skip is TLS, because a TCP listener is not what any of these assertions are
//! about — the transport is covered by `tls_alpn.rs` and `crate::tls`.
//!
//! The test that matters most is [`every_endpoint_writes_an_audit_entry`]: it is what
//! makes "no response leaves the process before its audit entry is stored" a checked
//! property rather than a convention a future handler can quietly break.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use ciphr_audit::{AuditDevice, AuditSink, Chain, EncodedRecord};
use ciphr_core::{Plaintext, SecretPath};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, Token, TokenPepper};
use ciphr_server::{AppState, api};
use ciphr_store::{AuditFilter, SealState, SqliteAuditDevice, SqliteStore, Store};
use tower::ServiceExt;

const POLICIES: &str = r#"
[[identity]]
name     = "deploy"
kind     = "machine"
policies = ["infra"]

[[identity]]
name     = "auditor"
kind     = "human"
policies = ["audit"]

[[policy]]
name = "infra"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list", "write", "delete"]

  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []

[[policy]]
name = "audit"

  # `inspect` rather than `read` since ADR-23: these are control-plane paths, and a
  # capability about a secret on a rule that names `sys/` is refused at load time.
  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["inspect"]

  [[policy.rule]]
  path         = "sys/identities"
  capabilities = ["inspect"]

  [[policy.rule]]
  path         = "sys/policies"
  capabilities = ["inspect"]

  [[policy.rule]]
  path         = "sys/surface"
  capabilities = ["inspect"]

  [[policy.rule]]
  path         = "sys/honeypots"
  capabilities = ["inspect"]

  # Reading the inventory and the one control-plane mutation, as two capabilities on one
  # path (ADR-23, ADR-24). That they are separable is pinned in
  # `ciphr-policy/tests/decision_table.rs`; here the auditor holds both, so the tests
  # below are about the routes rather than about the evaluator.
  [[policy.rule]]
  path         = "sys/tokens"
  capabilities = ["inspect", "revoke"]
"#;

/// A running API, plus what a test needs to talk to it.
struct Harness {
    router: axum::Router,
    /// A token for `deploy`.
    deploy_token: String,
    /// A token for `auditor`.
    auditor_token: String,
    /// A honeypot token, planted for `deploy` (ADR-15). Authenticates nothing.
    bait_token: String,
    /// Where the database is, so a test can read the audit log independently.
    database: std::path::PathBuf,
    /// Kept alive so the directory is not removed while the test runs.
    _directory: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        Self::with_audit(AuditKind::Working)
    }

    fn with_audit(kind: AuditKind) -> Self {
        Self::build_harness(kind, Self::runtime_entries().into())
    }

    /// The two runtime entries a deployment with a viewer and prefix-fetching consumers
    /// turns on.
    ///
    /// The harness carries them because most tests here are about what those routes do,
    /// and a harness whose surface was empty would be testing the fallback. The
    /// *absence* has its own tests, which resolve their own surface rather than
    /// inheriting one — see `an_entry_that_is_not_named_has_no_route`.
    fn runtime_entries() -> ciphr_server::ActiveSurface {
        Self::resolve(&["viewer_api", "bulk_export"])
    }

    /// A surface holding exactly these entries.
    ///
    /// `surface::only` rather than `surface::resolve`: this composes a router in-process,
    /// which is not a deployment starting on a configuration, so ADR-20's rule that a
    /// compiled-in build entry must be *declared* does not apply — and without that, an
    /// all-features build would refuse to construct any harness that did not name
    /// `honeypot_alert`, in every test file.
    fn resolve(entries: &[&str]) -> ciphr_server::ActiveSurface {
        ciphr_server::surface::only(entries).expect("the names are entries")
    }

    /// A harness whose surface is exactly the entries named, and nothing else.
    fn with_surface(entries: &[&str]) -> Self {
        Self::build_harness(AuditKind::Working, Self::resolve(entries).into())
    }

    /// A harness that federates, with the providers written as they would be in a
    /// configuration file.
    ///
    /// The TOML rather than a builder, because what these tests are about is a
    /// deployment's configuration reaching the verifier -- and `[[oidc.key]]` nested
    /// under `[[oidc]]` is the part of that path most likely to be got wrong.
    fn with_federation(oidc: &str) -> Self {
        #[derive(serde::Deserialize)]
        struct Providers {
            oidc: Vec<ciphr_server::oidc::ProviderConfig>,
        }

        let parsed: Providers = toml::from_str(oidc).expect("the provider fixture parses");
        let federation =
            ciphr_server::oidc::Federation::resolve(&parsed.oidc).expect("the fixture resolves");

        Self::build_harness(
            AuditKind::Working,
            ciphr_server::Composition {
                // `token_status` beside it so a test can ask what the exchange put in
                // the inventory through the documented route rather than by opening the
                // database. A deployment that federates has a reason to want both.
                surface: Self::resolve(&["oidc_login", "token_status"]),
                federation,
            },
        )
    }

    fn build_harness(kind: AuditKind, composition: ciphr_server::Composition) -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let database = directory.path().join("store.db");

        let seal = StaticSeal::from_master_key(
            "CIPHR_MASTER_KEY",
            MasterKey::from_hex(&"11".repeat(32)).expect("valid"),
        );
        let root = RootKey::generate().expect("entropy");
        let root_id = RootKeyId::generate().expect("entropy");

        let mut store = SqliteStore::open(&database).expect("open");
        store
            .initialize(&SealState {
                seal_id: seal.id().to_owned(),
                wrapped_root_key: seal.rewrap(&root, root_id).expect("wrap"),
            })
            .expect("initialize");

        // Two tokens, issued the way the CLI will.
        let pepper = TokenPepper::derive(&root);
        let deploy = Token::generate().expect("entropy");
        let auditor = Token::generate().expect("entropy");
        store
            .issue_token(
                "deploy",
                &deploy,
                &pepper,
                "operator",
                None,
                ciphr_store::TokenPurpose::Credential,
            )
            .expect("issue");
        store
            .issue_token(
                "auditor",
                &auditor,
                &pepper,
                "operator",
                None,
                ciphr_store::TokenPurpose::Credential,
            )
            .expect("issue");

        // Bait, planted in every harness rather than in the one test that needs it.
        // Its presence must not change any other behaviour, and having it everywhere is
        // what would notice if it did.
        let bait = Token::generate().expect("entropy");
        store
            .issue_token(
                "deploy",
                &bait,
                &pepper,
                "operator",
                None,
                ciphr_store::TokenPurpose::Honeypot,
            )
            .expect("plant bait");

        // Seed one secret so reads have something to find.
        let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid");
        let value = Plaintext::from(&b"seeded"[..]);
        store
            .put(&path, "operator", &mut |version| {
                ciphr_crypto::encrypt(&root, &path, version, &value)
            })
            .expect("put");

        let devices: Vec<Box<dyn AuditDevice>> = match kind {
            AuditKind::Working => {
                vec![Box::new(
                    SqliteAuditDevice::open(&database).expect("audit device"),
                )]
            }
            AuditKind::Failing => vec![Box::new(AlwaysFails)],
            AuditKind::Partial => vec![
                Box::new(SqliteAuditDevice::open(&database).expect("audit device")),
                Box::new(AlwaysFails),
            ],
            AuditKind::Behind => vec![
                Box::new(SqliteAuditDevice::open(&database).expect("audit device")),
                Box::new(Behind),
            ],
        };
        // `Behind` reports a head of 1, so a chain resumed past that is what makes it
        // behind. Every other kind starts from a fresh chain, where nothing can be.
        let chain = if matches!(kind, AuditKind::Behind) {
            Chain::resume(4, [0u8; ciphr_audit::HASH_LEN])
        } else {
            Chain::new()
        };
        let sink = AuditSink::new(devices, chain).expect("sink");

        let policies = ciphr_policy::PolicySet::from_toml(POLICIES).expect("policies");
        let state = AppState::new(
            store,
            sink,
            policies,
            root,
            "static".to_owned(),
            "supplied".to_owned(),
            // Nothing unless a test asked for something, so no test inherits a shape it
            // did not choose.
            composition,
        );

        // What `Server::prepare` does, so a harness is not a shape production never
        // has. A no-op for every kind but `Behind`, where it is the thing under test:
        // no device is quarantined at startup unless one came back behind the chain.
        state
            .record_quarantined()
            .expect("the startup quarantine record");

        Self {
            router: api::router(state),
            deploy_token: deploy.expose_text().to_string(),
            auditor_token: auditor.expose_text().to_string(),
            bait_token: bait.expose_text().to_string(),
            database,
            _directory: directory,
        }
    }

    fn send(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(self.router.clone().oneshot(request))
            .expect("the router must answer");

        let status = response.status();
        let bytes = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(axum::body::to_bytes(response.into_body(), 1 << 20))
            .expect("body");

        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, body)
    }

    fn get(&self, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
        self.send(Self::build("GET", uri, token, None))
    }

    /// The response body as it arrived, without parsing it.
    ///
    /// Needed for exactly one property: that the audit endpoint hands back the bytes that
    /// were hashed. Parsing into a `serde_json::Value` sorts the fields, so a test that
    /// looks at a parsed body cannot see the difference between the stored record and a
    /// re-serialization of it — which is how that defect survived the test above it.
    fn get_text(&self, uri: &str, token: Option<&str>) -> (StatusCode, String) {
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(
                self.router
                    .clone()
                    .oneshot(Self::build("GET", uri, token, None)),
            )
            .expect("the router must answer");

        let status = response.status();
        let bytes = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(axum::body::to_bytes(response.into_body(), 1 << 20))
            .expect("body");

        (
            status,
            String::from_utf8(bytes.to_vec()).expect("the body is UTF-8"),
        )
    }

    /// The stored audit records as text, exactly as the device holds them.
    fn audit_payloads(&self) -> Vec<String> {
        let store = SqliteStore::open(&self.database).expect("reopen");
        store
            .audit_query(&AuditFilter {
                limit: 1000,
                ..AuditFilter::default()
            })
            .expect("query")
            .into_iter()
            .map(|row| row.payload)
            .collect()
    }

    fn build(
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        match body {
            None => builder.body(Body::empty()).expect("request"),
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .expect("request"),
        }
    }

    /// The same, with a body that is not required to be valid JSON.
    ///
    /// `build` takes a `serde_json::Value`, which cannot express the thing under test:
    /// a body the parser refuses. This one takes the bytes.
    fn build_raw(
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        match body {
            None => builder.body(Body::empty()).expect("request"),
            Some(raw) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(raw.to_owned()))
                .expect("request"),
        }
    }

    /// Mark an existing secret as bait, the way `ciphr honeypot add` will.
    ///
    /// Through the store rather than through the API, because marking bait is not an API
    /// operation: it happens on the host, for the same reason ADR-3 keeps policies off
    /// the network.
    #[cfg(feature = "honeypot_alert")]
    fn mark_as_bait(&self, path: &str) {
        let mut store = SqliteStore::open(&self.database).expect("reopen");
        let parsed = SecretPath::parse(path).expect("a valid path");
        store
            .set_honeypot(&parsed, Some(ciphr_store::HoneypotTier::Alert))
            .expect("mark as bait");
    }

    /// Read the audit log directly, as an operator would.
    fn audit_entries(&self) -> Vec<serde_json::Value> {
        let store = SqliteStore::open(&self.database).expect("reopen");
        store
            .audit_query(&AuditFilter {
                limit: 1000,
                ..AuditFilter::default()
            })
            .expect("query")
            .into_iter()
            .map(|row| serde_json::from_str(&row.payload).expect("stored record is JSON"))
            .collect()
    }
}

#[derive(Clone, Copy)]
enum AuditKind {
    Working,
    Failing,
    /// One device that works and one that refuses everything. The state a second
    /// device is actually in when it has quietly stopped accepting records.
    Partial,
    /// One device that works and one that comes back holding fewer records than the
    /// chain -- the startup case, and the one a deployment meets after an upgrade.
    Behind,
}

/// A device that comes back behind the chain, the way a volume that filled would.
///
/// It writes fine; what it reports is a head below the one the chain resumed from, which
/// is the state `AuditSink::new` compares for and the case a deployment meets on its
/// first start after an upgrade.
struct Behind;

impl AuditDevice for Behind {
    fn name(&self) -> &'static str {
        "file:/tmp/behind.jsonl"
    }

    fn head_seq(&self) -> Result<Option<u64>, String> {
        Ok(Some(1))
    }

    fn write(&mut self, _record: &EncodedRecord) -> Result<(), String> {
        Ok(())
    }
}

/// A device that refuses everything, for the fail-closed test.
struct AlwaysFails;

impl AuditDevice for AlwaysFails {
    fn name(&self) -> &'static str {
        "always-fails"
    }

    /// It stores nothing, so it holds nothing. Empty rather than an error: an empty
    /// device is not quarantined at startup, which keeps this double doing the one thing
    /// it exists for -- failing a *write* -- instead of also standing in for a device
    /// that cannot say where it is.
    fn head_seq(&self) -> Result<Option<u64>, String> {
        Ok(None)
    }

    fn write(&mut self, _record: &EncodedRecord) -> Result<(), String> {
        Err("this device always fails".to_owned())
    }
}

/// A valid credential doing something malformed is no longer quieter than an invalid one.
///
/// Finding F12 of the review of 2026-08-24, and the inversion is the point. A *rejected*
/// credential has always produced an entry — that is how a brute-force attempt becomes
/// visible at all. A *valid* credential naming a path that is not a path produced none,
/// so somebody holding a stolen token and probing the parser worked in silence while the
/// failed guess from outside did not.
#[test]
fn an_authenticated_caller_refused_before_a_decision_is_recorded() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    // A path the parser refuses, with a token that works.
    let (status, _) = harness.get(
        "/v1/secrets/infra//DOUBLE_SLASH",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let entries = harness.audit_entries();
    assert_eq!(
        entries.len(),
        before + 1,
        "exactly one entry, not none and not two"
    );

    let refused = entries.last().expect("an entry");
    assert_eq!(refused["entry"]["action"], "request-refused");
    assert_eq!(
        refused["entry"]["allowed"], false,
        "nothing was allowed -- and nothing was evaluated either"
    );
    assert_eq!(
        refused["entry"]["principal"]["name"], "deploy",
        "who was refused"
    );
    assert_eq!(
        refused["entry"]["detail"], "attempted: read",
        "what they were attempting, which `request-refused` alone does not say"
    );

    // No path, and no echo of what was sent. The malformed input is exactly the part a
    // caller controls, and the trail is the one artefact this project keeps
    // tamper-evident -- the same argument F11 made about a parse error on the way out.
    assert!(
        refused["entry"]["path"].is_null(),
        "no path: there was no path, that is what was wrong with it"
    );
    assert!(
        !refused.to_string().contains("DOUBLE_SLASH"),
        "the refused input must not be echoed into the trail, got {refused}"
    );
}

/// A route that does not exist, asked for with a valid token, is recorded.
///
/// Route probing is how somebody with a stolen credential learns which optional surface
/// entries a deployment turned on. It produced nothing at all before.
#[test]
fn an_authenticated_caller_probing_an_unknown_route_is_recorded() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.get("/v1/does-not-exist", Some(&harness.deploy_token));
    assert_eq!(status, StatusCode::NOT_FOUND);

    let entries = harness.audit_entries();
    assert_eq!(entries.len(), before + 1);
    let refused = entries.last().expect("an entry");
    assert_eq!(refused["entry"]["action"], "request-refused");
    assert_eq!(refused["entry"]["deny_reason"], "unmatched-route");
    assert_eq!(refused["entry"]["principal"]["name"], "deploy");
}

/// A method a route does not have, likewise.
#[test]
fn an_authenticated_caller_using_the_wrong_method_is_recorded() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    // `/v1/health` is a GET. A DELETE reaches the route and not the handler.
    let (status, _) = harness.send(Harness::build(
        "DELETE",
        "/v1/health",
        Some(&harness.deploy_token),
        None,
    ));
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "and not a 405 that maps the API"
    );

    let entries = harness.audit_entries();
    assert_eq!(entries.len(), before + 1);
    let refused = entries.last().expect("an entry");
    assert_eq!(refused["entry"]["action"], "request-refused");
    assert_eq!(refused["entry"]["deny_reason"], "unmatched-method");
}

/// Anonymous probing writes nothing, and that is the decision rather than an oversight.
///
/// The trail is fail-closed: a full audit volume takes the service down. If unauthenticated
/// traffic wrote entries, anyone who can reach the listener could turn a `404` into an
/// outage. An authenticated caller can already fill the trail with legitimate reads, so
/// recording them adds no capability a valid token did not already carry.
#[test]
fn anonymous_probing_writes_nothing() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.get("/v1/does-not-exist", None);
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = harness.send(Harness::build("DELETE", "/v1/health", None, None));
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert_eq!(
        harness.audit_entries().len(),
        before,
        "an unauthenticated caller must not be able to write to the trail"
    );
}

/// An invalid credential on an unknown route writes nothing, like an absent one.
///
/// **The asymmetry here is deliberate and worth stating**, because it is not obvious. On
/// a route that exists, a credential that does not work *is* recorded — that path
/// predates this change and is how a brute-force attempt becomes visible. On a route that
/// does not exist, it is not.
///
/// The reason is what the two bound. Recording a failed authentication on a real route
/// requires the attacker to know a route; recording it on any URL at all would let
/// anybody who can reach the listener write to a fail-closed trail by making up paths,
/// and a full audit volume is an outage. A made-up token is exactly as cheap to produce
/// as no token, so the fallback treats the two the same and asks only whether the caller
/// *is* somebody.
#[test]
fn a_rejected_credential_on_an_unknown_route_writes_nothing() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.get(
        "/v1/does-not-exist",
        Some("cph_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert_eq!(
        harness.audit_entries().len(),
        before,
        "a token that authenticates nobody is as cheap to make up as none at all"
    );
}

/// A body the parser refuses, from a caller whose token works, is recorded.
///
/// The last gap F12 left open. Axum answers a body-extractor rejection before the handler
/// runs *and* before the router fallback sees anything, so neither of the two places that
/// record a refused request could see it: a valid token sending broken JSON was the last
/// way to be turned away in silence.
#[test]
fn an_authenticated_caller_sending_a_malformed_body_is_recorded() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.send(Harness::build_raw(
        "PUT",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        Some("{\"value\": not json at all}"),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let entries = harness.audit_entries();
    assert_eq!(entries.len(), before + 1, "one entry, and not none");

    let refused = entries.last().expect("an entry");
    assert_eq!(refused["entry"]["action"], "request-refused");
    assert_eq!(refused["entry"]["deny_reason"], "malformed-body");
    assert_eq!(refused["entry"]["principal"]["name"], "deploy");
    assert_eq!(
        refused["entry"]["detail"], "attempted: write",
        "a PUT is a write, and the export below is a read"
    );

    // The body is caller-controlled bytes. The rejection message goes to whoever sent it
    // and already knows; the trail gets the fact and not the input.
    assert!(
        !refused.to_string().contains("not json at all"),
        "the body must not be echoed into the trail, got {refused}"
    );
}

/// The same on the export route, and the entry says `read` rather than `write`.
///
/// The extractor cannot know which route it is on, so the body type carries the action.
/// One value for both would put "attempted: write" on a read — small, and exactly the
/// kind of thing a reader of a trail later has to un-learn.
#[test]
fn a_malformed_export_body_is_recorded_as_a_read() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.send(Harness::build_raw(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some("{\"paths\": [,]}"),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let entries = harness.audit_entries();
    assert_eq!(entries.len(), before + 1);
    let refused = entries.last().expect("an entry");
    assert_eq!(refused["entry"]["action"], "request-refused");
    assert_eq!(refused["entry"]["deny_reason"], "malformed-body");
    assert_eq!(refused["entry"]["detail"], "attempted: read");
}

/// An anonymous caller sending a malformed body writes nothing.
///
/// The same rule the router fallback follows, for the same reason: the trail is
/// fail-closed, so letting anybody write to it by posting garbage would turn a `400` into
/// an outage.
#[test]
fn an_anonymous_malformed_body_writes_nothing() {
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, _) = harness.send(Harness::build_raw(
        "PUT",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        None,
        Some("{ broken"),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert_eq!(
        harness.audit_entries().len(),
        before,
        "an unauthenticated caller must not be able to write to the trail"
    );
}

/// A body that parses still costs one authentication and one parse, as before.
///
/// The extractor authenticates only on the *failing* path. A test that only proved the
/// failure case would pass against a wrapper that had quietly doubled the work every
/// write does.
#[test]
fn a_well_formed_body_is_unaffected() {
    let harness = Harness::new();

    let (status, body) = harness.send(Harness::build(
        "PUT",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "still works" })),
    ));
    assert_eq!(status, StatusCode::OK, "got {body}");

    let entries = harness.audit_entries();
    assert!(
        !entries
            .iter()
            .any(|entry| entry["entry"]["action"] == "request-refused"),
        "a body that parses refuses nothing"
    );
}

#[test]
fn health_needs_no_token_and_reveals_no_inventory() {
    let harness = Harness::new();
    let (status, body) = harness.get("/v1/health", None);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["sealed"], false);
    assert_eq!(body["seal"], "static");
    // Where the key came from, so a deployment can confirm it is not in the container
    // configuration rather than assuming the file it edited took effect.
    assert_eq!(body["key_source"], "supplied");
    assert!(body["audit_devices"].is_array());
    // Nothing has been recorded yet, and that is a third state -- not "healthy".
    assert_eq!(
        body["audit_devices"][0]["accepting"],
        serde_json::Value::Null
    );

    // An unauthenticated endpoint must not say how many secrets exist, or whether any
    // do.
    let text = body.to_string();
    for leak in ["secrets", "count", "paths", "identities"] {
        assert!(!text.contains(leak), "health must not mention {leak}");
    }
}

#[test]
fn a_request_without_a_token_is_refused_and_says_how_to_authenticate() {
    let harness = Harness::new();
    let request = Harness::build("GET", "/v1/secrets/infra/service-a/DB_PASSWORD", None, None);

    let response = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(harness.router.clone().oneshot(request))
        .expect("answer");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
}

/// Finding F3: every `/v1` response says `no-store`, including the ones that failed.
///
/// The server used to emit no cache directive at all — for plaintext reads and exports as
/// much as for anything else — and the only mitigation in the tree was the viewer asking
/// Fetch not to cache its own request. The SDK, the CLI, browser private caches, reverse
/// proxies and everything else in the path were left with their defaults, and a permissive
/// one retains a plaintext value past the token's lifetime.
///
/// The list below is deliberately not only the value routes. A `403` says an identity may
/// not read a path and a `404` says it does not exist; both are worth keeping out of a
/// shared cache, and a per-route list is one somebody has to keep correct forever.
#[test]
fn every_response_forbids_caching() {
    let harness = Harness::new();
    let deploy = harness.deploy_token.clone();
    let auditor = harness.auditor_token.clone();

    let cases: Vec<(&str, &str, Option<&str>)> = vec![
        // A value, which is the case the whole finding is about.
        (
            "GET",
            "/v1/secrets/infra/service-a/DB_PASSWORD",
            Some(&deploy),
        ),
        // Metadata, which names paths even when it carries no value.
        (
            "GET",
            "/v1/versions/infra/service-a/DB_PASSWORD",
            Some(&deploy),
        ),
        ("GET", "/v1/list/infra", Some(&deploy)),
        // Unauthenticated, and the one route a monitor polls.
        ("GET", "/v1/health", None),
        ("GET", "/v1/surface", Some(&deploy)),
        // The refusals. `401` carries no body worth caching and is here anyway: the
        // property is about the layer, not about which responses deserve it.
        ("GET", "/v1/secrets/infra/service-a/DB_PASSWORD", None),
        ("GET", "/v1/secrets/nowhere/at-all/KEY", Some(&deploy)),
        ("GET", "/v1/audit", Some(&auditor)),
        // A route this build does not have, answered from the fallback rather than by a
        // handler -- so it exercises the layer where no handler runs at all.
        ("GET", "/v1/not-a-route", Some(&deploy)),
    ];

    for (method, uri, token) in cases {
        let request = Harness::build(method, uri, token, None);
        let response = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(harness.router.clone().oneshot(request))
            .expect("answer");

        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{method} {uri} (status {}) must forbid caching",
            response.status()
        );
    }
}

#[test]
fn every_kind_of_bad_token_gets_the_same_answer() {
    let harness = Harness::new();
    let valid = harness.deploy_token.clone();

    for token in [
        "not-a-token".to_owned(),
        String::new(),
        valid[..valid.len() - 1].to_owned(),
        // Well-formed but never issued.
        Token::generate().unwrap().expose_text().to_string(),
        // Bait belongs in this list and not in a test of its own: ADR-15's property 1
        // is that a honeypot token is one more kind of invalid credential from the
        // caller's side. If that ever stops being true, this loop is where it shows.
        harness.bait_token.clone(),
    ] {
        let (status, body) = harness.get(
            "/v1/secrets/infra/service-a/DB_PASSWORD",
            Some(token.as_str()),
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED, "for {token:?}");
        assert_eq!(body["error"], "unauthenticated");
        // Nothing about which part was wrong.
        assert!(body.get("detail").is_none());
    }
}

/// The response headers must not distinguish bait either.
///
/// The body and the status are checked above; a `WWW-Authenticate` that differed, or an
/// extra header on one path, would be exactly the bait that announces itself to whoever
/// measures carefully.
#[test]
fn bait_and_an_unknown_token_produce_identical_responses() {
    let harness = Harness::new();
    let unknown = Token::generate().unwrap().expose_text().to_string();

    let responses: Vec<_> = [unknown.as_str(), harness.bait_token.as_str()]
        .into_iter()
        .map(|token| {
            let request = Harness::build(
                "GET",
                "/v1/secrets/infra/service-a/DB_PASSWORD",
                Some(token),
                None,
            );
            let response = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(harness.router.clone().oneshot(request))
                .expect("answer");
            let status = response.status();
            let mut headers: Vec<_> = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            headers.sort();
            (status, headers)
        })
        .collect();

    assert_eq!(responses[0], responses[1]);
}

/// An entry a deployment did not name has no route at all.
///
/// **Off is absent, not dormant.** The point of the assertion being on the status code is
/// that the off state is observable from outside: a handler that answered `403` or a
/// `404` of its own would be compiled, wired, and one boolean from serving, and nothing
/// but reading the configuration file could tell you which.
///
/// This works in both configurations. `with_surface(&[])` yields an empty surface in a
/// default build and one holding only `honeypot_alert` where the feature is compiled in —
/// and neither names the two runtime entries, which is what this test is about.
#[test]
fn an_entry_that_is_not_named_has_no_route() {
    let harness = Harness::with_surface(&[]);
    let token = harness.auditor_token.clone();

    for route in ["/v1/audit", "/v1/identities", "/v1/policies"] {
        let (status, _) = harness.get(route, Some(&token));
        assert_eq!(status, StatusCode::NOT_FOUND, "{route} without viewer_api");
    }

    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": ["infra/service-a/DB_PASSWORD"] })),
    );
    let (status, _) = harness.send(export);
    assert_eq!(status, StatusCode::NOT_FOUND, "export without bulk_export");

    // The federated exchange, which is the one optional route a caller reaches without
    // a credential -- so its off state has to be the fallback's `404` and not a handler
    // that decides to refuse. `openapi.yaml` has documented that status for this path
    // since phase 3, when it was a reservation rather than an entry.
    let login = Harness::build(
        "POST",
        "/v1/auth/oidc/login",
        None,
        Some(serde_json::json!({ "id_token": "a.b.c" })),
    );
    let (status, _) = harness.send(login);
    assert_eq!(status, StatusCode::NOT_FOUND, "login without oidc_login");

    // What every deployment keeps: health, the value path, listing, and the surface
    // endpoint itself.
    let (status, _) = harness.get("/v1/health", None);
    assert_eq!(status, StatusCode::OK);
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token.clone()),
    );
    assert_eq!(status, StatusCode::OK);
    let (status, body) = harness.get("/v1/surface", Some(&token));
    assert_eq!(status, StatusCode::OK);
    let names = body["entries"].to_string();
    assert!(!names.contains("viewer_api"));
    assert!(!names.contains("bulk_export"));
}

/// Named, and the routes are there — the other half of the pair above.
#[test]
fn the_runtime_entries_bring_their_routes() {
    let harness = Harness::new();
    let (status, _) = harness.get("/v1/audit", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);

    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": ["infra/service-a/DB_PASSWORD"] })),
    );
    let (status, _) = harness.send(export);
    assert_eq!(status, StatusCode::OK);

    let (_, health) = harness.get("/v1/health", None);
    let names = health["surface"].to_string();
    assert!(names.contains("viewer_api"));
    assert!(names.contains("bulk_export"));
}

/// An unauthenticated caller gets nothing from it, even though `/v1/health` lists the
/// same entry names.
///
/// That split is plan section 10's rule, and it is worth a test because the two
/// endpoints deliberately disagree about what they will say.
#[test]
fn surface_needs_a_token_although_health_does_not() {
    let harness = Harness::new();
    let (status, _) = harness.get("/v1/surface", None);
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = harness.get("/v1/health", None);
    assert_eq!(status, StatusCode::OK);
}

/// The record behind an active entry, including the cost sentence that ships with the
/// binary — ADR-20 asks for exactly that.
#[cfg(feature = "honeypot_alert")]
#[test]
fn surface_reports_the_record_behind_an_active_entry() {
    let harness = Harness::with_surface(&["viewer_api", "honeypot_alert"]);
    let (status, body) = harness.get("/v1/surface", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);

    let entry = body["entries"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|entry| entry["entry"] == "honeypot_alert")
        .expect("the build entry");
    // Against `Kind::as_str` rather than against a literal, so the wire word and the
    // word `--check-config` prints are pinned to each other and not merely to two
    // strings that agree today. They disagreed once: `as_str` was added to be the one
    // spelling and the response kept its own `match`.
    assert_eq!(entry["kind"], ciphr_server::surface::Kind::Build.as_str());
    assert!(
        entry["accepted"].as_str().is_some(),
        "a date is always reported"
    );
    assert!(entry["reason"].as_str().is_some_and(|r| !r.is_empty()));
    // A runtime entry beside it, so the two kinds are distinguishable on the wire.
    let runtime = body["entries"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|entry| entry["entry"] == "viewer_api")
        .expect("the runtime entry");
    assert_eq!(
        runtime["kind"],
        ciphr_server::surface::Kind::Runtime.as_str()
    );
    // The operator wrote the reason; the software says what they said yes to.
    assert!(
        entry["cost"]
            .as_str()
            .is_some_and(|cost| cost.contains("No detection of bait")),
        "the cost sentence ships with the binary"
    );

    // The same names, unauthenticated, and nothing else.
    let (_, health) = harness.get("/v1/health", None);
    let names: Vec<&str> = health["surface"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(names.contains(&"honeypot_alert"));
    assert!(names.contains(&"viewer_api"));
    assert!(
        !health.to_string().contains("no operator recorded this"),
        "the reason must not reach an unauthenticated endpoint"
    );
}

/// The honeypot route is absent from a default binary, not present and refusing.
///
/// ADR-20: off means absent. A handler answering 404 from inside itself would be
/// compiled, wired, and one boolean from serving.
#[cfg(not(feature = "honeypot_alert"))]
#[test]
fn the_honeypot_route_does_not_exist_without_the_entry() {
    let harness = Harness::new();
    let (status, _) = harness.get("/v1/honeypots", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The administrative view of bait: both kinds, and the trips that are open.
#[cfg(feature = "honeypot_alert")]
#[test]
fn the_honeypot_route_lists_bait_and_open_trips() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    // Take it, so there is a trip to report.
    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token.clone()),
    );

    let (status, body) = harness.get("/v1/honeypots", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);

    let bait = body["honeypots"].as_array().expect("an array");
    let secret = bait
        .iter()
        .find(|entry| entry["kind"] == "secret")
        .expect("the marked secret");
    assert_eq!(secret["path"], "infra/service-a/DB_PASSWORD");
    assert_eq!(secret["tier"], "alert");
    assert_eq!(secret["tripped"], true);

    let token = bait
        .iter()
        .find(|entry| entry["kind"] == "token")
        .expect("the planted token");
    assert_eq!(token["identity"], "deploy");
    assert_eq!(token["tripped"], false);
    // The verifier never leaves the store, and neither does the token.
    assert!(token["path"].is_null());

    let trips = body["open_trips"].as_array().expect("an array");
    assert_eq!(trips.len(), 1);
    assert_eq!(trips[0]["path"], "infra/service-a/DB_PASSWORD");
    assert_eq!(trips[0]["identity"], "deploy");
}

/// An identity without `read` on `sys/honeypots` cannot see the bait.
///
/// The flag's whole value depends on this: a caller who can enumerate the honeypots can
/// avoid them.
#[cfg(feature = "honeypot_alert")]
#[test]
fn the_honeypot_route_is_authorized_like_everything_else() {
    let harness = Harness::new();
    let (status, _) = harness.get("/v1/honeypots", Some(&harness.deploy_token.clone()));
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A honeypot *secret* trips on the value route, and does not trip on the routes that
/// only name it.
///
/// The list/versions half is the one worth pinning: ADR-15 says enumerating a name is not
/// taking the bait, and a honeypot that fires on `list` fires on every inventory an
/// operator runs.
#[cfg(feature = "honeypot_alert")]
#[test]
fn a_honeypot_secret_trips_on_a_read_and_not_on_a_listing() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    // Naming it is not taking it.
    let (status, _) = harness.get("/v1/list/infra", Some(&harness.deploy_token.clone()));
    assert_eq!(status, StatusCode::OK);
    let (status, _) = harness.get(
        "/v1/versions/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token.clone()),
    );
    assert_eq!(status, StatusCode::OK);
    assert!(
        !harness
            .audit_entries()
            .iter()
            .any(|entry| entry["entry"]["action"] == "honeypot-triggered"),
        "enumerating a name must not trip"
    );

    // Reading its value is.
    let (status, body) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token.clone()),
    );
    assert_eq!(status, StatusCode::OK, "bait answers like any other secret");
    assert_eq!(body["value"], "seeded");
    // No extra field anywhere on the value path.
    assert!(body.get("honeypot").is_none());
    assert!(body.get("tier").is_none());

    let entries = harness.audit_entries();
    let trip = entries
        .iter()
        .find(|entry| entry["entry"]["action"] == "honeypot-triggered")
        .expect("the read must be recorded as a trip");
    assert_eq!(trip["entry"]["principal"]["name"], "deploy");
    assert_eq!(trip["entry"]["path"], "infra/service-a/DB_PASSWORD");
    assert_eq!(trip["entry"]["detail"], "attempted: read");
    assert_eq!(trip["entry"]["allowed"], true);
    // The rule that allowed it is still there: the trip replaced the action, not the
    // decision the entry records.
    assert!(trip["entry"]["rule"]["policy"].is_string());
}

/// A refused read of bait trips nothing.
///
/// ADR-15 is explicit: bait outside an identity's grants produces a denial, and a denial
/// trips nothing. Without this an identity scoped away from the bait would page somebody
/// every time it probed.
#[cfg(feature = "honeypot_alert")]
#[test]
fn a_denied_read_of_bait_trips_nothing() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.auditor_token.clone()),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);

    assert!(
        !harness
            .audit_entries()
            .iter()
            .any(|entry| entry["entry"]["action"] == "honeypot-triggered"),
        "a denial is not a trip"
    );
}

/// `/v1/health` says a tripwire is open, and never which bait.
#[cfg(feature = "honeypot_alert")]
#[test]
fn health_reports_that_something_fired_and_not_what() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    let (_, before) = harness.get("/v1/health", None);
    assert_eq!(before["tripped"], false);
    assert_eq!(before["open_tripwires"], 0);

    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token.clone()),
    );

    let (_, after) = harness.get("/v1/health", None);
    assert_eq!(after["tripped"], true);
    assert_eq!(after["open_tripwires"], 1);
    // Nothing about which path, and no identity.
    let rendered = after.to_string();
    assert!(
        !rendered.contains("DB_PASSWORD"),
        "health must not name bait"
    );
    assert!(
        !rendered.contains("deploy"),
        "health must not name an identity"
    );
}

/// A store that cannot be asked produces `degraded`, and never an affirmative "clear".
///
/// Finding F9 of the review of 2026-08-24. `tripwire_state` swallowed every store and
/// lock error into `(false, 0)`, so `/v1/health` answered `status: "ok"`,
/// `tripped: false`, `open_tripwires: 0` while being unable to establish any of it. The
/// moment that matters is an incident, and the answer it gave then was the reassuring
/// one.
///
/// The failure here is real rather than injected: the `tripwire` table is dropped
/// through a second connection, so the server's own query fails the way a corrupted or
/// truncated database makes it fail.
#[cfg(feature = "honeypot_alert")]
#[test]
fn health_says_degraded_when_it_cannot_read_the_tripwire_state() {
    let harness = Harness::new();

    let (_, before) = harness.get("/v1/health", None);
    assert_eq!(before["status"], "ok");
    assert_eq!(before["tripped"], false);
    assert!(
        before.get("degraded").is_none(),
        "nothing is unverifiable in the ordinary case, so the field is absent"
    );

    {
        // `rusqlite` directly, as `tests/check_config.rs` does and for the same reason:
        // nothing in `ciphr-store`'s interface can express "a database that has become
        // unreadable", and that is the state under test.
        let connection = rusqlite::Connection::open(&harness.database).expect("open");
        connection
            .execute_batch("DROP TABLE tripwire")
            .expect("drop the table the health query reads");
    }

    let (status, after) = harness.get("/v1/health", None);
    assert_eq!(
        status,
        StatusCode::OK,
        "the process is serving; a load balancer must not pull it out of rotation"
    );
    assert_eq!(after["status"], "degraded");
    assert_eq!(
        after["degraded"],
        serde_json::json!(["tripwires"]),
        "which part could not be established, by name"
    );
    assert!(
        after.get("tripped").is_none() && after.get("open_tripwires").is_none(),
        "absent rather than false: inventing `false` here is the finding, got {after}"
    );

    // The name and nothing else. A store error message names a database file, and this
    // endpoint is unauthenticated.
    let rendered = after.to_string();
    assert!(
        !rendered.contains("tripwire\"") || !rendered.contains("no such table"),
        "the reason must stay out of the response, got {rendered}"
    );
}

/// A build without the entry says nothing about tripwires at all.
///
/// Absent rather than `false`: "this build cannot detect bait" and "nothing has been
/// taken" are different facts, and a monitor that conflates them reports a working
/// tripwire on a service that has none.
#[cfg(not(feature = "honeypot_alert"))]
#[test]
fn health_omits_the_tripwire_fields_without_the_entry() {
    let harness = Harness::new();
    let (_, body) = harness.get("/v1/health", None);
    assert!(body.get("tripped").is_none());
    assert!(body.get("open_tripwires").is_none());
}

/// The latch: a second read of the same bait does not open a second trip.
///
/// **Why this is not racy, since the latch write is deliberately off the request path.**
/// `Harness::send` builds a runtime per call and drops it when the response is in hand,
/// and dropping a tokio runtime waits for its blocking tasks. So each request here drains
/// its own latch write before the next line runs. In a real deployment the runtime
/// outlives the request and the write is genuinely concurrent, which is the point — this
/// test can be exact about the outcome only because of how it drives the router, and that
/// is worth knowing before somebody adds a sleep to "fix" a test that does not need one.
#[cfg(feature = "honeypot_alert")]
#[test]
fn the_second_read_of_the_same_bait_does_not_latch_again() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    for _ in 0..3 {
        harness.get(
            "/v1/secrets/infra/service-a/DB_PASSWORD",
            Some(&harness.deploy_token.clone()),
        );
    }

    let (_, health) = harness.get("/v1/health", None);
    assert_eq!(health["open_tripwires"], 1, "one latch, three reads");

    // Every read is still in the trail, though: the latch bounds the paging, not the
    // record.
    let trips = harness
        .audit_entries()
        .iter()
        .filter(|entry| entry["entry"]["action"] == "honeypot-triggered")
        .count();
    assert_eq!(trips, 3, "the trail records each read");
}

/// A bulk export of a prefix containing bait trips on the bait and on nothing else.
///
/// This is the case ADR-15's placement rule exists for, and it is worth a test rather
/// than a sentence: `POST /v1/export` is a value route, so bait under a fetched prefix
/// trips on every service start.
#[cfg(feature = "honeypot_alert")]
#[test]
fn an_export_that_includes_bait_trips_on_that_path_only() {
    let harness = Harness::new();
    harness.mark_as_bait("infra/service-a/DB_PASSWORD");

    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": ["infra/service-a/DB_PASSWORD"] })),
    );
    let (status, _) = harness.send(export);
    assert_eq!(status, StatusCode::OK);

    let entries = harness.audit_entries();
    let trip = entries
        .iter()
        .find(|entry| entry["entry"]["action"] == "honeypot-triggered")
        .expect("an export of bait is a trip");
    assert_eq!(trip["entry"]["detail"], "attempted: read");
    assert_eq!(trip["entry"]["path"], "infra/service-a/DB_PASSWORD");
}

/// The trail says bait was taken, and says which bait and what was attempted.
///
/// Only in a build that has the entry. Without it there is nothing to record, which the
/// companion test below pins.
#[cfg(feature = "honeypot_alert")]
#[test]
fn taking_the_bait_is_recorded_as_a_trip() {
    let harness = Harness::new();
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.bait_token.clone()),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let entries = harness.audit_entries();
    let trip = entries
        .iter()
        .find(|entry| entry["entry"]["action"] == "honeypot-triggered")
        .expect("the trip must be in the trail");

    // Which bait. `subject` and not `principal`: nobody authenticated.
    assert_eq!(trip["entry"]["subject"]["name"], "deploy");
    assert!(trip["entry"]["subject"]["token_id"].is_string());
    assert!(trip["entry"]["principal"].is_null());
    // What was attempted, which replacing the action would otherwise discard.
    assert_eq!(trip["entry"]["detail"], "attempted: read");
    assert_eq!(trip["entry"]["allowed"], false);
    assert_eq!(trip["entry"]["request"]["http_status"], 401);

    // One entry for the attempt, not two. A second write is work an ordinary rejected
    // credential does not cause, and therefore measurable.
    let attempts = entries
        .iter()
        .filter(|entry| {
            entry["entry"]["action"] == "honeypot-triggered"
                || entry["entry"]["deny_reason"] == "unauthenticated"
        })
        .count();
    assert_eq!(
        attempts, 1,
        "a trip replaces the entry rather than adding one"
    );
}

/// Presenting bait opens the latch, so the thing that pages a human can see it.
///
/// The test above stops at the trail, and so did the implementation: finding F1 of
/// `docs/assurance/reviews/review-2026-08-21-current-tree.md` is that the entry was written and nothing
/// latched. `/v1/health` kept answering `tripped: false`, `/v1/honeypots` kept calling the
/// credential untripped, and a deployment that polled health — the third of the three
/// things `honeypots.md` requires — missed the event while doing everything right.
///
/// Not racy, for the reason `the_second_read_of_the_same_bait_does_not_latch_again` gives
/// in full: `Harness::send` builds a runtime per call and dropping a tokio runtime waits
/// for its blocking tasks, so each request drains its own latch write.
#[cfg(feature = "honeypot_alert")]
#[test]
fn presenting_a_honeypot_token_opens_the_latch() {
    let harness = Harness::new();

    let (_, before) = harness.get("/v1/health", None);
    assert_eq!(before["tripped"], false);
    assert_eq!(before["open_tripwires"], 0);

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.bait_token.clone()),
    );
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "what the caller is told does not change"
    );

    let (_, after) = harness.get("/v1/health", None);
    assert_eq!(after["tripped"], true);
    assert_eq!(after["open_tripwires"], 1);
    // That something fired, never what. A token id here would let whoever presented the
    // credential confirm that the one they hold is the bait.
    let rendered = after.to_string();
    assert!(
        !rendered.contains("deploy"),
        "health must not name an identity"
    );

    // Which bait is the administrative read's job.
    let (status, body) = harness.get("/v1/honeypots", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);
    let token = body["honeypots"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|entry| entry["kind"] == "token")
        .expect("the planted token");
    assert_eq!(token["tripped"], true, "the bait that was taken says so");

    let trips = body["open_trips"].as_array().expect("an array");
    assert_eq!(trips.len(), 1);
    assert_eq!(trips[0]["kind"], "token");
    assert!(trips[0]["token_id"].is_string(), "which credential it was");
    assert!(trips[0]["path"].is_null(), "a token trip names no path");
    // Nobody authenticated, so the trip names nobody. The identity the bait was issued
    // for is on the honeypot row above, where it means what it says.
    assert!(
        trips[0]["identity"].is_null(),
        "presenting bait authenticates nothing, so no identity took it"
    );
    assert_eq!(trips[0]["tier"], "alert");
}

/// Three presentations, one latch, three entries.
///
/// The latch bounds the paging and not the record — for tokens exactly as for secrets. It
/// also bounds the *work* after finding F5, and that half is not visible from here: with
/// or without the deduplication this test passes, because the database's partial index
/// already refused the second row. `state.rs` has the unit tests for the part this one
/// cannot see, and this comment is here so nobody deletes them as redundant.
#[cfg(feature = "honeypot_alert")]
#[test]
fn a_token_presented_three_times_latches_once() {
    let harness = Harness::new();

    for _ in 0..3 {
        harness.get(
            "/v1/secrets/infra/service-a/DB_PASSWORD",
            Some(&harness.bait_token.clone()),
        );
    }

    let (_, health) = harness.get("/v1/health", None);
    assert_eq!(health["open_tripwires"], 1, "one latch, three attempts");

    let trips = harness
        .audit_entries()
        .iter()
        .filter(|entry| entry["entry"]["action"] == "honeypot-triggered")
        .count();
    assert_eq!(trips, 3, "the trail records each attempt");
}

/// Without the entry, bait is recorded as any other rejected credential is.
///
/// This is what "a deployment that plants none runs the code the review read" means in
/// practice, and it is worth a test because the alternative -- a build that quietly
/// records trips it cannot act on -- would look identical from the outside.
#[cfg(not(feature = "honeypot_alert"))]
#[test]
fn without_the_entry_bait_is_just_a_rejected_credential() {
    let harness = Harness::new();
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.bait_token.clone()),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let entries = harness.audit_entries();
    assert!(
        !entries
            .iter()
            .any(|entry| entry["entry"]["action"] == "honeypot-triggered"),
        "a build without the entry has no trips to record"
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry["entry"]["deny_reason"] == "unauthenticated"),
        "the attempt is still recorded, as any rejected credential is"
    );
}

#[test]
fn a_permitted_read_returns_the_value() {
    let harness = Harness::new();
    let (status, body) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], "seeded");
    assert_eq!(body["version"], 1);
    assert_eq!(body["path"], "infra/service-a/DB_PASSWORD");
}

#[test]
fn a_denied_read_is_forbidden_and_the_rule_is_in_the_audit_trail_not_the_response() {
    let harness = Harness::new();
    let (status, body) = harness.get(
        "/v1/secrets/infra/ciphr/MASTER_BACKUP",
        Some(&harness.deploy_token),
    );

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "forbidden");
    // The caller learns nothing about the policy that refused them.
    let text = body.to_string();
    assert!(!text.contains("infra/ciphr"));
    assert!(!text.contains("rule"));

    // The operator does.
    let entries = harness.audit_entries();
    let denial = entries
        .iter()
        .find(|entry| entry["entry"]["allowed"] == false)
        .expect("the denial must be recorded");
    assert_eq!(denial["entry"]["deny_reason"], "not-granted");
    assert_eq!(denial["entry"]["rule"]["pattern"], "infra/ciphr/**");
    assert_eq!(denial["entry"]["principal"]["name"], "deploy");
    assert_eq!(denial["entry"]["request"]["http_status"], 403);
}

#[test]
fn a_write_then_a_read_round_trips_through_the_api() {
    let harness = Harness::new();
    let write = Harness::build(
        "PUT",
        "/v1/secrets/infra/service-b/API_TOKEN",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "written-over-http" })),
    );

    let (status, body) = harness.send(write);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);

    let (status, body) = harness.get(
        "/v1/secrets/infra/service-b/API_TOKEN",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], "written-over-http");
}

#[test]
fn the_reserved_prefix_cannot_be_written_through_the_api() {
    let harness = Harness::new();
    let write = Harness::build(
        "PUT",
        "/v1/secrets/sys/audit",
        Some(&harness.auditor_token),
        Some(serde_json::json!({ "value": "nice try" })),
    );

    let (status, body) = harness.send(write);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("reserved"),
        "got {body}"
    );
}

#[test]
fn a_malformed_path_is_refused_before_anything_else_happens() {
    let harness = Harness::new();

    for path in ["infra//a", "infra/../a", "infra/a%20b"] {
        let (status, _) = harness.get(&format!("/v1/secrets/{path}"), Some(&harness.deploy_token));
        assert_eq!(status, StatusCode::BAD_REQUEST, "for {path}");
    }
}

#[test]
fn deleting_makes_a_secret_unreadable_and_is_recorded() {
    let harness = Harness::new();
    let delete = Harness::build(
        "DELETE",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        None,
    );

    let (status, _) = harness.send(delete);
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert!(
        harness
            .audit_entries()
            .iter()
            .any(|entry| entry["entry"]["action"] == "delete"),
        "the deletion must be recorded"
    );
}

#[test]
fn a_delete_that_deletes_nothing_says_so_in_the_trail() {
    // Finding F4. The decision is recorded before the work, so without a second entry
    // the trail claims an authorized deletion at 200 for a secret that is still there.
    let harness = Harness::new();
    let delete = Harness::build(
        "DELETE",
        "/v1/secrets/infra/service-a/NOT_THERE",
        Some(&harness.deploy_token),
        None,
    );

    let (status, _) = harness.send(delete);
    assert_eq!(status, StatusCode::NOT_FOUND);

    let deletes: Vec<_> = harness
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["entry"]["action"] == "delete")
        .collect();

    assert_eq!(deletes.len(), 2, "the decision and its correction");
    assert_eq!(deletes[0]["entry"]["allowed"], true);
    assert_eq!(deletes[0]["entry"]["request"]["http_status"], 200);
    assert_eq!(deletes[1]["entry"]["deny_reason"], "delete-failed");
    assert_eq!(deletes[1]["entry"]["request"]["http_status"], 404);
    assert_eq!(deletes[1]["entry"]["path"], "infra/service-a/NOT_THERE");
}

#[test]
fn a_version_listing_of_a_missing_path_says_so_in_the_trail() {
    // The same shape as the delete above. This handler was not in F4's list and had
    // F4's defect.
    let harness = Harness::new();
    let (status, _) = harness.get(
        "/v1/versions/infra/service-a/NOT_THERE",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::NOT_FOUND);

    let listings: Vec<_> = harness
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["entry"]["action"] == "list")
        .collect();

    assert_eq!(listings.len(), 2, "the decision and its correction");
    assert_eq!(listings[1]["entry"]["deny_reason"], "not-listed");
    assert_eq!(listings[1]["entry"]["request"]["http_status"], 404);
}

#[test]
fn an_export_that_fails_corrects_every_entry_it_had_already_written() {
    // Finding F4, the part that is easy to under-fix: correcting only the path that
    // failed would leave the earlier "allowed read, 200" entries standing for values
    // that never left the process, because the whole export aborts as a unit.
    let harness = Harness::new();
    for path in ["infra/abort/ONE", "infra/abort/TWO"] {
        let write = Harness::build(
            "PUT",
            &format!("/v1/secrets/{path}"),
            Some(&harness.deploy_token),
            Some(serde_json::json!({ "value": "x" })),
        );
        harness.send(write);
    }

    let before = harness.audit_entries().len();

    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({
            "paths": ["infra/abort/ONE", "infra/abort/TWO", "infra/abort/MISSING"]
        })),
    );
    let (status, body) = harness.send(export);

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.to_string().contains("\"value\""), "no partial answer");

    let written: Vec<_> = harness.audit_entries().split_off(before);

    // Three decisions, then three corrections: one per path this request recorded,
    // including the two whose reads succeeded and were thrown away.
    let allowed: Vec<_> = written
        .iter()
        .filter(|entry| entry["entry"]["allowed"] == true)
        .collect();
    let corrections: Vec<_> = written
        .iter()
        .filter(|entry| entry["entry"]["deny_reason"] == "not-served")
        .collect();

    assert_eq!(allowed.len(), 3, "one decision per requested path");
    assert_eq!(corrections.len(), 3, "one correction per recorded path");
    assert!(
        corrections
            .iter()
            .all(|entry| entry["entry"]["request"]["http_status"] == 404),
        "the correction carries the status the caller got: {corrections:?}"
    );

    let corrected: Vec<&str> = corrections
        .iter()
        .map(|entry| entry["entry"]["path"].as_str().expect("a path"))
        .collect();
    assert!(
        corrected.contains(&"infra/abort/ONE") && corrected.contains(&"infra/abort/TWO"),
        "the paths that were read and discarded must be corrected too: {corrected:?}"
    );
}

#[test]
fn the_version_history_is_available_without_values() {
    let harness = Harness::new();
    let write = Harness::build(
        "PUT",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "second" })),
    );
    harness.send(write);

    let (status, body) = harness.get(
        "/v1/versions/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    assert_eq!(status, StatusCode::OK);
    let versions = body["versions"].as_array().expect("an array of versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], 1);
    assert_eq!(versions[1]["version"], 2);
    // No values anywhere in a version listing.
    assert!(!body.to_string().contains("second"));
}

#[test]
fn the_version_history_carries_the_rotation_class() {
    // The class is what tells a reader whether rotating this secret destroys
    // anything, and until now it existed only in the store and the CLI -- so the
    // viewer could not show it and no API consumer could see it at all.
    let harness = Harness::new();
    harness.send(Harness::build(
        "PUT",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "first" })),
    ));

    let (status, body) = harness.get(
        "/v1/versions/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["path"], "infra/service-a/DB_PASSWORD");
    // Written through the API without a class, so nobody has classified it.
    assert_eq!(body["rotation"]["class"], "unclassified");
    // And the absence of an answer is not reported as a safe one.
    assert_eq!(body["rotation"]["needs_care"], true);
    // The advice travels with the class so the viewer shows the same words the CLI
    // prints, rather than a second copy that drifts. For this class the words that
    // matter are the ones naming how to record an answer.
    assert!(
        body["rotation"]["advice"]
            .as_str()
            .expect("advice")
            .contains("ciphr rotation"),
        "the advice should say what to do about it: {}",
        body["rotation"]["advice"]
    );
}

#[test]
fn a_write_can_carry_its_rotation_class_and_is_audited_as_two_things() {
    // The migration case: an estate imported over the running service, one path at a
    // time, without leaving every value saying "nobody has looked at this" until
    // somebody stops the service to say otherwise.
    let harness = Harness::new();
    let (status, body) = harness.send(Harness::build(
        "PUT",
        "/v1/secrets/infra/service-d/DB_KEY",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "imported", "rotation": "breaks-data" })),
    ));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);

    let (status, body) = harness.get(
        "/v1/versions/infra/service-d/DB_KEY",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rotation"]["class"], "breaks-data");
    assert_eq!(body["rotation"]["needs_care"], true);

    // Two entries, not one. A class that moved inside a `write` entry is a
    // `breaks-data` downgraded to `rotatable` with nothing in the trail saying so --
    // the exact drift the CLI's `classify` was funnelled into one function to prevent.
    let entries = harness.audit_entries();
    let classify: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|entry| {
            entry["entry"]["action"] == "classify"
                && entry["entry"]["path"] == "infra/service-d/DB_KEY"
        })
        .collect();
    assert_eq!(classify.len(), 1, "one classify entry, got {entries:#?}");
    assert_eq!(classify[0]["entry"]["allowed"], true);
    assert_eq!(classify[0]["entry"]["principal"]["name"], "deploy");
    assert!(
        entries.iter().any(|entry| {
            entry["entry"]["action"] == "write"
                && entry["entry"]["path"] == "infra/service-d/DB_KEY"
        }),
        "the value write is still recorded as a write"
    );
}

#[test]
fn a_write_without_a_class_changes_no_class() {
    // "Absent means unchanged" in both directions: a new path still lands on the
    // pessimistic default, and a value written over an existing classification does not
    // silently reset it to `unclassified`.
    let harness = Harness::new();
    let path = "/v1/secrets/infra/service-e/TOKEN";

    harness.send(Harness::build(
        "PUT",
        path,
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "one", "rotation": "invalidates-sessions" })),
    ));
    harness.send(Harness::build(
        "PUT",
        path,
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "two" })),
    ));

    let (_, body) = harness.get(
        "/v1/versions/infra/service-e/TOKEN",
        Some(&harness.deploy_token),
    );
    assert_eq!(body["versions"].as_array().expect("versions").len(), 2);
    assert_eq!(body["rotation"]["class"], "invalidates-sessions");

    // And the second write recorded no classification, because none happened.
    let classifications = harness
        .audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["entry"]["action"] == "classify"
                && entry["entry"]["path"] == "infra/service-e/TOKEN"
        })
        .count();
    assert_eq!(classifications, 1, "only the write that named a class");
}

#[test]
fn an_unknown_rotation_class_is_refused_before_anything_happens() {
    // Never defaulted. Defaulting a typo would turn it into "safe to rotate", which is
    // the one claim that destroys data if it is wrong -- and the refusal comes before
    // the authorization entry, so the trail carries no allowed write that never was.
    let harness = Harness::new();
    let before = harness.audit_entries().len();

    let (status, body) = harness.send(Harness::build(
        "PUT",
        "/v1/secrets/infra/service-f/VALUE",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "v", "rotation": "rotateable" })),
    ));

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("rotateable"), "got {body}");
    assert!(
        detail.contains("rotatable"),
        "the error should name the classes that do exist: {body}"
    );
    assert_eq!(
        harness.audit_entries().len(),
        before,
        "a malformed request produces no entry"
    );

    let store = SqliteStore::open(&harness.database).expect("reopen");
    let path = SecretPath::parse("infra/service-f/VALUE").expect("valid");
    assert!(
        store.metadata(&path).is_err(),
        "nothing may be written when the request was refused"
    );
}

#[test]
fn listing_shows_only_what_the_caller_may_list() {
    let harness = Harness::new();

    // Two secrets: one the deploy identity may see, one it may not.
    for (path, value) in [("infra/service-c/A", "a"), ("infra/ciphr/HIDDEN", "hidden")] {
        let request = Harness::build(
            "PUT",
            &format!("/v1/secrets/{path}"),
            Some(&harness.deploy_token),
            Some(serde_json::json!({ "value": value })),
        );
        harness.send(request);
    }

    let (status, body) = harness.get("/v1/list/infra", Some(&harness.deploy_token));
    assert_eq!(status, StatusCode::OK);

    let listed = body["paths"].to_string();
    assert!(listed.contains("infra/service-a/DB_PASSWORD"));
    assert!(!listed.contains("infra/ciphr"), "got {listed}");
}

#[test]
fn a_listing_carries_the_rotation_class_of_every_path_it_shows() {
    // The corpus question -- what has nobody classified yet? -- used to be answerable
    // only with the service stopped, because `ciphr list --rotation` goes through the
    // CLI and the CLI takes the exclusive store lock. This asks it of a running one.
    let harness = Harness::new();

    let request = Harness::build(
        "PUT",
        "/v1/secrets/infra/service-c/SEED",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "s", "rotation": "seed-only" })),
    );
    harness.send(request);

    let (status, body) = harness.get("/v1/list/infra", Some(&harness.deploy_token));
    assert_eq!(status, StatusCode::OK);

    let entries = body["entries"].as_array().expect("entries");
    let paths = body["paths"].as_array().expect("paths");
    assert_eq!(
        entries.len(),
        paths.len(),
        "both arrays carry the same set, so a client reading only `paths` sees no fewer"
    );
    for (entry, path) in entries.iter().zip(paths) {
        assert_eq!(&entry["path"], path, "and in the same order");
    }

    let seeded = entries
        .iter()
        .find(|entry| entry["path"] == "infra/service-c/SEED")
        .expect("the secret just written");
    assert_eq!(seeded["rotation"], "seed-only");

    let untouched = entries
        .iter()
        .find(|entry| entry["path"] == "infra/service-a/DB_PASSWORD")
        .expect("the fixture secret");
    assert_eq!(
        untouched["rotation"], "unclassified",
        "a secret nobody classified says so rather than claiming to be safe to rotate"
    );
}

#[test]
fn a_rotation_filter_narrows_the_listing_and_the_trail_counts_what_was_revealed() {
    let harness = Harness::new();

    let request = Harness::build(
        "PUT",
        "/v1/secrets/infra/service-c/SEED",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "s", "rotation": "seed-only" })),
    );
    harness.send(request);

    let (status, body) = harness.get(
        "/v1/list/infra?rotation=seed-only",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);

    let paths = body["paths"].as_array().expect("paths");
    assert_eq!(paths.len(), 1, "only the classified one, got {paths:?}");
    assert_eq!(paths[0], "infra/service-c/SEED");

    // The number in the trail is what left the process, not what the caller was
    // entitled to see. Recording the pre-filter count would overstate every filtered
    // read for as long as the trail is kept.
    let entries = harness.audit_entries();
    let listing = entries
        .iter()
        .rfind(|record| record["entry"]["action"] == "list")
        .expect("a list entry");
    assert_eq!(
        listing["entry"]["results"].as_u64(),
        Some(1),
        "the entry counts the filtered set, which is what was revealed"
    );
}

#[test]
fn an_unknown_rotation_class_in_a_filter_is_refused() {
    // The same asymmetry the write path has: a class on the way out is an open string,
    // a class on the way in is closed. Accepting one this build cannot interpret would
    // silently filter against nothing and return an empty listing that looks like an
    // answer.
    let harness = Harness::new();

    let (status, body) = harness.get(
        "/v1/list/infra?rotation=probably-fine",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let text = body.to_string();
    assert!(
        text.contains("probably-fine") && text.contains("unclassified"),
        "the refusal names what was sent and what the classes are, got {text}"
    );
}

#[test]
fn export_writes_one_audit_entry_per_secret_served() {
    // The property that makes a bulk read auditable at all. A collective entry for an
    // export is the blind spot that disqualified other candidates during the
    // evaluation.
    let harness = Harness::new();
    for path in ["infra/bulk/ONE", "infra/bulk/TWO", "infra/bulk/THREE"] {
        let request = Harness::build(
            "PUT",
            &format!("/v1/secrets/{path}"),
            Some(&harness.deploy_token),
            Some(serde_json::json!({ "value": "x" })),
        );
        harness.send(request);
    }

    let before = harness
        .audit_entries()
        .iter()
        .filter(|entry| entry["entry"]["action"] == "read")
        .count();

    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({
            "paths": ["infra/bulk/ONE", "infra/bulk/TWO", "infra/bulk/THREE"]
        })),
    );
    let (status, body) = harness.send(export);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secrets"].as_array().expect("array").len(), 3);

    let after = harness
        .audit_entries()
        .iter()
        .filter(|entry| entry["entry"]["action"] == "read")
        .count();
    assert_eq!(after - before, 3, "one entry per secret, not one per call");
}

/// An export names each path once, and at most 256 of them — and a refusal costs the
/// server a parse and nothing else.
///
/// Finding F5 of the review of 2026-08-24. `ExportRequest.paths` had no bound: one
/// authenticated request could name a path ten thousand times and buy an authorization,
/// a durable audit write, a store read and a decryption for each occurrence, all of it
/// under the process-wide store and audit mutexes, and then a *correcting* audit write
/// per path already processed if anything failed late.
///
/// The audit shape is the assertion that matters: **no `read` entries**. A refusal that
/// still authorized and decrypted would mean the structural checks had moved rather than
/// been moved *in front of* the work.
///
/// Not "no entries at all", which is what this asserted until F12 landed. A refused
/// request now writes exactly one `request-refused` entry, because an authenticated
/// caller making a request this server will not serve should not be invisible. The two
/// findings do not disagree: F5 is about the work not happening, F12 about the caller not
/// being silent, and one entry that names neither a path nor a decision is both.
#[test]
fn an_export_is_bounded_and_a_refusal_costs_no_work() {
    let harness = Harness::new();
    let request = Harness::build(
        "PUT",
        "/v1/secrets/infra/bulk/ONE",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "x" })),
    );
    harness.send(request);

    let reads_before = harness
        .audit_entries()
        .iter()
        .filter(|entry| entry["entry"]["action"] == "read")
        .count();

    // Too many.
    let many: Vec<String> = (0..257).map(|n| format!("infra/bulk/P{n}")).collect();
    let (status, body) = harness.send(Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": many })),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert!(
        body["detail"]
            .as_str()
            .expect("a detail")
            .contains("at most 256"),
        "the refusal names the limit, got {body}"
    );

    // The same path twice. Refused rather than deduplicated: asking twice is a caller
    // bug, and silently returning fewer entries than were asked for is how such a bug
    // reaches production.
    let (status, body) = harness.send(Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({
            "paths": ["infra/bulk/ONE", "infra/bulk/ONE"]
        })),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert!(
        body["detail"]
            .as_str()
            .expect("a detail")
            .contains("more than once"),
        "the refusal names the rule, got {body}"
    );

    // A malformed path *after* a valid one. This is the ordering the finding was about:
    // before the fix, the valid path ahead of it had already been authorized, recorded
    // and decrypted, and then corrected on the way out -- two entries bought by a
    // request that was never going to be served.
    let (status, body) = harness.send(Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({
            "paths": ["infra/bulk/ONE", "not a valid path!!"]
        })),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");

    let entries = harness.audit_entries();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["entry"]["action"] == "read")
            .count(),
        reads_before,
        "a structurally invalid export authorizes nothing and decrypts nothing"
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["entry"]["action"] == "request-refused")
            .count(),
        3,
        "one per refused call, and no more -- the caller is visible, the work is not done"
    );

    // The bytes that were malformed do not reach the trail. F11 made that argument about
    // a parse error on the way out; the same holds for the one artefact this project
    // keeps tamper-evident.
    let rendered = entries
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !rendered.contains("not a valid path!!"),
        "the refused input must not be echoed into the trail"
    );
}

/// An empty request is still refused, and still says so.
#[test]
fn an_export_with_no_paths_is_refused() {
    let harness = Harness::new();
    let (status, body) = harness.send(Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": [] })),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert!(
        body["detail"]
            .as_str()
            .expect("a detail")
            .contains("no paths"),
        "got {body}"
    );
}

/// Exactly the limit is allowed, so the boundary is a limit and not an off-by-one.
///
/// The paths do not exist, so this is refused for a different reason — `404` — and that
/// is the point: it got past the structural check, which is what is under test. Making
/// 256 real secrets to assert a boundary would be a slower test asserting the same thing.
#[test]
fn the_path_limit_is_inclusive() {
    let harness = Harness::new();
    let at_limit: Vec<String> = (0..256).map(|n| format!("infra/bulk/P{n}")).collect();
    let (status, body) = harness.send(Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "paths": at_limit })),
    ));
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "256 is allowed; the refusal above it is what bounds this, got {body}"
    );
}

#[test]
fn an_export_that_includes_one_forbidden_path_returns_nothing() {
    // Returning the permitted subset would let a caller map which paths they may read,
    // one export at a time.
    let harness = Harness::new();
    let export = Harness::build(
        "POST",
        "/v1/export",
        Some(&harness.deploy_token),
        Some(serde_json::json!({
            "paths": ["infra/service-a/DB_PASSWORD", "infra/ciphr/MASTER"]
        })),
    );

    let (status, body) = harness.send(export);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.to_string().contains("seeded"));
}

#[test]
fn the_administrative_endpoints_are_authorized_as_ordinary_paths() {
    let harness = Harness::new();

    // The auditor may read the audit trail and the configuration views.
    for uri in ["/v1/audit", "/v1/identities", "/v1/policies"] {
        let (status, _) = harness.get(uri, Some(&harness.auditor_token));
        assert_eq!(status, StatusCode::OK, "auditor must reach {uri}");
    }

    // The deploy runner may not, because no rule grants it `sys/**`.
    for uri in ["/v1/audit", "/v1/identities", "/v1/policies"] {
        let (status, _) = harness.get(uri, Some(&harness.deploy_token));
        assert_eq!(status, StatusCode::FORBIDDEN, "deploy must not reach {uri}");
    }
}

#[test]
fn the_audit_endpoint_returns_records_a_client_can_verify_itself() {
    let harness = Harness::new();
    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    let (status, body) = harness.get("/v1/audit?limit=50", Some(&harness.auditor_token));
    assert_eq!(status, StatusCode::OK);

    let entries = body["entries"].as_array().expect("array");
    assert!(!entries.is_empty());

    // Each entry carries its hash and the exact stored record, so the caller can check
    // the chain rather than trusting this endpoint about it.
    for entry in entries {
        assert!(entry["hash"].as_str().is_some_and(|hash| hash.len() == 64));
        assert!(entry["record"]["seq"].is_number());
        assert!(entry["record"]["prev_hash"].is_string());
    }

    // No secret value is anywhere in the audit trail.
    assert!(!body.to_string().contains("seeded"));
}

/// The property the test above cannot see, because it reads a parsed body.
///
/// `openapi.yaml` promises the record is returned as the exact bytes that were hashed, so
/// that a client can recompute the hash instead of trusting this endpoint. That was untrue
/// for as long as the response held a `serde_json::Value`: a `Value` is a sorted map, so
/// the fields came back in alphabetical order rather than the order they were hashed in,
/// and any client that recomputed the hash got a mismatch on an untouched chain.
#[test]
fn the_audit_endpoint_returns_the_exact_bytes_that_were_hashed() {
    let harness = Harness::new();
    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    let (status, text) = harness.get_text("/v1/audit?limit=50", Some(&harness.auditor_token));
    assert_eq!(status, StatusCode::OK);

    let stored = harness.audit_payloads();
    assert!(!stored.is_empty());

    for payload in &stored {
        assert!(
            text.contains(payload.as_str()),
            "the response must carry the stored record verbatim, and does not contain: {payload}"
        );
    }

    // And the hash it reports is the hash of those bytes, which is what makes the
    // recomputation the documentation invites actually possible.
    let body: serde_json::Value = serde_json::from_str(&text).expect("the body is JSON");
    let entries = body["entries"].as_array().expect("array");
    for (entry, payload) in entries.iter().zip(&stored) {
        assert_eq!(
            entry["hash"].as_str().expect("hash"),
            ciphr_core::hex::encode(&ciphr_audit::hash_payload(payload.as_bytes())),
            "sequence {} does not hash to what the endpoint reports",
            entry["seq"]
        );
    }
}

#[test]
fn audit_filters_are_applied_by_the_server() {
    let harness = Harness::new();
    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    harness.get(
        "/v1/secrets/infra/ciphr/DENIED",
        Some(&harness.deploy_token),
    );

    let (_, denied) = harness.get(
        "/v1/audit?decision=deny&identity=deploy",
        Some(&harness.auditor_token),
    );
    let entries = denied["entries"].as_array().expect("array");
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|entry| entry["record"]["entry"]["allowed"] == false),
        "a deny filter must return only denials"
    );

    let (status, _) = harness.get("/v1/audit?decision=maybe", Some(&harness.auditor_token));
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn every_endpoint_writes_an_audit_entry() {
    // The test that keeps the central promise honest as handlers are added. If a new
    // route serves a response without recording it, this fails.
    let harness = Harness::new();

    let cases: Vec<(&str, &str, Option<serde_json::Value>, &str)> = vec![
        (
            "GET",
            "/v1/secrets/infra/service-a/DB_PASSWORD",
            None,
            &harness.deploy_token,
        ),
        (
            "PUT",
            "/v1/secrets/infra/audited/VALUE",
            Some(serde_json::json!({ "value": "v" })),
            &harness.deploy_token,
        ),
        (
            "DELETE",
            "/v1/secrets/infra/audited/VALUE",
            None,
            &harness.deploy_token,
        ),
        (
            "GET",
            "/v1/versions/infra/service-a/DB_PASSWORD",
            None,
            &harness.deploy_token,
        ),
        ("GET", "/v1/list/infra", None, &harness.deploy_token),
        (
            "POST",
            "/v1/export",
            Some(serde_json::json!({ "paths": ["infra/service-a/DB_PASSWORD"] })),
            &harness.deploy_token,
        ),
        ("GET", "/v1/audit", None, &harness.auditor_token),
        ("GET", "/v1/identities", None, &harness.auditor_token),
        ("GET", "/v1/policies", None, &harness.auditor_token),
    ];

    for (method, uri, body, token) in cases {
        let before = harness.audit_entries().len();
        let request = Harness::build(method, uri, Some(token), body);
        let (status, _) = harness.send(request);
        let after = harness.audit_entries().len();

        assert!(
            status.is_success(),
            "{method} {uri} should succeed, got {status}"
        );
        assert!(after > before, "{method} {uri} produced no audit entry");
    }
}

#[test]
fn a_request_is_refused_when_the_audit_trail_cannot_be_written() {
    // Fail closed. The value exists, the caller is authorized, and the answer is still
    // 503 — because an access that could not be logged must not happen.
    let harness = Harness::with_audit(AuditKind::Failing);
    let (status, body) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "audit_unavailable");
    assert!(
        !body.to_string().contains("seeded"),
        "no value may be served when it cannot be logged"
    );
}

#[test]
fn a_write_is_not_performed_when_the_audit_trail_cannot_be_written() {
    // The ordering that matters for mutations: the entry comes first, so a failure
    // leaves the store untouched rather than changed-but-unlogged.
    let harness = Harness::with_audit(AuditKind::Failing);
    let write = Harness::build(
        "PUT",
        "/v1/secrets/infra/service-b/NEW",
        Some(&harness.deploy_token),
        Some(serde_json::json!({ "value": "must not be stored" })),
    );

    let (status, _) = harness.send(write);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let store = SqliteStore::open(&harness.database).expect("reopen");
    let path = SecretPath::parse("infra/service-b/NEW").expect("valid");
    assert!(
        store.metadata(&path).is_err(),
        "nothing may be written when the write cannot be logged"
    );
}

#[test]
fn health_reports_a_device_that_stopped_accepting_records() {
    // Finding 6. `AuditSink::record` reports which devices refused; before this the
    // server discarded that, so a second device failing every write for a month was
    // invisible in the API, in the health endpoint, and in the logs. That is the exact
    // state `device.rs` names as the thing to prevent.
    let harness = Harness::with_audit(AuditKind::Partial);

    let before = harness.get("/v1/health", None).1;
    let names: Vec<String> = before["audit_devices"]
        .as_array()
        .expect("array")
        .iter()
        .map(|d| d["name"].as_str().expect("name").to_owned())
        .collect();
    assert_eq!(names.len(), 2, "the harness configures two devices");
    assert_eq!(
        names,
        vec!["sqlite-1".to_owned(), "device-1".to_owned()],
        "labels, numbered within their kind in configuration order"
    );
    for device in before["audit_devices"].as_array().expect("array") {
        assert_eq!(
            device["accepting"],
            serde_json::Value::Null,
            "before the first record, no device has an outcome yet"
        );
    }

    // One authenticated request is enough: every endpoint writes an audit entry.
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "one working device is enough to serve the request"
    );

    let after = harness.get("/v1/health", None).1;
    let devices = after["audit_devices"].as_array().expect("array");
    // Selected by published label, in configuration order: the harness's `Partial`
    // sink is [sqlite, always-fails], and `always-fails` names itself without a `kind:`
    // prefix, so it is labelled `device-1`. Before F14 this test could look up the
    // device by the name it calls itself, which is exactly what the endpoint stopped
    // handing out.
    let working = devices
        .iter()
        .find(|d| d["name"] == "sqlite-1")
        .expect("the working device");
    let broken = devices
        .iter()
        .find(|d| d["name"] == "device-1")
        .expect("the failing device");

    assert_eq!(working["accepting"], true);
    assert_eq!(
        broken["accepting"], false,
        "a device that refused the last record must not look healthy"
    );
}

/// Finding F14 of the review of 2026-08-24: the audit devices are labelled, and the
/// label is not the path.
///
/// A device names itself `sqlite:/var/lib/ciphr/ciphr.db`. Publishing that on an
/// unauthenticated endpoint tells anyone who can reach the port where the database
/// lives — free reconnaissance, and a direct contradiction of the rule one field away,
/// which withholds a device's *failure reason* precisely because it names a path.
#[test]
fn health_labels_its_audit_devices_and_never_names_their_paths() {
    let harness = Harness::new();
    let body = harness.get("/v1/health", None).1;

    let devices = body["audit_devices"].as_array().expect("array");
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices[0]["name"], "sqlite-1",
        "a label, numbered within its kind"
    );

    // The whole response, not just the field: the path must not arrive by any route.
    let text = body.to_string();
    let database = harness.database.to_string_lossy().replace('\\', "/");
    let file_name = harness
        .database
        .file_name()
        .expect("a file name")
        .to_string_lossy()
        .into_owned();
    assert!(
        !text.contains(&*database) && !text.contains(&file_name),
        "the database path must not appear in an unauthenticated response, got {text}"
    );
    assert!(
        !text.contains("sqlite:"),
        "nor the device's own `kind:path` name, got {text}"
    );
}

/// A device quarantined at startup is in the trail, not only on `/v1/health`.
///
/// Finding 1 of [the field report of 2026-08-25]. That deployment measured it: a
/// throwaway server holding a quarantined file device reported itself healthy, its
/// container health check passed, and `docker logs` was empty. The only place the state
/// existed was one field on one unauthenticated JSON route -- for the one state the
/// release notes describe as needing a human, and the one that never clears while the
/// process runs.
///
/// It is also the case that fires most often: the first start after an upgrade, for any
/// deployment whose file device had already fallen behind. That is precisely when
/// somebody is watching a deploy log and precisely when the monitoring rule for a field
/// introduced in the same release has not been written yet.
#[test]
fn a_device_quarantined_at_startup_is_in_the_trail() {
    let harness = Harness::with_audit(AuditKind::Behind);

    let entries = harness.audit_entries();
    let stopped: Vec<_> = entries
        .iter()
        .filter(|entry| entry["entry"]["action"] == "audit-device-failed")
        .collect();
    assert_eq!(
        stopped.len(),
        1,
        "one entry, written before the first request"
    );
    assert_eq!(
        stopped[0]["entry"]["deny_reason"], "device-behind-at-start: file:/tmp/behind.jsonl",
        "and it says which device, and that this is the startup case"
    );
    assert_eq!(
        stopped[0]["entry"]["detail"], "missed from seq 2",
        "where it stopped, which is what the recovery procedure needs"
    );

    // And health still says it too -- the trail is the artefact, the route is the
    // interface, and this finding was about there being only one of them.
    let health = harness.get("/v1/health", None).1;
    let device = health["audit_devices"]
        .as_array()
        .expect("array")
        .iter()
        .find(|d| d["name"] == "file-1")
        .expect("the device that fell behind");
    assert_eq!(device["quarantined_from"], 2);
    assert_eq!(device["accepting"], false);
}

/// A device stopped at runtime says so in the trail, and not just that it refused once.
///
/// Finding 1 of the field report of 2026-08-25 is about the *startup* case; this is the
/// other half of the same complaint. The trail already carried an entry when a device
/// refused a record, but it read the same whether the device recovered on its own or was
/// stopped for good — and a reader who cannot tell those apart has to treat every refusal
/// as the expensive one.
#[test]
fn the_trail_says_a_device_was_stopped_and_not_merely_that_it_refused() {
    let harness = Harness::with_audit(AuditKind::Partial);

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);

    let entries = harness.audit_entries();
    let device_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry["entry"]["action"] == "audit-device-failed")
        .collect();
    assert_eq!(
        device_entries.len(),
        1,
        "one entry for the device that missed it"
    );
    assert_eq!(
        device_entries[0]["entry"]["deny_reason"], "device-quarantined: always-fails",
        "stopped for good, which `device-refused` alone would not say"
    );

    // A second request does not add another: the device is not asked any more, so it
    // refuses nothing and there is nothing further to explain.
    harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(
        harness
            .audit_entries()
            .iter()
            .filter(|entry| entry["entry"]["action"] == "audit-device-failed")
            .count(),
        1,
        "the gap is explained once, not once per later request"
    );
}

/// A device that missed a record is stopped, and health says so and keeps saying so.
///
/// Finding F6 of the review of 2026-08-24. Two halves, and the second is the one that
/// would regress silently: a quarantined device is no longer *asked*, so it is absent
/// from the failure list of every later record — and a naive reading of that list would
/// mark it as accepting again. Health would then be green over a copy of the audit trail
/// that stopped growing an hour ago.
#[test]
fn a_quarantined_device_is_reported_and_does_not_go_green_again() {
    let harness = Harness::with_audit(AuditKind::Partial);

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "one working device serves the request"
    );

    let after = harness.get("/v1/health", None).1;
    let devices = after["audit_devices"].as_array().expect("array");
    let broken = devices
        .iter()
        .find(|d| d["name"] == "device-1")
        .expect("the failing device");
    assert_eq!(
        broken["quarantined_from"], 1,
        "it missed the first record, and that is the number to alert on"
    );
    assert_eq!(broken["accepting"], false);

    let working = devices
        .iter()
        .find(|d| d["name"] == "sqlite-1")
        .expect("the working device");
    assert!(
        working.get("quarantined_from").is_none(),
        "a device that is still being written to carries no such field"
    );

    // A second request. The quarantined device is skipped, so it fails nothing -- and
    // must not be reported as healthy for it.
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);

    let later = harness.get("/v1/health", None).1;
    let broken = later["audit_devices"]
        .as_array()
        .expect("array")
        .iter()
        .find(|d| d["name"] == "device-1")
        .expect("still listed");
    assert_eq!(
        broken["accepting"], false,
        "not asked is not the same as accepting"
    );
    assert_eq!(broken["quarantined_from"], 1, "and it stays stopped");
}

#[test]
fn health_never_reports_why_a_device_failed() {
    // The endpoint is unauthenticated. A device failure message names a path or a
    // database, so the boolean is reported and the reason is not.
    let harness = Harness::with_audit(AuditKind::Partial);
    let _ = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );

    let text = harness.get("/v1/health", None).1.to_string();
    assert!(
        !text.contains("this device always fails"),
        "the reason must stay out of an unauthenticated response, got {text}"
    );
}

#[test]
fn a_listing_records_how_much_it_revealed_and_claims_no_rule() {
    // Finding 4. The entry used to be a plain `Entry::allowed` with no rule attached --
    // an allow the evaluator never produced, which is the falsifier D4 names for itself.
    // Listings authorize per returned path, so there is no single decision to record;
    // what the trail can honestly carry is how many paths were revealed.
    let harness = Harness::new();

    // `deploy` may list `infra/**` but is denied everything under `infra/ciphr/**`.
    let (status, body) = harness.get("/v1/list/infra", Some(&harness.deploy_token));
    assert_eq!(status, StatusCode::OK);
    let returned = body["paths"].as_array().expect("paths").len();

    let entries = harness.audit_entries();
    let listing = entries
        .iter()
        .rfind(|record| record["entry"]["action"] == "list")
        .expect("a list entry");

    assert_eq!(
        listing["entry"]["results"].as_u64(),
        Some(returned as u64),
        "the entry must say how many paths the caller was shown"
    );
    assert!(
        listing["entry"]["rule"].is_null(),
        "a listing attaches no rule, because no single rule decided it"
    );
    assert_eq!(listing["entry"]["path"], "infra");
}

#[test]
fn a_device_that_refuses_a_record_is_recorded_by_the_ones_that_accepted() {
    // Finding 8. The chain advances when any device accepts, so a refusing device is
    // missing that sequence number for good -- and a gap, found later, is
    // indistinguishable from a deleted entry. The recovery procedure that follows from
    // that assumes the surrounding accesses were unlogged, which is an expensive answer
    // to give for a disk that was briefly full. The devices that did accept now carry
    // the reason the other one did not.
    let harness = Harness::with_audit(AuditKind::Partial);

    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK, "one working device still serves");

    let entries = harness.audit_entries();
    let explanation = entries
        .iter()
        .find(|record| record["entry"]["action"] == "audit-device-failed")
        .expect("the working device must record that the other one refused");

    let reason = explanation["entry"]["deny_reason"]
        .as_str()
        .expect("a reason");
    assert!(
        reason.contains("always-fails"),
        "the entry must name which copy has the gap, got {reason}"
    );

    // It must not claim to be an access by anyone.
    assert!(explanation["entry"]["principal"].is_null());
    assert!(explanation["entry"]["path"].is_null());
}

/// The audit trail records the address the listener saw, and nothing when it saw none.
///
/// Both halves are the property. Plan section 23 keys its rate limit on this address and
/// its audit section records it, and before this existed `request_context` returned
/// `None` unconditionally while the comment above it described taking the address from
/// the connection -- so an unauthenticated denial was countable and unattributable. The
/// second half matters for this crate: a router driven by `oneshot` is told no address,
/// and that has to be a missing field rather than a failed request.
#[test]
fn the_trail_records_the_address_the_listener_saw() {
    let harness = Harness::new();

    let mut with_address = Harness::build(
        "GET",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        None,
    );
    let peer: SocketAddr = "10.0.0.7:54321".parse().expect("address");
    with_address.extensions_mut().insert(ConnectInfo(peer));
    let (status, _) = harness.send(with_address);
    assert_eq!(status, StatusCode::OK);

    // An IPv4 peer on a dual-stack listener arrives mapped. One host must not appear
    // under two spellings in the same trail.
    let mut mapped = Harness::build(
        "GET",
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
        None,
    );
    let mapped_peer: SocketAddr = "[::ffff:10.0.0.8]:40000".parse().expect("address");
    mapped.extensions_mut().insert(ConnectInfo(mapped_peer));
    assert_eq!(harness.send(mapped).0, StatusCode::OK);

    // No connection information at all: the request succeeds and the field is absent.
    let (status, _) = harness.get(
        "/v1/secrets/infra/service-a/DB_PASSWORD",
        Some(&harness.deploy_token),
    );
    assert_eq!(status, StatusCode::OK);

    let (_, body) = harness.get("/v1/audit?limit=50", Some(&harness.auditor_token));
    let addresses: Vec<Option<&str>> = body["entries"]
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["record"]["entry"]["request"]["client_ip"].as_str())
        .collect();

    assert!(
        addresses.contains(&Some("10.0.0.7")),
        "the peer address belongs in the trail, got {addresses:?}"
    );
    assert!(
        addresses.contains(&Some("10.0.0.8")),
        "an IPv4-mapped peer must be recorded as IPv4, got {addresses:?}"
    );
    assert!(
        !addresses.iter().any(|address| address
            .is_some_and(|address| address.contains("54321") || address.contains(':'))),
        "the port is per-connection noise and does not belong in the trail, got {addresses:?}"
    );
    assert!(
        addresses.contains(&None),
        "a request with no connection information records no address, got {addresses:?}"
    );
}

// ---------------------------------------------------------------------------
// `POST /v1/tokens/{token_id}/revoke` — the one write this API may do (ADR-24)
// ---------------------------------------------------------------------------

/// The token id of a token, as the store and the trail spell it.
fn token_id_of(text: &str) -> String {
    Token::parse(text)
        .expect("a token this harness issued")
        .id()
        .as_text()
}

/// A harness whose surface has the revoke route on, plus the routes the assertions
/// below read the trail through.
fn revoking_harness() -> Harness {
    Harness::with_surface(&["viewer_api", "token_revoke"])
}

/// Off means absent, and for a *write* route that is the property worth pinning first:
/// a deployment that has not named this entry has no privileged write path at all, not
/// a handler that decides to refuse (ADR-20, ADR-24).
#[test]
fn the_revoke_route_is_absent_until_the_entry_names_it() {
    let harness = Harness::new();
    let target = token_id_of(&harness.deploy_token);

    let (status, _) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unnamed entry is a route axum answers from the fallback"
    );
}

/// The whole point of the endpoint: a leaked credential stops working, and the service
/// keeps running while it happens.
#[test]
fn revoking_over_the_api_stops_the_token_authenticating() {
    let harness = revoking_harness();
    let target = token_id_of(&harness.deploy_token);

    // It works before.
    let (status, _) = harness.get("/v1/list/infra", Some(&harness.deploy_token.clone()));
    assert_eq!(status, StatusCode::OK);

    let (status, body) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["identity"], "deploy", "whose credential it was");
    assert_eq!(body["revoked_now"], true, "this call is what revoked it");

    // And not afterwards. `AppState::authenticate` checks revocation per request, which
    // is why writing the row was the only thing missing.
    let (status, _) = harness.get("/v1/list/infra", Some(&harness.deploy_token.clone()));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked token authenticates nothing, on the next request"
    );
}

/// A retry is safe, and says which call did the work.
#[test]
fn a_second_revoke_succeeds_and_reports_that_it_changed_nothing() {
    let harness = revoking_harness();
    let target = token_id_of(&harness.deploy_token);
    let uri = format!("/v1/tokens/{target}/revoke");

    let (status, first) = harness.send(Harness::build(
        "POST",
        &uri,
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["revoked_now"], true);

    let (status, second) = harness.send(Harness::build(
        "POST",
        &uri,
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(
        status,
        StatusCode::OK,
        "a retry after a network failure must not be an error"
    );
    assert_eq!(
        second["revoked_now"], false,
        "the second write established nothing, and the response says so"
    );
}

/// `revoked_now` is the write's own answer, not a read taken before it.
///
/// Finding F8 of the review of 2026-08-24. The field used to be
/// `found.revoked_at.is_none()`, evaluated on a row read *before* the mutation and
/// before the audit entry, so two responders revoking the same leaked credential at the
/// same moment were both told they were the one who stopped it. One of them was wrong,
/// during precisely the conversation where that matters.
///
/// A genuine interleaving cannot be forced deterministically from here, so this asserts
/// the property that makes the interleaving harmless: the token is revoked out of band,
/// through the store the handler shares, and the response still says `false` even though
/// nothing about the request changed. There is no longer a read whose staleness could be
/// observed -- `WHERE revoked_at IS NULL` makes the database decide, and it decides once.
#[test]
fn revoked_now_reflects_the_write_and_not_a_stale_read() {
    let harness = revoking_harness();
    let target = token_id_of(&harness.deploy_token);

    let mut store = SqliteStore::open(&harness.database).expect("reopen");
    assert!(
        store.revoke_token(&target).expect("out-of-band revoke"),
        "the out-of-band call is the one that revoked it"
    );
    drop(store);

    let (status, body) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(
        body["revoked_now"], false,
        "somebody else established the timestamp, and this call says so"
    );
}

/// The entry names who acted *and* whose credential stopped working — the second half is
/// what makes "when did this credential stop working" answerable, and it is the same
/// shape the CLI records for the same operation.
#[test]
fn a_revocation_is_recorded_with_the_token_as_its_subject() {
    let harness = revoking_harness();
    let target = token_id_of(&harness.deploy_token);

    let (status, _) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::OK);

    let payloads = harness.audit_payloads();
    let entry = payloads
        .iter()
        .find(|payload| payload.contains("\"revoke-token\""))
        .unwrap_or_else(|| panic!("a revocation writes an entry, got {payloads:?}"));

    assert!(
        entry.contains("\"principal\":{\"name\":\"auditor\""),
        "the authenticated identity acted, not `cli:$USER`: {entry}"
    );
    assert!(
        entry.contains(&format!("\"token_id\":\"{target}\"")),
        "the subject names the credential: {entry}"
    );
    assert!(
        entry.contains("\"path\":\"sys/tokens\""),
        "authorized as the reserved path: {entry}"
    );
}

/// `revoke` is the only capability that reaches it — a broad secret grant does not, which
/// is ADR-23's property doing its work at the route it was needed for.
#[test]
fn an_identity_without_the_capability_cannot_revoke() {
    let harness = revoking_harness();
    let target = token_id_of(&harness.auditor_token);

    // `deploy` holds read and list across `infra/**` and nothing under `sys/`.
    let (status, _) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.deploy_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And the credential still works, because nothing was written.
    let (status, _) = harness.get("/v1/audit?limit=1", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);
}

/// Whether a token id exists is not answerable without the capability.
///
/// The handler looks the id up *before* it records the decision, so that the entry can
/// name the credential — and this is the test that the order does not leak: an
/// unauthorized caller gets the same `403` for an id that exists and one that does not,
/// and only an authorized caller ever sees the `404`.
#[test]
fn a_missing_token_is_a_404_only_for_a_caller_that_may_revoke() {
    let harness = revoking_harness();
    let missing = "zzzzzzzz";
    let existing = token_id_of(&harness.deploy_token);

    let (status, _) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{missing}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "authorized, and nothing matched"
    );

    for id in [missing, existing.as_str()] {
        let (status, _) = harness.send(Harness::build(
            "POST",
            &format!("/v1/tokens/{id}/revoke"),
            Some(&harness.deploy_token.clone()),
            None,
        ));
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "existence must not be observable without `revoke`"
        );
    }
}

// ---------------------------------------------------------------------------
// `GET /v1/tokens` — the authenticated answer to "is this credential still valid"
// ---------------------------------------------------------------------------

/// A harness with the token inventory readable, and the revoke route beside it where a
/// test needs to change a state and then read it back.
fn token_status_harness() -> Harness {
    Harness::with_surface(&["token_status", "token_revoke"])
}

/// Off means absent, here as everywhere.
#[test]
fn the_token_inventory_is_absent_until_the_entry_names_it() {
    let harness = Harness::new();

    let (status, _) = harness.get("/v1/tokens", Some(&harness.auditor_token.clone()));

    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// What the inventory says, and — the half that matters more — what it does not contain.
#[test]
fn the_inventory_carries_metadata_and_no_credential() {
    let harness = token_status_harness();

    let (status, body) = harness.get("/v1/tokens", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK);

    let tokens = body["tokens"].as_array().expect("an array");
    assert!(
        tokens.len() >= 3,
        "the harness issued three, got {}",
        tokens.len()
    );

    let deploy_id = token_id_of(&harness.deploy_token);
    let entry = tokens
        .iter()
        .find(|token| token["token_id"] == deploy_id)
        .expect("the deploy token is in the inventory");
    assert_eq!(entry["identity"], "deploy");
    assert_eq!(
        entry["state"], "valid",
        "it has not been revoked or expired"
    );
    assert!(entry["created_at"].is_i64(), "issued when");
    assert_eq!(entry["honeypot"], false);

    // The bait token is visible *here* and nowhere a caller could see it: ADR-15 allows
    // the administrative read path to say which credential is bait, because the
    // deployment has to know and whoever presents it must not be able to tell.
    let bait_id = token_id_of(&harness.bait_token);
    let bait = tokens
        .iter()
        .find(|token| token["token_id"] == bait_id)
        .expect("bait is a token like any other in the store");
    assert_eq!(bait["honeypot"], true);

    // No verifier, no token, nothing derived from one. Checked against the whole
    // document rather than field by field, so a field added later cannot smuggle one in.
    let serialized = body.to_string();
    for secret in [
        harness.deploy_token.as_str(),
        harness.auditor_token.as_str(),
        harness.bait_token.as_str(),
    ] {
        assert!(
            !serialized.contains(secret),
            "a token must never appear in the inventory"
        );
    }
    assert!(
        !serialized.contains("verifier"),
        "and neither may the thing it is checked against: {serialized}"
    );
}

/// `inspect` on `sys/tokens` and nothing else reaches it — a broad secret grant does not.
#[test]
fn reading_the_inventory_needs_inspect_on_the_token_path() {
    let harness = token_status_harness();

    let (status, _) = harness.get("/v1/tokens", Some(&harness.deploy_token.clone()));

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "`deploy` holds read and list across infra/** and nothing under sys/"
    );
}

/// The state is derived in one place, so the API and the CLI cannot disagree — and a
/// revocation over the API is visible in the next read.
#[test]
fn a_revoked_token_reads_as_revoked() {
    let harness = token_status_harness();
    let target = token_id_of(&harness.deploy_token);

    let (status, _) = harness.send(Harness::build(
        "POST",
        &format!("/v1/tokens/{target}/revoke"),
        Some(&harness.auditor_token.clone()),
        None,
    ));
    assert_eq!(status, StatusCode::OK);

    let (status, body) = harness.get(
        "/v1/tokens?identity=deploy",
        Some(&harness.auditor_token.clone()),
    );
    assert_eq!(status, StatusCode::OK);

    let tokens = body["tokens"].as_array().expect("an array");
    assert!(
        tokens.iter().all(|token| token["identity"] == "deploy"),
        "?identity= narrows the listing, got {body}"
    );
    let entry = tokens
        .iter()
        .find(|token| token["token_id"] == target)
        .expect("the revoked token stays in the inventory");
    assert_eq!(entry["state"], "revoked");
    assert!(
        entry["revoked_at"].is_i64(),
        "and the timestamp it was revoked at is there: {entry}"
    );
}

// ---------------------------------------------------------------------------
// OIDC federation (ADR-26)
// ---------------------------------------------------------------------------

/// A P-256 key pair, and the JWK halves a configuration would carry.
///
/// Generated per test rather than checked in. `AGENTS.md` rules out test fixtures that
/// look like real key material, which is also why `rcgen` produces the TLS certificates
/// for the end-to-end tests. ES256 rather than RS256 because `ring` cannot generate an
/// RSA key at all -- the RSA verification path has its own known-answer test in
/// `crates/ciphr-server/src/oidc.rs`, against the vector in RFC 7515.
struct Signer {
    pair: ring::signature::EcdsaKeyPair,
    random: ring::rand::SystemRandom,
    x: String,
    y: String,
}

impl Signer {
    fn new() -> Self {
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &random,
        )
        .expect("a P-256 key");
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &random,
        )
        .expect("the key parses");

        let point = ring::signature::KeyPair::public_key(&pair)
            .as_ref()
            .to_vec();
        Self {
            pair,
            random,
            x: ciphr_core::base64url::encode(&point[1..33]),
            y: ciphr_core::base64url::encode(&point[33..65]),
        }
    }

    /// The provider stanzas a deployment would write for this key.
    fn providers(&self, bindings: &str) -> String {
        format!(
            "[[oidc]]\n\
             name = \"forge\"\n\
             issuer = \"https://forge.example/api/actions\"\n\
             audience = \"ciphr\"\n\
             ttl = \"15m\"\n\
             [[oidc.key]]\n\
             alg = \"ES256\"\n\
             kid = \"k1\"\n\
             x = \"{}\"\n\
             y = \"{}\"\n\
             {bindings}",
            self.x, self.y
        )
    }

    /// A signed ID token carrying exactly these claims.
    fn token(&self, claims: &serde_json::Value) -> String {
        let header = ciphr_core::base64url::encode(br#"{"alg":"ES256","kid":"k1"}"#);
        let payload = ciphr_core::base64url::encode(claims.to_string().as_bytes());
        let signed = format!("{header}.{payload}");
        let signature = self
            .pair
            .sign(&self.random, signed.as_bytes())
            .expect("signing succeeds");
        format!(
            "{signed}.{}",
            ciphr_core::base64url::encode(signature.as_ref())
        )
    }
}

/// Claims a forge would issue for a job, valid far enough into the future.
fn job_claims() -> serde_json::Value {
    serde_json::json!({
        "iss": "https://forge.example/api/actions",
        "aud": "ciphr",
        "sub": "repo:acme/widget:ref:refs/heads/main",
        "exp": 4_000_000_000_i64,
    })
}

/// The binding that turns those claims into the `deploy` identity of `POLICIES`.
fn deploy_binding() -> String {
    concat!(
        "[[oidc.binding]]\n",
        "identity = \"deploy\"\n",
        "claims = { sub = \"repo:acme/widget:ref:refs/heads/main\" }\n"
    )
    .to_owned()
}

fn login(harness: &Harness, id_token: &str) -> (StatusCode, serde_json::Value) {
    let request = Harness::build(
        "POST",
        "/v1/auth/oidc/login",
        None,
        Some(serde_json::json!({ "id_token": id_token })),
    );
    harness.send(request)
}

/// The whole point of the route: what comes back is a credential that works.
///
/// Asserted by *using* it rather than by reading the body. A response carrying a
/// well-formed token the store cannot verify would satisfy any test that only inspected
/// the JSON, and that is exactly the failure this route could have.
#[test]
fn a_federated_exchange_hands_back_a_token_that_authenticates() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    let (status, body) = login(&harness, &signer.token(&job_claims()));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["identity"], "deploy");

    let token = body["token"].as_str().expect("a token").to_owned();
    assert!(token.starts_with("cph_"), "the ordinary token format");
    assert_eq!(
        body["token_id"].as_str().expect("an identifier"),
        &token[4..12],
        "the identifier in the response is the token's own, which is what the trail names"
    );

    // The credential the exchange minted, used on an ordinary route.
    let (status, secret) = harness.get("/v1/secrets/infra/service-a/DB_PASSWORD", Some(&token));
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], "seeded");

    // And it expires, which is the property the long-lived bootstrap token did not have.
    assert!(
        body["expires_at"].as_i64().unwrap_or_default() > 0,
        "a federated token without an expiry would be the credential this route removes"
    );
}

/// The trail names the identity, the provider and the verified claim.
#[test]
fn the_trail_says_which_provider_vouched_and_for_which_claim() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    let (status, _) = login(&harness, &signer.token(&job_claims()));
    assert_eq!(status, StatusCode::OK);

    let entries = harness.audit_entries();
    let entry = entries
        .iter()
        .find(|record| record["entry"]["action"] == "federate-token")
        .expect("a federated exchange is recorded");

    assert_eq!(entry["entry"]["allowed"], true);
    assert_eq!(
        entry["entry"]["principal"]["name"], "oidc:forge",
        "the actor is the provider: no credential of this system was presented"
    );
    assert_eq!(entry["entry"]["subject"]["name"], "deploy");
    assert_eq!(entry["entry"]["subject"]["kind"], "machine");
    assert!(
        entry["entry"]["subject"]["token_id"].is_string(),
        "the entry names the credential it minted: {entry}"
    );
    assert_eq!(
        entry["entry"]["detail"], "sub: repo:acme/widget:ref:refs/heads/main",
        "the verified claim, which is the only field that says which job this was"
    );
    assert_eq!(entry["entry"]["path"], "sys/tokens");

    // What it must never carry. Every JWT this test can produce starts its header with
    // `eyJ`, so this catches the presented token in any field.
    let text = entry.to_string();
    assert!(
        !text.contains("eyJ"),
        "the presented token must not reach the trail: {text}"
    );
}

/// Four refusals of a verified token, four findings, one status code.
#[test]
fn a_verified_token_that_is_refused_says_why_in_the_trail_and_not_on_the_wire() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    let cases: &[(&str, serde_json::Value)] = &[
        (
            "expired",
            serde_json::json!({
                "iss": "https://forge.example/api/actions",
                "aud": "ciphr",
                "sub": "repo:acme/widget:ref:refs/heads/main",
                "exp": 1_000_000_000_i64,
            }),
        ),
        (
            "audience-mismatch",
            serde_json::json!({
                "iss": "https://forge.example/api/actions",
                "aud": "some-other-service",
                "sub": "repo:acme/widget:ref:refs/heads/main",
                "exp": 4_000_000_000_i64,
            }),
        ),
        (
            "no-binding",
            serde_json::json!({
                "iss": "https://forge.example/api/actions",
                "aud": "ciphr",
                "sub": "repo:acme/widget:ref:refs/heads/other",
                "exp": 4_000_000_000_i64,
            }),
        ),
        (
            "missing-expiry",
            serde_json::json!({
                "iss": "https://forge.example/api/actions",
                "aud": "ciphr",
                "sub": "repo:acme/widget:ref:refs/heads/main",
            }),
        ),
    ];

    for (expected, claims) in cases {
        let before = harness.audit_entries().len();
        let (status, body) = login(&harness, &signer.token(claims));

        // Identical on the wire, whichever of the four it was. The module documentation
        // of `crate::error` is the rule this keeps: a caller that learns why it was
        // refused learns something about the configuration.
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{expected}");
        assert_eq!(body["error"], "unauthenticated", "{expected}");
        assert!(
            body.get("detail").is_none(),
            "a 401 explains nothing: {body}"
        );

        let entries = harness.audit_entries();
        assert_eq!(
            entries.len(),
            before + 1,
            "a verified token that was refused is worth exactly one line ({expected})"
        );
        let entry = entries.last().expect("the entry just written");
        assert_eq!(entry["entry"]["action"], "federate-token", "{expected}");
        assert_eq!(entry["entry"]["allowed"], false, "{expected}");
        assert_eq!(
            entry["entry"]["deny_reason"], *expected,
            "the four refusals do not collapse into one: {entry}"
        );
    }
}

/// An unverifiable token is refused and *not* recorded, and that is the decision.
///
/// The route is unauthenticated, so an entry per attempt would be an anonymous write
/// into a fail-closed trail: fill it and every later request is a `503`. The router
/// fallback and `AuditedJson` draw the line in the same place, and ADR-16 deferred a
/// whole phase over the same cost. The consequence is asserted here rather than only
/// argued in prose: a flood of forged tokens leaves no trail, and
/// `docs/operations/federation.md` says so out loud.
#[test]
fn an_unverifiable_token_writes_nothing_at_all() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    // Correct claims, somebody else's key.
    let forged = Signer::new().token(&job_claims());
    let unknown_issuer = signer.token(&serde_json::json!({
        "iss": "https://somebody-else/api/actions",
        "aud": "ciphr",
        "sub": "repo:acme/widget:ref:refs/heads/main",
        "exp": 4_000_000_000_i64,
    }));

    for id_token in [forged.as_str(), unknown_issuer.as_str(), "not-a-token", ""] {
        let before = harness.audit_entries().len();
        let (status, _) = login(&harness, id_token);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            harness.audit_entries().len(),
            before,
            "an anonymous caller writes nothing to a fail-closed trail"
        );
    }
}

/// A caller may ask for less than the configured lifetime, and never for more.
#[test]
fn the_lifetime_is_a_ceiling_a_caller_can_only_lower() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    let ask = |seconds: i64| {
        let request = Harness::build(
            "POST",
            "/v1/auth/oidc/login",
            None,
            Some(serde_json::json!({
                "id_token": signer.token(&job_claims()),
                "ttl_seconds": seconds,
            })),
        );
        harness.send(request)
    };

    // The configured ceiling is fifteen minutes. A shorter ask is honoured; a longer one
    // is reduced rather than refused, because the caller asked for convenience and the
    // deployment's answer is the only direction this route may move in.
    let (status, shorter) = ask(120);
    assert_eq!(status, StatusCode::OK, "{shorter}");
    let (status, longer) = ask(86_400);
    assert_eq!(status, StatusCode::OK, "{longer}");

    let shorter_expiry = shorter["expires_at"].as_i64().expect("an expiry");
    let longer_expiry = longer["expires_at"].as_i64().expect("an expiry");
    assert!(
        longer_expiry - shorter_expiry < 15 * 60 * 1000,
        "a day was asked for and at most the configured fifteen minutes was given: \
         {shorter_expiry} then {longer_expiry}"
    );

    // Zero is a request shape this route will not honour, and it says so -- before
    // anything is verified, because it is a fact about the request rather than about the
    // configuration.
    let (status, body) = ask(0);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"].as_str().unwrap_or_default().contains("ttl"),
        "{body}"
    );
}

/// The credential an exchange minted is in the inventory, and says where it came from.
#[test]
fn a_federated_token_is_visible_in_the_inventory_as_one() {
    let signer = Signer::new();
    let harness = Harness::with_federation(&signer.providers(&deploy_binding()));

    let (status, body) = login(&harness, &signer.token(&job_claims()));
    assert_eq!(status, StatusCode::OK, "{body}");
    let token_id = body["token_id"].as_str().expect("an identifier").to_owned();

    let (status, inventory) = harness.get("/v1/tokens", Some(&harness.auditor_token.clone()));
    assert_eq!(status, StatusCode::OK, "{inventory}");

    let record = inventory["tokens"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|entry| entry["token_id"] == token_id)
        .expect("the minted credential is in the inventory")
        .clone();

    assert_eq!(record["identity"], "deploy");
    assert_eq!(
        record["created_by"], "oidc:forge",
        "which path minted the row, readable without joining the trail"
    );
    assert!(
        record["expires_at"].is_i64(),
        "a federated credential always expires: {record}"
    );
    assert_eq!(record["state"], "valid");
}
