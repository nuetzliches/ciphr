//! End-to-end tests of the HTTP API, through the real router.
//!
//! No mocks and no test mode: these drive the same routes, the same authentication,
//! the same evaluator, and the same audit sink that a deployment does. The one thing
//! they skip is TLS, because a TCP listener is not what any of these assertions are
//! about — the transport is covered by `tls.rs`.
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

  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["read"]

  [[policy.rule]]
  path         = "sys/identities"
  capabilities = ["read"]

  [[policy.rule]]
  path         = "sys/policies"
  capabilities = ["read"]
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
        };
        let sink = AuditSink::new(devices, Chain::new()).expect("sink");

        let policies = ciphr_policy::PolicySet::from_toml(POLICIES).expect("policies");
        let state = AppState::new(
            store,
            sink,
            policies,
            root,
            "static".to_owned(),
            "supplied".to_owned(),
            // The surface the default build has: nothing. A test that wants an entry
            // resolves one explicitly, so no test inherits a shape it did not ask for.
            ciphr_server::ActiveSurface::default(),
        );

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
}

/// A device that refuses everything, for the fail-closed test.
struct AlwaysFails;

impl AuditDevice for AlwaysFails {
    fn name(&self) -> &'static str {
        "always-fails"
    }

    fn write(&mut self, _record: &EncodedRecord) -> Result<(), String> {
        Err("this device always fails".to_owned())
    }
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
    let working = devices
        .iter()
        .find(|d| d["name"] != "always-fails")
        .expect("the working device");
    let broken = devices
        .iter()
        .find(|d| d["name"] == "always-fails")
        .expect("the failing device");

    assert_eq!(working["accepting"], true);
    assert_eq!(
        broken["accepting"], false,
        "a device that refused the last record must not look healthy"
    );
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
