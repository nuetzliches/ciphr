//! A backup, restored into place, serving secrets over the real router.
//!
//! `docs/operations/backup.md` makes claims a restore depends on, and until this file
//! existed every one of them was prose. The store-level tests prove a copy is a readable
//! database; that is not the same claim. What an operator needs is that the file **works
//! as the deployment's store afterwards** — the seal record opens with the same master
//! key, tokens issued before the backup still authenticate, the policy evaluator still
//! decides, and the audit chain continues from the restored head rather than colliding
//! with it. Any one of those failing turns a restore into an outage, and none of them is
//! visible from the file's size.
//!
//! The restore here is the procedure the document describes: the live database is
//! removed, sidecars included, and the backup is moved into its place. Nothing is
//! reached into; the server is then built on whatever is at that path.
//!
//! Two of these pin *consequences* rather than features — a restore rolls back a token
//! revocation, and rolls back a secret written after the backup. Both are documented, and
//! a documented consequence with no test is how this project got a runbook whose
//! procedure was wrong.
//!
//! # What each half proves, measured rather than assumed
//!
//! The suite was run with `restore` replaced by a no-op, to find out which assertions
//! actually depend on the file having been swapped. Two failed and two did not, and the
//! split is worth knowing before trusting any single one of them:
//!
//! - `a_restored_backup_serves_the_secrets_it_held` and
//!   `the_audit_chain_continues_from_the_restored_head` **passed** without a restore.
//!   They establish that the store at that path works; they cannot tell a restored file
//!   from the original, because both hold the same secret.
//! - `a_restored_backup_is_missing_what_was_written_after_it` and
//!   `a_restored_backup_accepts_a_token_that_was_revoked_after_it` **failed**. They are
//!   what makes the suite about the backup: each asserts something that is true of the
//!   copy and false of the live database it replaced.
//!
//! So the first two are the "does it work" half and the last two are the "is it the
//! backup" half, and removing either half leaves a suite that would pass on a restore
//! that never happened.

use std::net::SocketAddr;
use std::path::Path;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use ciphr_audit::{AuditDevice, AuditSink};
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

[[policy]]
name = "infra"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list", "write"]
"#;

const SECRET: &str = "infra/service-a/DB_PASSWORD";

/// The deployment's master key. Fixed, and obviously not a real one.
///
/// The same value has to be used on both sides of the restore, because the seal record
/// travels *inside* the database — which is the reason `backup.md` tells a deployment to
/// keep every key any retained backup was sealed under.
fn seal() -> StaticSeal {
    StaticSeal::from_master_key(
        "CIPHR_MASTER_KEY",
        MasterKey::from_hex(&"11".repeat(32)).expect("a valid master key"),
    )
}

/// What the first phase of each test produces: a store, a backup of it, and a token.
struct BeforeTheBackup {
    /// Where the live database is, and where the backup will be restored to.
    database: std::path::PathBuf,
    /// The backup file.
    backup: std::path::PathBuf,
    /// A credential for `deploy`, issued *before* the backup was taken.
    token: String,
    /// Its identifier, for revoking it afterwards.
    token_id: String,
    _directory: tempfile::TempDir,
}

/// Set up a store the way a deployment would, then back it up.
///
/// Everything here happens through the ordinary write path — no fixture is inserted
/// behind the store's back, because a backup of hand-written rows would prove nothing
/// about a backup of a real one.
fn a_store_and_a_backup_of_it() -> BeforeTheBackup {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("store.db");
    let backup = directory.path().join("backup.db");

    let seal = seal();
    let root = RootKey::generate().expect("entropy");
    let root_id = RootKeyId::generate().expect("entropy");

    let mut store = SqliteStore::open(&database).expect("open");
    store
        .initialize(&SealState {
            seal_id: seal.id().to_owned(),
            wrapped_root_key: seal.rewrap(&root, root_id).expect("wrap"),
        })
        .expect("initialize");

    let pepper = TokenPepper::derive(&root);
    let token = Token::generate().expect("entropy");
    store
        .issue_token(
            "deploy",
            &token,
            &pepper,
            "operator",
            None,
            ciphr_store::TokenPurpose::Credential,
        )
        .expect("issue a token");

    let path = SecretPath::parse(SECRET).expect("a valid path");
    let value = Plaintext::from(&b"seeded"[..]);
    store
        .put(&path, "operator", &mut |version| {
            ciphr_crypto::encrypt(&root, &path, version, &value)
        })
        .expect("put");

    drop(store);

    let token_text = token.expose_text().to_string();

    // Serve one request *before* the backup, so the copy carries a chain rather than an
    // empty table. This is not decoration: without it every claim below about the audit
    // chain continuing from the restored head would be checked against nothing, and a
    // chain that restarted at zero would look correct.
    {
        let router = serve(&database);
        let (status, body) = get(&router, &format!("/v1/secrets/{SECRET}"), &token_text);
        assert_eq!(
            status,
            StatusCode::OK,
            "the fixture has to work before it is worth backing up: {body}"
        );
    }

    // Read-only, the way `ciphr backup` does it, rather than through the writable handle
    // that built the fixture.
    SqliteStore::open_read_only(&database)
        .expect("open the source read-only")
        .backup_into(&backup)
        .expect("back up");

    BeforeTheBackup {
        database,
        backup,
        token: token_text,
        token_id: token.id().to_string(),
        _directory: directory,
    }
}

/// Do what an operator does: remove the live database and put the backup in its place.
///
/// The sidecars go too. A `-wal` left behind from the old database beside a restored file
/// is the one restore mistake worth reproducing here rather than assuming away — SQLite
/// would read it as part of a database it does not belong to.
fn restore(backup: &Path, over: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", over.display()));
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).expect("remove the live database");
        }
    }
    std::fs::rename(backup, over).expect("move the backup into place");
}

/// Build the server on whatever database is at this path, the way startup does.
///
/// The root key is unsealed **from the store being opened**, not carried over from the
/// first phase. That is the point: if the restored file's seal record did not survive the
/// copy, this is where a restore fails, and it fails before any request is made.
fn serve(database: &Path) -> axum::Router {
    let store = SqliteStore::open(database).expect("open the restored database");
    let state = store
        .seal_state()
        .expect("read the seal record")
        .expect("the restored database is initialized");
    let root = seal()
        .unseal(&state.wrapped_root_key)
        .expect("the restored seal record opens with the same master key");

    let devices: Vec<Box<dyn AuditDevice>> = vec![Box::new(
        SqliteAuditDevice::open(database).expect("audit device"),
    )];
    // `audit_chain()` and not `Chain::new()`, because that is what `Server::prepare`
    // does: the chain resumes from the stored head, which after a restore is the
    // *restored* head. A chain that started at zero would reuse a sequence number the
    // restored trail already holds, no device would accept the record, and fail-closed
    // would turn every request into a `503` — which is what this test produced when it
    // was written the other way, and is the same failure the store lock exists to
    // prevent between two live processes.
    let chain = store
        .audit_chain()
        .expect("resume the chain from the stored head");
    let sink = AuditSink::new(devices, chain).expect("sink");
    let policies = ciphr_policy::PolicySet::from_toml(POLICIES).expect("policies");

    api::router(AppState::new(
        store,
        sink,
        policies,
        root,
        "static".to_owned(),
        "supplied".to_owned(),
        ciphr_server::surface::only(&[]).expect("an empty surface"),
    ))
}

fn get(router: &axum::Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4400))))
        .body(Body::empty())
        .expect("a valid request");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let response = runtime
        .block_on(router.clone().oneshot(request))
        .expect("the router must answer");
    let status = response.status();
    let bytes = runtime
        .block_on(axum::body::to_bytes(response.into_body(), 1 << 20))
        .expect("body");
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, body)
}

#[test]
fn a_restored_backup_serves_the_secrets_it_held() {
    let before = a_store_and_a_backup_of_it();
    restore(&before.backup, &before.database);

    let router = serve(&before.database);
    let (status, body) = get(&router, &format!("/v1/secrets/{SECRET}"), &before.token);

    assert_eq!(
        status,
        StatusCode::OK,
        "the restored store must serve: {body}"
    );
    assert_eq!(
        body["value"], "seeded",
        "the value has to survive the round trip, not merely the row"
    );

    // Four things had to hold for that one assertion, and naming them is the point of
    // this test: the seal record opened with the same key, the wrapped data key came
    // back, the token authenticated against a verifier peppered from the restored root
    // key, and the audit record was accepted against the restored chain head. Any of
    // them failing produces something other than a 200 with this body.
}

#[test]
fn a_restored_backup_is_missing_what_was_written_after_it() {
    let before = a_store_and_a_backup_of_it();

    // Written to the *live* store after the backup was taken. This is what "a restore
    // rolls the store back" costs, and it is the half operators expect.
    {
        let mut store = SqliteStore::open(&before.database).expect("reopen");
        let state = store.seal_state().expect("seal").expect("initialized");
        let root = seal().unseal(&state.wrapped_root_key).expect("unseal");
        let path = SecretPath::parse("infra/service-a/API_TOKEN").expect("a valid path");
        let value = Plaintext::from(&b"written-later"[..]);
        store
            .put(&path, "operator", &mut |version| {
                ciphr_crypto::encrypt(&root, &path, version, &value)
            })
            .expect("put");
    }

    restore(&before.backup, &before.database);
    let router = serve(&before.database);

    let (status, _) = get(
        &router,
        "/v1/secrets/infra/service-a/API_TOKEN",
        &before.token,
    );
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a secret written after the backup cannot be in it"
    );

    // And the one that was in it is still there, so this is a rollback and not a broken
    // store.
    let (status, _) = get(&router, &format!("/v1/secrets/{SECRET}"), &before.token);
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn a_restored_backup_accepts_a_token_that_was_revoked_after_it() {
    let before = a_store_and_a_backup_of_it();

    // Revoked on the live store, after the backup. `revoked_at` is a column, so the
    // revocation is state — and state is what a restore rolls back.
    {
        let mut store = SqliteStore::open(&before.database).expect("reopen");
        store
            .revoke_token(&before.token_id)
            .expect("revoke the token");
    }

    // Confirm the revocation actually took effect before the restore, so that the
    // assertion afterwards is about the restore and not about a revocation that never
    // happened.
    let live = serve(&before.database);
    let (status, _) = get(&live, &format!("/v1/secrets/{SECRET}"), &before.token);
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked token must not authenticate"
    );
    drop(live);

    restore(&before.backup, &before.database);
    let restored = serve(&before.database);
    let (status, _) = get(&restored, &format!("/v1/secrets/{SECRET}"), &before.token);

    // **This is documented behaviour, not a defect**, and it is pinned so that it stays
    // documented: the holder of that credential is whoever the revocation was about, and
    // `backup.md` says to re-revoke before the service is reachable. If this assertion
    // ever fails, the runbook needs editing in the same commit.
    assert_eq!(
        status,
        StatusCode::OK,
        "a restore from before a revocation makes the credential valid again"
    );
}

#[test]
fn the_audit_chain_continues_from_the_restored_head() {
    let before = a_store_and_a_backup_of_it();
    let entries_in_the_backup = {
        let store = SqliteStore::open_read_only(&before.backup).expect("open the backup");
        store
            .audit_query(&AuditFilter {
                limit: 1000,
                ..AuditFilter::default()
            })
            .expect("query")
            .len()
    };
    assert!(
        entries_in_the_backup > 0,
        "the fixture served a request before the backup, so the trail cannot be empty"
    );

    restore(&before.backup, &before.database);
    let router = serve(&before.database);

    let (status, _) = get(&router, &format!("/v1/secrets/{SECRET}"), &before.token);
    assert_eq!(status, StatusCode::OK);

    let rows = SqliteStore::open(&before.database)
        .expect("reopen")
        .audit_query(&AuditFilter {
            limit: 1000,
            ..AuditFilter::default()
        })
        .expect("query");

    // The read appended exactly one record, and it appended it *after* the restored
    // ones. A chain that restarted at zero would have failed the request rather than
    // getting here — fail-closed refuses a record no device accepts — so this asserts
    // the shape of what survived rather than merely that something did.
    assert_eq!(rows.len(), entries_in_the_backup + 1);
    assert_eq!(
        usize::try_from(rows.last().expect("a record").seq).expect("a plausible sequence"),
        entries_in_the_backup + 1,
        "the sequence continues rather than restarting"
    );
}
