//! The metadata listings run read-only: no lock, no master key, no audit entry.
//!
//! ADR-22, exercised through the binary. `list`, `versions`, `rotation <path>` and
//! `token list` read columns that are plaintext in the database file, so they take
//! the read-only path instead of opening a session. Three consequences are only
//! observable from outside the process, and each gets a test: the listings answer
//! while another process holds the store lock — normally the running server, and for
//! `token list` that is the incident case issue #14 was filed about — they need no
//! master key, and they leave no audit entry behind.
//!
//! The boundary matters as much as the opening: revoking stays a session command,
//! and the refusal under the lock now names the live route where one exists.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Sixty-four hexadecimal characters, so the test needs nothing from its environment.
const MASTER_KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";

const POLICIES: &str = r#"
[[identity]]
name     = "alice"
kind     = "human"
policies = ["viewer"]

[[policy]]
name = "viewer"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read"]
"#;

fn ciphr(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(args)
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run ciphr")
}

/// The same, with the master key deliberately absent from the environment.
fn ciphr_without_key(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(args)
        .env_remove("CIPHR_MASTER_KEY")
        .output()
        .expect("run ciphr")
}

fn put(store: &Path, path: &str, args: &[&str]) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .arg("-d")
        .arg(store)
        .args(["put", path])
        .args(args)
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("run ciphr put");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"a value")
        .expect("write the value");
    assert!(child.wait().expect("wait").success(), "put");
}

/// Issue a token for `alice` and return its non-secret identifier.
fn issue(store: &Path, policies: &Path) -> String {
    let output = ciphr(
        store,
        &[
            "--policies",
            policies.to_str().expect("path"),
            "token",
            "issue",
            "alice",
            "--force",
        ],
    );
    assert!(output.status.success(), "issue: {}", stderr(&output));
    let printed = stdout(&output);
    let token = printed.trim().strip_prefix("cph_").expect("a ciphr token");
    token.chars().take(8).collect()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn the_listings_answer_while_another_process_holds_the_lock() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let policies = directory.path().join("policies.toml");
    std::fs::write(&policies, POLICIES).expect("write policies");

    assert!(ciphr(&store, &["init"]).status.success(), "init");
    put(&store, "infra/service-a/DB_PASSWORD", &[]);
    put(
        &store,
        "infra/service-a/DB_KEY",
        &["--rotation", "breaks-data"],
    );
    let token_id = issue(&store, &policies);

    // Stand in for the running server. These are the questions asked while it runs —
    // "what is stored", "what class is this", and above all "is this credential
    // still valid" — so needing the lock would mean needing an outage to ask them.
    let lock = ciphr_store::StoreLock::acquire(&store).expect("take the lock");

    let listed = ciphr(&store, &["list"]);
    assert!(listed.status.success(), "list: {}", stderr(&listed));
    assert!(stdout(&listed).contains("infra/service-a/DB_PASSWORD"));

    let unclassified = ciphr(&store, &["list", "--rotation", "unclassified"]);
    assert!(
        unclassified.status.success(),
        "the corpus question answers live: {}",
        stderr(&unclassified)
    );
    assert!(stdout(&unclassified).contains("DB_PASSWORD"));
    assert!(!stdout(&unclassified).contains("DB_KEY"));

    let versions = ciphr(&store, &["versions", "infra/service-a/DB_PASSWORD"]);
    assert!(versions.status.success(), "versions: {}", stderr(&versions));

    let class = ciphr(&store, &["rotation", "infra/service-a/DB_KEY"]);
    assert!(class.status.success(), "rotation: {}", stderr(&class));
    assert!(stdout(&class).contains("breaks-data"));

    let tokens = ciphr(&store, &["token", "list"]);
    assert!(tokens.status.success(), "token list: {}", stderr(&tokens));
    assert!(
        stdout(&tokens).contains(&token_id) && stdout(&tokens).contains("valid"),
        "credential state is readable during the incident: {}",
        stdout(&tokens)
    );

    // The boundary: revoking writes a row and an audit entry, so it still opens a
    // session and is still refused. That is issue #14's open half, not this change's.
    let revoke = ciphr(&store, &["token", "revoke", &token_id]);
    assert!(
        !revoke.status.success(),
        "revoking must still be refused while the lock is held"
    );
    assert!(
        stderr(&revoke).contains("in use by process"),
        "and refused because of the lock: {}",
        stderr(&revoke)
    );

    drop(lock);
}

#[test]
fn the_listings_need_no_master_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let policies = directory.path().join("policies.toml");
    std::fs::write(&policies, POLICIES).expect("write policies");

    assert!(ciphr(&store, &["init"]).status.success(), "init");
    put(&store, "infra/service-a/DB_PASSWORD", &[]);
    issue(&store, &policies);

    // Nothing in a listing decrypts, so nothing about it should require the key. A
    // monitoring job that asks "what is unclassified" or "which tokens never expire"
    // does not need the highest-value secret in the deployment in its environment.
    for listing in [
        vec!["list"],
        vec!["versions", "infra/service-a/DB_PASSWORD"],
        vec!["rotation", "infra/service-a/DB_PASSWORD"],
        vec!["token", "list"],
    ] {
        let output = ciphr_without_key(&store, &listing);
        assert!(
            output.status.success(),
            "{listing:?} must not read the master key: {}",
            stderr(&output)
        );
    }

    // The contrast: reading a value does consume the key, and fails without it.
    let read = ciphr_without_key(&store, &["get", "infra/service-a/DB_PASSWORD", "--force"]);
    assert!(!read.status.success(), "get must still need the key");
}

#[test]
fn a_listing_writes_no_audit_entry() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");
    let policies = directory.path().join("policies.toml");
    let audit = directory.path().join("audit.jsonl");
    std::fs::write(&policies, POLICIES).expect("write policies");

    let audited = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_ciphr"))
            .arg("-d")
            .arg(&store)
            .arg("--audit-file")
            .arg(&audit)
            .args(args)
            .env("CIPHR_MASTER_KEY", MASTER_KEY)
            .output()
            .expect("run ciphr");
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
    };

    audited(&["init"]);
    put(&store, "infra/service-a/DB_PASSWORD", &[]);
    let trail = std::fs::read_to_string(&audit).expect("audit file");
    let before = trail.lines().filter(|line| !line.trim().is_empty()).count();

    audited(&["list"]);
    audited(&["versions", "infra/service-a/DB_PASSWORD"]);
    audited(&["rotation", "infra/service-a/DB_PASSWORD"]);
    audited(&["token", "list"]);

    // No entry, deliberately (ADR-22): whoever can run these can read the same rows
    // with sqlite3 on the same file and leave nothing, so an entry here would measure
    // politeness rather than access. The server's `list` entries are unaffected.
    let trail = std::fs::read_to_string(&audit).expect("audit file");
    assert_eq!(
        trail.lines().filter(|line| !line.trim().is_empty()).count(),
        before,
        "a listing must leave the trail exactly as it was: {trail}"
    );
    assert!(
        !trail.contains("\"action\":\"list\""),
        "and no stray list action either: {trail}"
    );
}

#[test]
fn the_lock_refusal_names_the_live_route_where_one_exists() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = directory.path().join("store.db");

    assert!(ciphr(&store, &["init"]).status.success(), "init");
    let lock = ciphr_store::StoreLock::acquire(&store).expect("take the lock");

    // `get` has a live equivalent, and the refusal announces it without taking it.
    let read = ciphr(&store, &["get", "infra/service-a/DB_PASSWORD", "--force"]);
    assert!(!read.status.success());
    assert!(
        stderr(&read).contains("in use by process"),
        "the lock's own message survives: {}",
        stderr(&read)
    );
    assert!(
        stderr(&read).contains("GET /v1/secrets/infra/service-a/DB_PASSWORD"),
        "and the live route is named: {}",
        stderr(&read)
    );

    // A command with no route — revoking — gets the plain message and no hint.
    let revoke = ciphr(&store, &["token", "revoke", "AAAAAAAA"]);
    assert!(!revoke.status.success());
    assert!(
        stderr(&revoke).contains("in use by process"),
        "still the lock: {}",
        stderr(&revoke)
    );
    assert!(
        !stderr(&revoke).contains("/v1/"),
        "no invented route for a host-only command: {}",
        stderr(&revoke)
    );

    drop(lock);
}
