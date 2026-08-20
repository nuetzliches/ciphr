//! Creating and revoking a credential is in the audit trail.
//!
//! Until 2026-08-20 no token command wrote an entry at all. That is a narrower gap
//! than it sounds and a worse one than it looks.
//!
//! Narrower, because it defends against nobody: issuing a token needs the master
//! key, and whoever holds the master key and the database decrypts every secret
//! directly. The threat model puts that reader outside the boundary on purpose
//! (A5), and no entry changes it.
//!
//! Worse, because of what it does to the trail's own guarantee. A token minted
//! this way is invisible, and every access made with it afterwards reads as
//! ordinary activity of a legitimate identity — so the trail answers "who read
//! this" confidently and wrongly. The hash chain cannot help: it proves nothing
//! was *removed*, and this was never written. With the entry, hiding the act
//! requires rewriting the chain, which is exactly what the anchor outside the
//! store detects.

use std::process::{Command, Stdio};

const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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

struct Cli {
    store: std::path::PathBuf,
    policies: std::path::PathBuf,
    audit: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let policies = directory.path().join("policies.toml");
        std::fs::write(&policies, POLICIES).expect("write policies");

        let cli = Self {
            store: directory.path().join("store.db"),
            policies,
            audit: directory.path().join("audit.jsonl"),
            _directory: directory,
        };
        cli.run(&["init"]).expect("init");
        cli
    }

    /// Run a command and hand back its standard output, or `None` if it failed.
    fn run(&self, arguments: &[&str]) -> Option<String> {
        let output = Command::new(env!("CARGO_BIN_EXE_ciphr"))
            .arg("-d")
            .arg(&self.store)
            .arg("--policies")
            .arg(&self.policies)
            .arg("--audit-file")
            .arg(&self.audit)
            .args(arguments)
            .env("CIPHR_MASTER_KEY", KEY)
            .stdin(Stdio::null())
            .output()
            .expect("run ciphr");

        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).expect("utf-8"))
    }

    /// Issue a token and return its non-secret identifier.
    fn issue(&self, identity: &str) -> String {
        let printed = self
            .run(&["token", "issue", identity, "--force"])
            .expect("issue");
        let token = printed.trim().strip_prefix("cph_").expect("a ciphr token");
        token.chars().take(8).collect()
    }

    /// Every audit entry, as parsed records.
    fn entries(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.audit)
            .expect("the audit file must exist")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("a record")["entry"].clone()
            })
            .collect()
    }

    fn with_action(&self, action: &str) -> Vec<serde_json::Value> {
        self.entries()
            .into_iter()
            .filter(|entry| entry["action"] == action)
            .collect()
    }
}

#[test]
fn issuing_a_token_records_who_it_was_for_and_which_one() {
    let cli = Cli::new();
    let token_id = cli.issue("alice");

    let issued = cli.with_action("issue-token");
    assert_eq!(issued.len(), 1, "exactly one entry per issued token");

    // The actor is the operator on the host, not the identity: a person running a
    // command is not a machine identity, and the trail must not conflate them.
    assert!(
        issued[0]["principal"]["name"]
            .as_str()
            .expect("a principal")
            .starts_with("cli:"),
        "the actor is the operator: {}",
        issued[0]["principal"]
    );

    // The subject is who the credential is for, and which credential it is.
    assert_eq!(issued[0]["subject"]["name"], "alice");
    assert_eq!(issued[0]["subject"]["kind"], "human");
    assert_eq!(issued[0]["subject"]["token_id"], token_id);
}

#[test]
fn the_recorded_token_id_is_the_one_later_accesses_carry() {
    // The entire point of recording the id: it joins the creation of a credential
    // to everything done with it. A different id here would be worse than none,
    // because it would look like an answer.
    let cli = Cli::new();
    let token_id = cli.issue("alice");

    let listed = cli
        .run(&["token", "list", "--identity", "alice"])
        .expect("list");
    assert!(
        listed.contains(&token_id),
        "the store knows the same id: {listed}"
    );
}

#[test]
fn the_token_itself_is_never_in_the_trail() {
    // The record carries the non-secret leading part and nothing else. A trail that
    // held the credential would be a second copy of it, in the one file that is
    // deliberately duplicated off the host.
    let cli = Cli::new();
    let printed = cli
        .run(&["token", "issue", "alice", "--force"])
        .expect("issue");
    let token = printed.trim();

    let trail = std::fs::read_to_string(&cli.audit).expect("audit file");
    assert!(
        !trail.contains(token),
        "the token must not appear in the trail"
    );
    assert!(
        !trail.contains(token.strip_prefix("cph_").expect("prefix")),
        "nor its secret half without the prefix"
    );
}

#[test]
fn revoking_one_token_records_that_one() {
    let cli = Cli::new();
    let first = cli.issue("alice");
    let second = cli.issue("alice");

    cli.run(&["token", "revoke", &first]).expect("revoke");

    let revoked = cli.with_action("revoke-token");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["subject"]["token_id"], first);
    assert_ne!(revoked[0]["subject"]["token_id"], second);
}

#[test]
fn revoking_a_token_that_does_not_exist_records_nothing() {
    // A refusal must not leave a claim behind that the credential stopped working.
    let cli = Cli::new();
    cli.issue("alice");

    assert!(
        cli.run(&["token", "revoke", "ZZZZZZZZ"]).is_none(),
        "revoking an unknown token must fail"
    );
    assert_eq!(cli.with_action("revoke-token").len(), 0);
}

#[test]
fn revoking_a_whole_identity_records_one_entry_per_token() {
    // Not one entry with a count: the question afterwards is when *this* credential
    // stopped working, and a count cannot answer it.
    let cli = Cli::new();
    let first = cli.issue("alice");
    let second = cli.issue("alice");

    cli.run(&["token", "revoke-all", "alice"])
        .expect("revoke-all");

    let revoked = cli.with_action("revoke-token");
    assert_eq!(revoked.len(), 2);

    let mut ids: Vec<String> = revoked
        .iter()
        .map(|entry| {
            entry["subject"]["token_id"]
                .as_str()
                .expect("id")
                .to_owned()
        })
        .collect();
    ids.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(ids, expected);
}

#[test]
fn revoking_an_identity_twice_records_nothing_the_second_time() {
    // The second call revokes nothing, so it must claim nothing. An entry per call
    // rather than per token would have written one anyway.
    let cli = Cli::new();
    cli.issue("alice");
    cli.run(&["token", "revoke-all", "alice"]).expect("first");
    cli.run(&["token", "revoke-all", "alice"]).expect("second");

    assert_eq!(cli.with_action("revoke-token").len(), 1);
}
