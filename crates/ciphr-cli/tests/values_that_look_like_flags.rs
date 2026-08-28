//! A value of ours that begins with `-` reaches the command as a value.
//!
//! Three of this project's namespaces produce strings that a command-line parser
//! reads as flags, and the reasoning for each is on the `Command` enum in
//! `main.rs`. This file pins the behaviour from outside the binary, because that
//! is the only place it is observable: the argument never reaches any function a
//! unit test could call — clap refuses first and the process exits.
//!
//! **Why a test of its own rather than a line in an existing one.** The defect was
//! already covered, by accident and unreliably:
//! `token_operations_are_audited.rs` issues real tokens and revokes them, so it
//! rolled a one-in-sixty-four die on every run from the day it was written. It
//! lost during the release of `ui-v0.4.1`, which is how any of this was found. A
//! test that fails one run in sixty-four is not a test of this property; the ones
//! below use identifiers chosen to have the shape that breaks, so they either
//! always pass or always fail.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

const MASTER_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// An identity whose name begins with a hyphen, because nothing validates the
/// names in a policy file against a character set.
const POLICIES: &str = r#"
[[identity]]
name     = "-svc"
kind     = "machine"
policies = ["everything"]

[[policy]]
name = "everything"

  [[policy.rule]]
  path         = "**"
  capabilities = ["read", "write"]
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
        assert!(cli.run(&["init"]).status.success(), "init");
        cli
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ciphr"));
        command
            .arg("-d")
            .arg(&self.store)
            .arg("--policies")
            .arg(&self.policies)
            .arg("--audit-file")
            .arg(&self.audit)
            .env("CIPHR_MASTER_KEY", MASTER_KEY)
            .stdin(Stdio::null());
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command().args(arguments).output().expect("run ciphr")
    }

    fn put(&self, path: &str, value: &str) -> Output {
        let mut child = self
            .command()
            .args(["put", path])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn ciphr put");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(value.as_bytes())
            .expect("write value");
        child.wait_with_output().expect("ciphr put")
    }
}

/// What a parser refusal looks like, as opposed to the command running and
/// deciding something. Asserting on this rather than on the exit code is the
/// point: both are failures, and only one of them is this bug.
fn is_parser_refusal(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("unexpected argument") || stderr.contains("to pass")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_token_identifier_that_begins_with_a_hyphen_reaches_the_store() {
    // The shape roughly one identifier in sixty-four has. The token does not
    // exist, and that is the assertion: the command has to get far enough to say
    // so, rather than being refused before it starts.
    let cli = Cli::new();
    let output = cli.run(&["token", "revoke", "-Ab3xY9zQ"]);

    assert!(
        !is_parser_refusal(&output),
        "the identifier was read as a flag: {}",
        stderr_of(&output)
    );
    assert!(
        stderr_of(&output).contains("-Ab3xY9zQ"),
        "the refusal must name the identifier it looked for: {}",
        stderr_of(&output)
    );
}

#[test]
fn a_real_token_whose_identifier_begins_with_a_hyphen_can_be_revoked() {
    // The property the one above only approximates. Rather than issuing tokens
    // until one has the right shape -- sixty-four expected runs of the binary, and
    // a test that sometimes takes ten times that -- this asserts the round trip on
    // whatever identifier is dealt, and the test above pins the hyphen case.
    let cli = Cli::new();
    let issued = cli.run(&["token", "issue", "-svc", "--force", "--no-expiry"]);
    assert!(issued.status.success(), "issue: {}", stderr_of(&issued));

    let printed = String::from_utf8(issued.stdout).expect("utf-8");
    let token = printed.trim().strip_prefix("cph_").expect("a ciphr token");
    let token_id: String = token.chars().take(8).collect();

    let revoked = cli.run(&["token", "revoke", &token_id]);
    assert!(
        revoked.status.success(),
        "revoking {token_id} failed: {}",
        stderr_of(&revoked)
    );
}

#[test]
fn a_secret_path_that_begins_with_a_hyphen_can_be_read_back() {
    // `-` is an allowed segment character, so this path is storable -- and before
    // this fix it was storable and unreadable, which is the worse half: the store
    // held a value the obvious command would not return.
    let cli = Cli::new();
    let written = cli.put("-legacy/db", "hunter2");
    assert!(written.status.success(), "put: {}", stderr_of(&written));

    let read = cli.run(&["get", "-legacy/db", "--force"]);
    assert!(
        !is_parser_refusal(&read),
        "the path was read as a flag: {}",
        stderr_of(&read)
    );
    assert!(read.status.success(), "get: {}", stderr_of(&read));
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "hunter2",
        "the value must come back"
    );
}

#[test]
fn an_identity_whose_name_begins_with_a_hyphen_can_be_issued_a_token() {
    let cli = Cli::new();
    let output = cli.run(&["token", "issue", "-svc", "--force", "--no-expiry"]);

    assert!(
        !is_parser_refusal(&output),
        "the identity was read as a flag: {}",
        stderr_of(&output)
    );
    assert!(output.status.success(), "issue: {}", stderr_of(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .starts_with("cph_"),
        "a token must be printed"
    );
}

#[test]
fn a_defined_flag_after_the_subcommand_is_still_a_flag() {
    // The cost of `allow_hyphen_values` is that an *undefined* flag becomes data.
    // A defined one must not, or the fix would have broken every global option
    // this CLI has -- and `-d` is the one every command needs.
    let cli = Cli::new();
    let directory = tempfile::tempdir().expect("temp dir");
    let elsewhere = directory.path().join("elsewhere.db");

    let output = Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .args(["--policies", cli.policies.to_str().expect("utf-8 path")])
        .arg("--audit-file")
        .arg(&cli.audit)
        .args(["token", "revoke", "-d"])
        .arg(&elsewhere)
        .arg("AAAAAAAA")
        .env("CIPHR_MASTER_KEY", MASTER_KEY)
        .stdin(Stdio::null())
        .output()
        .expect("run ciphr");

    // `-d` took its value, so the command opened a store that does not exist yet
    // rather than treating `-d` as the identifier to revoke.
    assert!(
        !stderr_of(&output).contains("id '-d'"),
        "-d was swallowed as the token identifier: {}",
        stderr_of(&output)
    );
}
