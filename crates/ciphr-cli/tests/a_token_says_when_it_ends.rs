//! `token issue` will not guess how long a credential lives.
//!
//! Until `Unreleased` the shortest command produced the most dangerous credential:
//! `ciphr token issue deploy-runner` minted a token that never expires, and the only
//! thing standing against it was a line on standard error that no script reads. The
//! threat model is built around A3 — a compromised deploy runner holding a valid
//! token — and a token with no expiry is that adversary with unlimited time.
//!
//! The fix is not a shorter default. It is the same argument `Rotation::Unclassified`
//! already made: a deliberate answer and an untouched default must not be the same
//! byte in the same column, and the path of least resistance must not be the
//! destructive one. `--no-expiry` is still a real answer — break-glass credentials and
//! long-lived integrations exist — it simply has to be one somebody wrote down.
//!
//! What is asserted here is mostly the *refusal*, and above all that it happens before
//! anything is minted. A refusal that still leaves a row behind would be worse than no
//! refusal, because the operator would believe nothing happened.

use std::process::{Command, Output, Stdio};

const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const POLICIES: &str = r#"
[[identity]]
name     = "deploy-runner"
kind     = "machine"
policies = ["deploy"]

[[policy]]
name = "deploy"

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
        assert!(cli.run(&["init"]).status.success(), "init");
        cli
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ciphr"))
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
            .expect("run ciphr")
    }

    /// How many tokens the store holds, read the way an operator would.
    fn tokens(&self) -> usize {
        let listed = self.run(&["token", "list"]);
        assert!(listed.status.success(), "token list: {}", stderr(&listed));
        String::from_utf8(listed.stdout)
            .expect("utf-8")
            .lines()
            .filter(|line| line.contains("deploy-runner"))
            .count()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8")
}

#[test]
fn neither_flag_is_refused_and_nothing_is_minted() {
    let cli = Cli::new();
    let before = cli.tokens();

    let output = cli.run(&["token", "issue", "deploy-runner", "--force"]);

    assert!(
        !output.status.success(),
        "a token issued without an answer about its lifetime is the defect, not the fix"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing may reach standard output: whatever appears there is a credential, and a \
         refused command must not produce one"
    );

    // The message is the upgrade instruction for every script that has been running the
    // old form, so it names both ways out rather than only the safe one.
    let said = stderr(&output);
    assert!(said.contains("--ttl"), "got {said:?}");
    assert!(said.contains("--no-expiry"), "got {said:?}");

    assert_eq!(
        cli.tokens(),
        before,
        "the refusal has to come before the row exists; a token created and then reported \
         as an error is the worst of both"
    );
}

#[test]
fn no_expiry_is_an_answer_and_says_so() {
    let cli = Cli::new();

    let output = cli.run(&["token", "issue", "deploy-runner", "--force", "--no-expiry"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        String::from_utf8(output.stdout.clone())
            .expect("utf-8")
            .trim()
            .starts_with("cph_"),
        "the token is still printed exactly once, on standard output"
    );
    // Worth a different sentence than before: this is a choice somebody made rather
    // than a default nobody noticed.
    assert!(stderr(&output).contains("No expiry, as asked"));
    assert_eq!(cli.tokens(), 1);
}

#[test]
fn a_ttl_still_works_and_reports_the_moment_it_ends() {
    let cli = Cli::new();

    let output = cli.run(&["token", "issue", "deploy-runner", "--force", "--ttl", "1h"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Expires "),
        "got {:?}",
        stderr(&output)
    );
    assert_eq!(cli.tokens(), 1);
}

#[test]
fn the_two_flags_together_are_refused() {
    let cli = Cli::new();

    let output = cli.run(&[
        "token",
        "issue",
        "deploy-runner",
        "--force",
        "--ttl",
        "1h",
        "--no-expiry",
    ]);

    assert!(
        !output.status.success(),
        "there is no precedence rule between them on purpose -- a rule about which wins is \
         a rule that lets a deployment issue the credential nobody meant"
    );
    assert_eq!(cli.tokens(), 0);
}

#[test]
fn a_bad_duration_is_still_a_duration_error() {
    let cli = Cli::new();

    // The new check must not swallow the old one: `--ttl 90` is present, so this is not
    // the "say how long it lives" refusal, it is the bare-number refusal that has
    // existed since the flag did.
    let output = cli.run(&["token", "issue", "deploy-runner", "--force", "--ttl", "90"]);

    assert!(!output.status.success());
    let said = stderr(&output);
    assert!(said.contains("not a duration"), "got {said:?}");
    assert_eq!(cli.tokens(), 0);
}
