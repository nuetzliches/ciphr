//! Every way of setting a rotation class writes a `classify` entry.
//!
//! An integration test rather than a unit test for the same reason as
//! `init_records_to_every_device.rs`: the commands are private functions in a binary
//! crate, and what is under test is the effect of a flag on an audit trail.
//!
//! The regression this guards is narrow and was real. `ciphr rotation <path> <class>`
//! recorded the change, while `put --rotation` and `import --rotation` performed the
//! same change and recorded only a `write` — so a secret classified `breaks-data`
//! could be downgraded to `rotatable` by a `put`, leaving nothing in the trail that
//! says the classification moved. That is the step immediately before a rotation that
//! destroys data, and the documentation claimed all three were audited.

use std::io::Write as _;
use std::process::{Command, Stdio};

const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// A `ciphr` invocation against a store the test owns, with the audit file beside it.
struct Cli {
    store: std::path::PathBuf,
    audit: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let cli = Self {
            store: directory.path().join("store.db"),
            audit: directory.path().join("audit.jsonl"),
            _directory: directory,
        };
        cli.run(&["init"], None);
        cli
    }

    /// Run a command, optionally writing `stdin`, and require that it succeeds.
    fn run(&self, arguments: &[&str], stdin: Option<&str>) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ciphr"));
        command
            .arg("-d")
            .arg(&self.store)
            .arg("--audit-file")
            .arg(&self.audit)
            .args(arguments)
            .env("CIPHR_MASTER_KEY", KEY)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null());

        let mut child = command.spawn().expect("run ciphr");
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        let status = child.wait().expect("wait");
        assert!(status.success(), "ciphr {arguments:?} must succeed");
    }

    /// How many entries in the trail carry this action.
    fn count(&self, action: &str) -> usize {
        std::fs::read_to_string(&self.audit)
            .expect("the audit file must exist")
            .lines()
            .filter(|line| line.contains(&format!("\"action\":\"{action}\"")))
            .count()
    }
}

#[test]
fn put_with_a_class_records_that_somebody_classified_it() {
    let cli = Cli::new();
    cli.run(
        &["put", "infra/service-a/DB_KEY", "--rotation", "breaks-data"],
        Some("a value"),
    );

    assert_eq!(cli.count("write"), 1, "the value write is recorded");
    assert_eq!(
        cli.count("classify"),
        1,
        "and so is the classification, as its own action"
    );
}

#[test]
fn put_without_a_class_records_no_classification() {
    // The entry has to mean something: a write that classifies nothing must not
    // produce one, or `classify` stops answering "who decided this was safe".
    let cli = Cli::new();
    cli.run(&["put", "infra/service-a/DB_KEY"], Some("a value"));

    assert_eq!(cli.count("write"), 1);
    assert_eq!(cli.count("classify"), 0);
}

#[test]
fn a_put_that_downgrades_a_class_is_visible_in_the_trail() {
    // The case the regression made invisible, end to end: a secret that was
    // deliberately marked as destroying data, silently made "safe to rotate".
    let cli = Cli::new();
    cli.run(
        &["put", "infra/service-a/DB_KEY", "--rotation", "breaks-data"],
        Some("first"),
    );
    cli.run(
        &["put", "infra/service-a/DB_KEY", "--rotation", "rotatable"],
        Some("second"),
    );

    assert_eq!(
        cli.count("classify"),
        2,
        "both classifications are in the trail, so the downgrade can be found"
    );
}

#[test]
fn import_records_one_classification_per_secret() {
    // At bulk scale the gap was worse: a whole corpus classified with no trace.
    let cli = Cli::new();
    cli.run(
        &[
            "import",
            "--stdin",
            "--prefix",
            "infra/service-a",
            "--rotation",
            "volume-bound",
        ],
        Some("ONE=1\nTWO=2\nTHREE=3\n"),
    );

    assert_eq!(cli.count("write"), 3);
    assert_eq!(cli.count("classify"), 3);
}

#[test]
fn the_standalone_command_still_records_it() {
    let cli = Cli::new();
    cli.run(&["put", "infra/service-a/DB_KEY"], Some("a value"));
    cli.run(&["rotation", "infra/service-a/DB_KEY", "seed-only"], None);

    assert_eq!(cli.count("classify"), 1);
}
