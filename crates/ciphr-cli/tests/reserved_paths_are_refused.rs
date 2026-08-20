//! `ciphr put sys/audit` is refused, and leaves nothing behind.
//!
//! This is the falsifier named by claim D6 in `docs/security-review.md` — "a way to
//! create `sys/audit` as a secret" — and until the review of 2026-08-21 (finding F2)
//! it was available: the reserved-prefix check lived in the HTTP layer alone, so the
//! CLI wrote a real secret at a path that names a virtual one. A rule granting an
//! auditor `read` on `sys/audit` then authorized two different things.
//!
//! An integration test rather than a unit test because what is under test is the
//! command, not a function: the point of the finding was that the rule held in one
//! caller and not in another.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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
        assert!(cli.run(&["init"], None).status.success(), "init must work");
        cli
    }

    fn run(&self, arguments: &[&str], stdin: Option<&str>) -> Output {
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().expect("run ciphr");
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait")
    }

    /// The whole audit file, as text.
    fn trail(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }
}

#[test]
fn a_secret_cannot_be_created_under_the_reserved_prefix() {
    let cli = Cli::new();

    for path in ["sys/audit", "sys/identities", "sys/policies", "sys/other"] {
        let output = cli.run(&["put", path], Some("planted"));
        assert!(
            !output.status.success(),
            "put {path} must fail, not create a secret"
        );

        let complaint = String::from_utf8_lossy(&output.stderr);
        assert!(
            complaint.contains("reserved"),
            "the refusal must say why; got: {complaint}"
        );

        // Nothing was created, so nothing can be read back.
        let read_back = cli.run(&["get", path, "--force"], None);
        assert!(!read_back.status.success(), "{path} must not exist");
    }

    // And no refused write is recorded as one that happened: the refusal comes
    // before the store is opened, so the trail does not claim a write nobody
    // performed. The reads above are in there, correctly — they were attempted.
    let claimed_writes: Vec<String> = cli
        .trail()
        .lines()
        .filter(|line| line.contains(r#""action":"write""#))
        .map(str::to_owned)
        .collect();
    assert!(
        claimed_writes.is_empty(),
        "a refused write must not be in the trail: {claimed_writes:?}"
    );
}

#[test]
fn an_ordinary_path_that_merely_starts_with_those_letters_is_untouched() {
    // Segment-aware, like every other prefix comparison in the codebase: refusing
    // `system/...` would be a rule nobody wrote.
    let cli = Cli::new();

    assert!(
        cli.run(&["put", "system/config"], Some("ordinary"))
            .status
            .success(),
        "system/config is an ordinary path"
    );

    let read_back = cli.run(&["get", "system/config", "--force"], None);
    assert!(read_back.status.success());
    assert_eq!(String::from_utf8_lossy(&read_back.stdout).trim(), "ordinary");
}
