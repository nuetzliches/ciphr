//! `ciphr-ci` as a workflow step uses it: the real binary, the real service, a real
//! environment file.
//!
//! What cannot be asserted from inside the crate is the thing a job depends on — that the
//! *values* never reach standard output while the *masks* always do. That is a property of
//! two sinks and a process, so it is tested through the built binary with its output
//! captured, which is also what a runner does with it.
//!
//! Unlike `ciphr-run`'s tests this file is not gated on Unix: this program never `exec`s,
//! so it works on any platform a runner runs on and its tests run on the development
//! machine as well.
//!
//! The service harness below is the third of its kind in this workspace, after
//! `ciphr-sdk/tests/live.rs` and `ciphr-run/tests/wrapper.rs`. The comment in the second
//! one said a third consumer would be the moment to extract it; this is deliberately not
//! that extraction, and the reason is worth writing down rather than leaving as drift.
//! The three harnesses agree on the service and differ on everything a test *does* with
//! it — an in-process client, a program that replaces itself, a program whose two output
//! streams are the subject. A shared crate would have to expose all three shapes, which is
//! how scaffolding turns into a framework. What matters is that the *service* they compose
//! is the real one, and that is `ciphr_server::api::router` in every copy.

use std::net::TcpListener;
use std::process::Command;

use ciphr_audit::{AuditDevice, AuditSink, Chain};
use ciphr_core::{Plaintext, SecretPath};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, Token, TokenPepper};
use ciphr_server::{AppState, api};
use ciphr_store::{SealState, SqliteAuditDevice, SqliteStore, Store};

/// The binary under test, built by cargo for this integration test.
const PROGRAM: &str = env!("CARGO_BIN_EXE_ciphr-ci");

/// One identity for a repository's jobs, and one that cannot reach its prefix.
const POLICIES: &str = r#"
[[identity]]
name     = "ci-widget"
kind     = "machine"
policies = ["ci-widget"]

[[identity]]
name     = "outsider"
kind     = "machine"
policies = ["nothing"]

[[policy]]
name = "ci-widget"

  [[policy.rule]]
  path         = "ci/**"
  capabilities = ["read", "list"]

[[policy]]
name = "nothing"

  [[policy.rule]]
  path         = "elsewhere/**"
  capabilities = ["read"]
"#;

/// A live service and the files a workflow step needs beside it.
struct Live {
    base_url: String,
    /// The PEM this program must trust.
    authority: std::path::PathBuf,
    /// A token file for `ci-widget`.
    token: std::path::PathBuf,
    /// A token file for `outsider`.
    outsider_token: std::path::PathBuf,
    /// Where a test's environment file goes.
    directory: tempfile::TempDir,
    _store_directory: tempfile::TempDir,
}

impl Live {
    /// A store with a root key, two credentials, and two secrets under one prefix.
    fn seeded_store(database: &std::path::Path) -> (SqliteStore, RootKey, Token, Token) {
        let seal = StaticSeal::from_master_key(
            "CIPHR_MASTER_KEY",
            MasterKey::from_hex(&"11".repeat(32)).expect("a valid master key"),
        );
        let root = RootKey::generate().expect("entropy");
        let root_id = RootKeyId::generate().expect("entropy");

        let mut store = SqliteStore::open(database).expect("open the store");
        store
            .initialize(&SealState {
                seal_id: seal.id().to_owned(),
                wrapped_root_key: seal.rewrap(&root, root_id).expect("wrap the root key"),
            })
            .expect("initialize");

        let pepper = TokenPepper::derive(&root);
        let job = Token::generate().expect("entropy");
        let outsider = Token::generate().expect("entropy");
        for (identity, token) in [("ci-widget", &job), ("outsider", &outsider)] {
            store
                .issue_token(
                    identity,
                    token,
                    &pepper,
                    "operator",
                    None,
                    ciphr_store::TokenPurpose::Credential,
                )
                .expect("issue a token");
        }

        // One ordinary value and one that spans lines, because the multi-line case is the
        // one the heredoc and the per-line masking exist for.
        for (path, value) in [
            ("ci/widget/DB_PASSWORD", "seeded-db"),
            (
                "ci/widget/DEPLOY_KEY",
                "-----BEGIN KEY-----\nmiddle-line\n-----END KEY-----",
            ),
            // Under a prefix of its own, so the tests that fetch `ci/widget` are
            // unaffected. This is what an identity holding `write` would add if it
            // wanted the steps after the fetch to run its code: a name the runtime
            // reads before anything else, and a value that needs no file in the
            // image to be useful (F4).
            ("ci/hostile/NODE_OPTIONS", "--inspect=0.0.0.0:9229"),
        ] {
            let path = SecretPath::parse(path).expect("a valid path");
            let plaintext = Plaintext::from(value.as_bytes());
            store
                .put(&path, "operator", &mut |version| {
                    ciphr_crypto::encrypt(&root, &path, version, &plaintext)
                })
                .expect("seed a secret");
        }

        (store, root, job, outsider)
    }

    /// Start the service with the surface the caller wants, and return once it answers.
    fn start_with(surface: &[&str]) -> Self {
        let store_directory = tempfile::tempdir().expect("temp dir");
        let database = store_directory.path().join("store.db");
        let (store, root, job, outsider) = Self::seeded_store(&database);

        let devices: Vec<Box<dyn AuditDevice>> = vec![Box::new(
            SqliteAuditDevice::open(&database).expect("device"),
        )];
        let sink = AuditSink::new(devices, Chain::new()).expect("sink");
        let policies = ciphr_policy::PolicySet::from_toml(POLICIES).expect("policies");
        let state = AppState::new(
            store,
            sink,
            policies,
            root,
            "static".to_owned(),
            "supplied".to_owned(),
            // Which optional routes exist is the caller's choice here, because both
            // answers are a real deployment: a job has to work against one that named
            // `bulk_export` and against one that named nothing.
            ciphr_server::surface::only(surface).expect("a known entry"),
        );

        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate a certificate");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let address = listener.local_addr().expect("the bound address");
        // Required by `tokio::net::TcpListener::from_std`, which does not check it.
        listener
            .set_nonblocking(true)
            .expect("the listener accepts non-blocking mode");

        let directory = tempfile::tempdir().expect("temp dir");
        let authority = directory.path().join("ca.crt");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&authority, generated.cert.pem().as_bytes()).expect("write the cert");
        std::fs::write(&key_path, generated.signing_key.serialize_pem().as_bytes())
            .expect("write the key");

        let token = write_token(directory.path().join("token"), &job);
        let outsider_token = write_token(directory.path().join("outsider"), &outsider);

        let certificate_path = authority.clone();
        let router = api::router(state);

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");

            runtime.block_on(async move {
                let tls = ciphr_server::tls::load(&certificate_path, &key_path)
                    .await
                    .expect("the generated material is usable");

                axum_server::from_tcp_rustls(listener, tls)
                    .expect("the bound listener is usable")
                    .serve(router.into_make_service())
                    .await
                    .expect("serve");
            });
        });

        let live = Self {
            base_url: format!("https://{address}"),
            authority,
            token,
            outsider_token,
            directory,
            _store_directory: store_directory,
        };
        live.wait_until_up();
        live
    }

    /// The default deployment: no optional route named at all.
    fn start_without_bulk_export() -> Self {
        Self::start_with(&[])
    }

    /// Poll with the program itself, so what is waited for is what the tests then do.
    fn wait_until_up(&self) {
        for attempt in 0..100 {
            let output = self.run(&self.token, &["--path", "ci/widget/DB_PASSWORD"], None);
            if output.status.success() {
                return;
            }
            assert!(
                attempt < 99,
                "the service did not come up: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::thread::sleep(core::time::Duration::from_millis(50));
        }
    }

    /// Run the program, optionally with `GITHUB_ENV` pointing at a file.
    fn run(
        &self,
        token: &std::path::Path,
        flags: &[&str],
        github_env: Option<&std::path::Path>,
    ) -> std::process::Output {
        let mut command = Command::new(PROGRAM);
        command
            .args(["--url", &self.base_url])
            .args(["--token-file", &token.display().to_string()])
            .args(["--ca", &self.authority.display().to_string()])
            .args(flags);

        match github_env {
            Some(path) => {
                command.env("GITHUB_ENV", path);
            }
            None => {
                // Inherited from whoever runs `cargo test`, and on a runner that is a real
                // file this test has no business appending to.
                command.env_remove("GITHUB_ENV");
            }
        }

        command.output().expect("the program runs")
    }

    /// An environment file, seeded as a runner's is: not empty, and not ours.
    fn environment_file(&self, name: &str) -> std::path::PathBuf {
        let path = self.directory.path().join(name);
        std::fs::write(&path, b"SET_BY_AN_EARLIER_STEP=1\n").expect("seed the file");
        path
    }
}

/// A token file the permission check accepts.
fn write_token(path: std::path::PathBuf, token: &Token) -> std::path::PathBuf {
    std::fs::write(&path, token.expose_text().as_bytes()).expect("write the token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict the token file");
    }
    path
}

/// The property the whole binary exists for: the job gets the values, the log does not.
#[test]
fn the_job_gets_the_values_and_the_log_gets_only_masks() {
    let live = Live::start_with(&["bulk_export"]);
    let environment = live.environment_file("env-actions");

    let output = live.run(
        &live.token,
        &[
            "--path",
            "ci/widget/DB_PASSWORD",
            "--path",
            "ci/widget/DEPLOY_KEY",
            "--format",
            "actions-env",
            "--github-env",
            "--report",
        ],
        Some(&environment),
    );

    assert!(
        output.status.success(),
        "the fetch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let printed = String::from_utf8(output.stdout).expect("utf-8");
    // Every line of every value is masked, and the multi-line one line by line.
    assert!(printed.contains("::add-mask::seeded-db"), "{printed}");
    assert!(printed.contains("::add-mask::middle-line"), "{printed}");
    // And standard output carries the mask commands and nothing else: no assignment, and
    // therefore no value that a mask would have to catch up with.
    for line in printed.lines() {
        assert!(
            line.starts_with("::add-mask::"),
            "standard output must carry mask commands only, got {line:?}"
        );
    }

    let written = std::fs::read_to_string(&environment).expect("read back");
    assert!(
        written.starts_with("SET_BY_AN_EARLIER_STEP=1\n"),
        "the file is appended to, not replaced: {written:?}"
    );
    assert!(written.contains("DB_PASSWORD=seeded-db\n"), "{written}");
    // The multi-line value arrives as a heredoc whose delimiter is not derivable from the
    // name, and the value sits inside it unchanged.
    let opening = written
        .lines()
        .find(|line| line.starts_with("DEPLOY_KEY<<"))
        .expect("a heredoc assignment");
    let delimiter = opening.trim_start_matches("DEPLOY_KEY<<");
    assert!(delimiter.starts_with("ciphr_DEPLOY_KEY_"), "{opening}");
    assert!(written.contains("middle-line\n"), "{written}");

    // `--report` names the variables on standard error, and never a value.
    let reported = String::from_utf8(output.stderr).expect("utf-8");
    assert!(reported.contains("DB_PASSWORD"), "{reported}");
    assert!(reported.contains("DEPLOY_KEY"), "{reported}");
    assert!(
        !reported.contains("seeded-db"),
        "a report must carry no value"
    );
}

/// The gap this binary was written next to: a deployment that named no optional route.
#[test]
fn a_default_deployment_serves_a_job_without_naming_an_entry() {
    let live = Live::start_without_bulk_export();
    let environment = live.environment_file("env-default");

    // The prefix form, which is the one that needs both `list` and the read route.
    let output = live.run(
        &live.token,
        &["--prefix", "ci/widget", "--github-env"],
        Some(&environment),
    );

    assert!(
        output.status.success(),
        "a default deployment must serve a job: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read_to_string(&environment).expect("read back");
    assert!(written.contains("DB_PASSWORD=seeded-db\n"), "{written}");
    assert!(written.contains("DEPLOY_KEY<<"), "{written}");
}

/// F4: a secret named after a variable that decides how a process starts.
///
/// The set of names under a prefix is whatever the store holds, so an identity with
/// `write` there chooses environment variable names for every step after this one.
/// `NODE_OPTIONS` is the sharp case: `--inspect` opens a debugger port and needs no
/// file in the image.
///
/// The refusal happens **before the fetch**, so this also asserts what the trail
/// does not get: the values under that prefix are never read.
#[test]
fn a_secret_named_after_a_process_control_variable_is_refused() {
    let live = Live::start_with(&["bulk_export"]);
    let environment = live.environment_file("env-hostile");

    let output = live.run(
        &live.token,
        &["--prefix", "ci/hostile", "--github-env"],
        Some(&environment),
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "nothing may be printed");
    assert_eq!(
        std::fs::read_to_string(&environment).expect("read back"),
        "SET_BY_AN_EARLIER_STEP=1\n",
        "and nothing may be written"
    );

    let message = String::from_utf8(output.stderr).expect("utf-8");
    assert!(message.contains("NODE_OPTIONS"), "{message}");
    assert!(
        message.contains("before the program starts"),
        "the message has to say why that name is different from a password: {message}"
    );
    assert!(
        !message.contains("--inspect"),
        "the value must not be in the message: {message}"
    );
}

/// A refusal leaves the job's environment exactly as it was.
#[test]
fn a_refused_fetch_writes_nothing_and_exits_one() {
    let live = Live::start_with(&["bulk_export"]);
    let environment = live.environment_file("env-refused");

    let output = live.run(
        &live.outsider_token,
        &["--path", "ci/widget/DB_PASSWORD", "--github-env"],
        Some(&environment),
    );

    assert_eq!(output.status.code(), Some(1), "one code for every failure");
    assert!(
        output.stdout.is_empty(),
        "a refusal must print nothing at all, not even a mask"
    );
    assert_eq!(
        std::fs::read_to_string(&environment).expect("read back"),
        "SET_BY_AN_EARLIER_STEP=1\n",
        "the earlier step's variable is untouched and nothing was added"
    );

    let message = String::from_utf8(output.stderr).expect("utf-8");
    assert!(message.contains("ci/widget/DB_PASSWORD"), "{message}");
}

/// A layout that cannot become an environment costs no reads.
#[test]
fn a_prefix_nobody_may_list_is_refused_rather_than_delivered_empty() {
    let live = Live::start_with(&["bulk_export"]);
    let environment = live.environment_file("env-empty");

    let output = live.run(
        &live.outsider_token,
        &["--prefix", "ci/widget", "--github-env"],
        Some(&environment),
    );

    assert_eq!(output.status.code(), Some(1));
    let message = String::from_utf8(output.stderr).expect("utf-8");
    // The two causes are indistinguishable on the wire, and the message says so rather
    // than picking one -- and it names the flag that needs the narrower capability.
    assert!(message.contains("ci/widget"), "{message}");
    assert!(message.contains("--path"), "{message}");
    assert_eq!(
        std::fs::read_to_string(&environment).expect("read back"),
        "SET_BY_AN_EARLIER_STEP=1\n"
    );
}

/// `--github-env` outside a runner is refused before anything is read.
#[test]
fn asking_for_an_environment_file_that_does_not_exist_fetches_nothing() {
    let live = Live::start_with(&["bulk_export"]);

    let output = live.run(
        &live.token,
        &["--path", "ci/widget/DB_PASSWORD", "--github-env"],
        None,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8(output.stderr).expect("utf-8");
    assert!(message.contains("GITHUB_ENV"), "{message}");
}
