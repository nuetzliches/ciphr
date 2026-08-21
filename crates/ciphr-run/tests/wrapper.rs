//! The wrapper as a deployment uses it: the real binary, the real service, a real `exec`.
//!
//! `#![cfg(unix)]` covers the whole file, so on a platform without `exec` this compiles to
//! nothing rather than to a set of tests that skip themselves. The binary refuses there
//! anyway, and a test asserting a refusal on the development machine would say nothing
//! about the platform this program is for.
//!
//! The child has to be a separate process for a reason that is easy to miss: `exec`
//! replaces the process image, so a test that called it in-process would replace the test
//! runner. Everything here therefore goes through the built binary, which is also what a
//! container definition invokes.
//!
//! The service harness below is a near-twin of the one in `ciphr-sdk/tests/live.rs`. It is
//! duplicated rather than shared because sharing it would mean a ninth crate whose only
//! purpose is test scaffolding. If a third consumer appears, that is the moment to extract
//! it — not before.

#![cfg(unix)]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use ciphr_audit::{AuditDevice, AuditSink, Chain};
use ciphr_core::{Plaintext, SecretPath};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, Token, TokenPepper};
use ciphr_server::{AppState, api};
use ciphr_store::{SealState, SqliteAuditDevice, SqliteStore, Store};

/// The binary under test, built by cargo for this integration test.
const WRAPPER: &str = env!("CARGO_BIN_EXE_ciphr-run");

/// One identity for the service, and one that cannot reach its prefix.
const POLICIES: &str = r#"
[[identity]]
name     = "service-a"
kind     = "machine"
policies = ["service-a"]

[[identity]]
name     = "outsider"
kind     = "machine"
policies = ["nothing"]

[[policy]]
name = "service-a"

  [[policy.rule]]
  path         = "infra/service-a/**"
  capabilities = ["read", "list"]

[[policy]]
name = "nothing"

  [[policy.rule]]
  path         = "elsewhere/**"
  capabilities = ["read"]
"#;

/// A live service and the files a wrapper invocation needs.
struct Live {
    base_url: String,
    /// The same service addressed by name rather than by address.
    base_url_by_name: String,
    /// Path to the PEM the wrapper must trust.
    authority: std::path::PathBuf,
    /// Path to a token file for `service-a`, mode 0600.
    token: std::path::PathBuf,
    /// Path to a token file for `outsider`, mode 0600.
    outsider_token: std::path::PathBuf,
    /// Held so the files survive for the test's lifetime.
    _directory: tempfile::TempDir,
    _store_directory: tempfile::TempDir,
}

impl Live {
    /// A store with a root key, two credentials, and two secrets under one prefix.
    ///
    /// Extracted from [`Self::start`] because that function crossed clippy's line
    /// budget — and it only crossed it in CI, since `#![cfg(unix)]` means this file
    /// compiles to nothing on the development machine. Worth the note: a lint on a
    /// unix-gated file is a lint nobody sees locally.
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
        let service = Token::generate().expect("entropy");
        let outsider = Token::generate().expect("entropy");
        for (identity, token) in [("service-a", &service), ("outsider", &outsider)] {
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

        for (path, value) in [
            ("infra/service-a/DB_PASSWORD", "seeded-db"),
            ("infra/service-a/API_TOKEN", "seeded-api"),
        ] {
            let path = SecretPath::parse(path).expect("a valid path");
            let plaintext = Plaintext::from(value.as_bytes());
            store
                .put(&path, "operator", &mut |version| {
                    ciphr_crypto::encrypt(&root, &path, version, &plaintext)
                })
                .expect("seed a secret");
        }

        (store, root, service, outsider)
    }

    fn start() -> Self {
        let store_directory = tempfile::tempdir().expect("temp dir");
        let database = store_directory.path().join("store.db");
        let (store, root, service, outsider) = Self::seeded_store(&database);

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
            // `bulk_export` is a surface entry now (ADR-20), and a prefix fetch goes
            // through `POST /v1/export` -- so an empty surface would test the router's
            // fallback rather than this client. `only` rather than `resolve`: this
            // composes a router in-process, which is not a deployment starting on a
            // configuration, so the startup record ADR-20 requires does not apply.
            ciphr_server::surface::only(&["bulk_export"]).expect("a known entry"),
        );

        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate a certificate");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let address = listener.local_addr().expect("the bound address");
        // Required by `tokio::net::TcpListener::from_std`, which does not check it: a
        // blocking listener handed to a runtime blocks it inside `accept`.
        listener
            .set_nonblocking(true)
            .expect("the listener accepts non-blocking mode");

        let directory = tempfile::tempdir().expect("temp dir");
        let authority = directory.path().join("ca.crt");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&authority, generated.cert.pem().as_bytes()).expect("write the cert");
        std::fs::write(&key_path, generated.signing_key.serialize_pem().as_bytes())
            .expect("write the key");

        let token = write_token(directory.path().join("token"), &service);
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
            // The certificate carries both names, so this reaches the same listener
            // through the resolver instead of past it.
            base_url_by_name: format!("https://localhost:{}", address.port()),
            authority,
            token,
            outsider_token,
            _directory: directory,
            _store_directory: store_directory,
        };
        live.wait_until_up();
        live
    }

    /// Poll until the service answers, rather than sleeping a guessed interval.
    ///
    /// Uses the wrapper itself with `/bin/true`, so what is being waited for is exactly
    /// what the tests then do.
    fn wait_until_up(&self) {
        for attempt in 0..100 {
            let status = self
                .invoke(
                    &self.token,
                    &["--prefix", "infra/service-a"],
                    &["/bin/true"],
                )
                .expect("the wrapper runs");

            if status.success() {
                return;
            }
            assert!(attempt < 99, "the service did not come up");
            std::thread::sleep(core::time::Duration::from_millis(50));
        }
    }

    /// Run the wrapper with a token file, its own flags, and a command.
    fn invoke(
        &self,
        token: &std::path::Path,
        flags: &[&str],
        command: &[&str],
    ) -> std::io::Result<std::process::ExitStatus> {
        self.invoke_at(&self.base_url, token, flags, command)
    }

    /// Run the wrapper and capture what it wrote, rather than only its status.
    fn capture(
        &self,
        token: &std::path::Path,
        flags: &[&str],
        command: &[&str],
    ) -> std::process::Output {
        Command::new(WRAPPER)
            .args(["--url", &self.base_url])
            .args(["--token-file", &token.display().to_string()])
            .args(["--ca", &self.authority.display().to_string()])
            .args(flags)
            .arg("--")
            .args(command)
            .output()
            .expect("the wrapper runs")
    }

    /// The same, against a given URL.
    fn invoke_at(
        &self,
        url: &str,
        token: &std::path::Path,
        flags: &[&str],
        command: &[&str],
    ) -> std::io::Result<std::process::ExitStatus> {
        Command::new(WRAPPER)
            .args(["--url", url])
            .args(["--token-file", &token.display().to_string()])
            .args(["--ca", &self.authority.display().to_string()])
            .args(flags)
            .arg("--")
            .args(command)
            .status()
    }
}

/// Write a token to a file only its owner can read.
fn write_token(path: std::path::PathBuf, token: &Token) -> std::path::PathBuf {
    std::fs::write(&path, token.expose_text().as_bytes()).expect("write the token");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict the token file");
    path
}

/// The whole point: the child sees the values, under the ADR-18 names.
#[test]
fn the_child_receives_the_secrets_under_their_last_path_segment() {
    let live = Live::start();

    // The assertion is made by the child, in the environment the wrapper built for it.
    // If either variable is missing or wrong, `sh` exits non-zero and this fails.
    let status = live
        .invoke(
            &live.token,
            &["--prefix", "infra/service-a"],
            &[
                "/bin/sh",
                "-c",
                r#"test "$DB_PASSWORD" = seeded-db && test "$API_TOKEN" = seeded-api"#,
            ],
        )
        .expect("the wrapper runs");

    assert!(
        status.success(),
        "the child did not see both secrets: {status:?}"
    );
}

/// The child really is the same process, not a supervised one.
#[test]
fn the_wrapper_replaces_itself_rather_than_supervising() {
    let live = Live::start();

    // Two observations in one child. `$$` is the shell's own pid; the wrapper was started
    // by this test, so if the shell had been spawned as a *child* of the wrapper, its
    // parent would be the wrapper rather than this test process. After `exec` the shell
    // occupies the wrapper's pid, so its parent is whatever started the wrapper.
    //
    // The second half is the one that matters operationally: the exit code is the child's
    // own, not a code a supervisor chose to forward.
    let status = live
        .invoke(
            &live.token,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", "exit 42"],
        )
        .expect("the wrapper runs");

    assert_eq!(
        status.code(),
        Some(42),
        "the child's exit code must be the process's exit code"
    );
}

/// `--path` instead of `--prefix`: the same delivery with one capability less.
#[test]
fn named_paths_need_no_list_capability() {
    let live = Live::start();

    let status = live
        .invoke(
            &live.token,
            &["--path", "infra/service-a/DB_PASSWORD"],
            &[
                "/bin/sh",
                "-c",
                r#"test "$DB_PASSWORD" = seeded-db && test -z "$API_TOKEN""#,
            ],
        )
        .expect("the wrapper runs");

    assert!(
        status.success(),
        "a named path must deliver exactly that secret: {status:?}"
    );
}

/// Condition 3 of ADR-14, as a test: a failed fetch must not start the command.
#[test]
fn nothing_is_executed_when_the_fetch_fails() {
    let live = Live::start();

    // A file that exists, is readable only by its owner, and is not a token.
    let directory = tempfile::tempdir().expect("temp dir");
    let wrong = directory.path().join("token");
    std::fs::write(&wrong, b"not-a-token\n").expect("write");
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).expect("restrict");

    // The command would create this file if it ever ran. Nothing else can create it, so
    // its absence afterwards is the assertion.
    let evidence = directory.path().join("the-child-ran");
    let status = live
        .invoke(
            &wrong,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", &format!("touch {}", evidence.display())],
        )
        .expect("the wrapper runs");

    assert_eq!(
        status.code(),
        Some(125),
        "an authentication failure is the wrapper's failure, not the child's"
    );
    assert!(
        !evidence.exists(),
        "the command ran despite the fetch failing"
    );
}

/// The same, for a prefix this identity may not list.
#[test]
fn an_identity_without_the_prefix_starts_nothing() {
    let live = Live::start();

    let directory = tempfile::tempdir().expect("temp dir");
    let evidence = directory.path().join("the-child-ran");

    let status = live
        .invoke(
            &live.outsider_token,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", &format!("touch {}", evidence.display())],
        )
        .expect("the wrapper runs");

    // An empty listing, which the SDK refuses rather than turning into an empty
    // environment. A service booting with no secrets is the failure this prevents.
    assert_eq!(status.code(), Some(125));
    assert!(!evidence.exists(), "the command ran with no secrets");
}

/// A world-readable token file stops the process before it is used.
#[test]
fn a_world_readable_token_file_is_refused() {
    let live = Live::start();

    let directory = tempfile::tempdir().expect("temp dir");
    let exposed = directory.path().join("token");
    std::fs::copy(&live.token, &exposed).expect("copy the token");
    std::fs::set_permissions(&exposed, std::fs::Permissions::from_mode(0o644)).expect("loosen");

    let evidence = directory.path().join("the-child-ran");
    let status = live
        .invoke(
            &exposed,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", &format!("touch {}", evidence.display())],
        )
        .expect("the wrapper runs");

    assert_eq!(status.code(), Some(125));
    assert!(!evidence.exists(), "a leaked credential was used anyway");
}

/// A token file anyone can replace stops the process too, even though nobody can read it.
///
/// Finding F6: the check asked only whether the world could read, so mode `0602` started
/// the wrapper. For a token file that is the more useful bit to hold — an attacker who can
/// write it does not need to learn this token, they can substitute one of their own and
/// have the wrapper fetch secrets under an identity they control.
#[test]
fn a_world_writable_token_file_is_refused() {
    let live = Live::start();

    let directory = tempfile::tempdir().expect("temp dir");
    let replaceable = directory.path().join("token");
    std::fs::copy(&live.token, &replaceable).expect("copy the token");
    std::fs::set_permissions(&replaceable, std::fs::Permissions::from_mode(0o602)).expect("loosen");

    let evidence = directory.path().join("the-child-ran");
    let status = live
        .invoke(
            &replaceable,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", &format!("touch {}", evidence.display())],
        )
        .expect("the wrapper runs");

    assert_eq!(status.code(), Some(125));
    assert!(
        !evidence.exists(),
        "a replaceable credential was used anyway"
    );
}

/// The exit codes that let a restart policy tell the two failures apart.
#[test]
fn a_missing_command_is_127_and_the_secrets_are_still_gone() {
    let live = Live::start();

    let status = live
        .invoke(
            &live.token,
            &["--prefix", "infra/service-a"],
            &["/definitely/not/here"],
        )
        .expect("the wrapper runs");

    // 127 rather than 125: the fetch succeeded and the *command* is the problem, which is
    // a different thing for an operator to go and fix.
    assert_eq!(status.code(), Some(127));
}

/// A hostname has to resolve from the shipped binary, which is statically linked.
///
/// The reason this is its own test: static musl is exactly where name resolution breaks,
/// because NSS modules cannot be loaded into a static binary. Files and DNS still work,
/// and this proves the resolver runs at all — every other test here connects by address
/// and would pass on a binary that cannot resolve a name.
#[test]
fn a_hostname_resolves_from_the_wrapper() {
    let live = Live::start();

    let status = live
        .invoke_at(
            &live.base_url_by_name,
            &live.token,
            &["--prefix", "infra/service-a"],
            &["/bin/sh", "-c", r#"test "$DB_PASSWORD" = seeded-db"#],
        )
        .expect("the wrapper runs");

    assert!(
        status.success(),
        "the wrapper could not reach the service by name: {status:?}"
    );
}

/// `--report` is the only thing here that prints near a secret, so what it prints is
/// checked rather than asserted in a comment.
#[test]
fn the_report_names_the_variables_and_never_their_values() {
    let live = Live::start();

    let output = live.capture(
        &live.token,
        &["--prefix", "infra/service-a", "--report"],
        // The child prints nothing, so everything on stderr came from the wrapper.
        &["/bin/true"],
    );

    assert!(output.status.success(), "{output:?}");
    let reported = String::from_utf8_lossy(&output.stderr);

    // The names, and the program that replaced the process.
    assert!(reported.contains("DB_PASSWORD"), "{reported}");
    assert!(reported.contains("API_TOKEN"), "{reported}");
    assert!(reported.contains("/bin/true"), "{reported}");

    // And neither seeded value, on either stream. This is the assertion the flag exists
    // to keep true: `Plan` exposes its names and has no accessor for its values.
    for stream in [&output.stderr, &output.stdout] {
        let text = String::from_utf8_lossy(stream);
        assert!(!text.contains("seeded-db"), "a value was printed: {text}");
        assert!(!text.contains("seeded-api"), "a value was printed: {text}");
    }
}
