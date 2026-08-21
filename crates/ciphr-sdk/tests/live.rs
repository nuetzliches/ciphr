//! The client against the real service, over a real TLS socket.
//!
//! Everything else in this crate is tested against its own assumptions. This file is
//! the one that can fail when the client and the service disagree, so it runs the
//! actual router, the actual authentication, the actual policy evaluator and the actual
//! audit sink, reached over a TCP connection with a real handshake. Nothing is mocked
//! and there is no test mode: a client that only ever spoke to a fake of the server is
//! a client nobody has run.
//!
//! The certificate is generated per test run rather than checked in. A committed key
//! pair is test fixture material that looks like real key material, which `AGENTS.md`
//! rules out — and it would also be the one file in this repository whose leak nobody
//! would treat as an incident, which is exactly how a real one gets ignored.

use std::net::TcpListener;

use ciphr_audit::{AuditDevice, AuditSink, Chain};
use ciphr_core::{Plaintext, SecretPath};
use ciphr_crypto::{MasterKey, RootKey, RootKeyId, Seal, StaticSeal, Token, TokenPepper};
use ciphr_sdk::{Client, SdkError};
use ciphr_server::{AppState, api};
use ciphr_store::{SealState, SqliteAuditDevice, SqliteStore, Store};

/// One identity that may work under `infra/**`, and one that may not reach it at all.
///
/// The second one exists so that `403` is tested against the real evaluator rather than
/// against a hand-built response.
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
  capabilities = ["read", "list", "write", "delete"]

[[policy]]
name = "nothing"

  [[policy.rule]]
  path         = "elsewhere/**"
  capabilities = ["read"]
"#;

/// A live service, its trust anchor, and tokens for both identities.
struct Live {
    /// `https://127.0.0.1:<port>`.
    base_url: String,
    /// The certificate the client has to trust, as PEM.
    certificate_authority: Vec<u8>,
    /// A token for `service-a`.
    token: String,
    /// A token for `outsider`.
    outsider_token: String,
    /// Kept alive so the database is not removed while the service runs.
    _directory: tempfile::TempDir,
}

impl Live {
    /// Start the service on an ephemeral port and return once it is listening.
    fn start() -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let database = directory.path().join("store.db");

        // A fixed master key: this is a test store that exists for milliseconds, and a
        // value that obviously is not one is better than one that looks plausible.
        let seal = StaticSeal::from_master_key(
            "CIPHR_MASTER_KEY",
            MasterKey::from_hex(&"11".repeat(32)).expect("a valid master key"),
        );
        let root = RootKey::generate().expect("entropy");
        let root_id = RootKeyId::generate().expect("entropy");

        let mut store = SqliteStore::open(&database).expect("open the store");
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

        // Two secrets under one prefix, with distinct last segments, so the prefix has
        // a usable environment.
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
            // The surface the default build has: nothing. A test that wants an entry
            // resolves one explicitly, so no test inherits a shape it did not ask for.
            ciphr_server::ActiveSurface::default(),
        );

        // The certificate covers both spellings of the loopback address; the client
        // connects by IP, because on some platforms `localhost` resolves to `::1` first
        // while the listener below is on `127.0.0.1`.
        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate a certificate");
        let certificate_pem = generated.cert.pem();
        let key_pem = generated.signing_key.serialize_pem();

        // Bound before the server is spawned, so the port in `base_url` is the port the
        // service is on rather than one that was free a moment ago.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let address = listener.local_addr().expect("the bound address");
        // `tokio::net::TcpListener::from_std` requires this, and does not check it: a
        // blocking listener handed to a runtime blocks it inside `accept`.
        listener
            .set_nonblocking(true)
            .expect("the listener accepts non-blocking mode");

        let tls_directory = tempfile::tempdir().expect("temp dir");
        let certificate_path = tls_directory.path().join("cert.pem");
        let key_path = tls_directory.path().join("key.pem");
        std::fs::write(&certificate_path, certificate_pem.as_bytes()).expect("write the cert");
        std::fs::write(&key_path, key_pem.as_bytes()).expect("write the key");

        let router = api::router(state);

        // A thread with its own runtime: the client is blocking, so it cannot share one
        // with the server.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");

            runtime.block_on(async move {
                // The same loader the service uses, which is also what installs the
                // process-wide crypto provider for the listener.
                let tls = ciphr_server::tls::load(&certificate_path, &key_path)
                    .await
                    .expect("the generated material is usable");

                // `tls_directory` is dropped when this closure ends, so it is moved in
                // and held until the server stops.
                let _held = tls_directory;

                axum_server::from_tcp_rustls(listener, tls)
                    .expect("the bound listener is usable")
                    .serve(router.into_make_service())
                    .await
                    .expect("serve");
            });
        });

        Self {
            base_url: format!("https://{address}"),
            certificate_authority: certificate_pem.into_bytes(),
            // `expose_text` hands back a `Zeroizing<String>`; the test needs it for the
            // life of the run, so the wrapper is unwrapped here deliberately.
            token: service.expose_text().to_string(),
            outsider_token: outsider.expose_text().to_string(),
            _directory: directory,
        }
    }

    /// A client for `service-a`.
    fn client(&self) -> Client {
        self.client_with(&self.token, &self.certificate_authority)
    }

    /// A client with a specific credential and trust anchor.
    fn client_with(&self, token: &str, authority: &[u8]) -> Client {
        // The service is starting on another thread. Retrying the *health* endpoint is
        // how the test waits for it, rather than sleeping a guessed interval.
        let client = Client::builder(&self.base_url, token, authority)
            .timeout(core::time::Duration::from_secs(5))
            .build()
            .expect("a usable client");

        for attempt in 0..100 {
            match client.health() {
                Ok(_) => return client,
                // A rejected certificate is not a service that has not started yet, and
                // waiting for it would turn a real failure into a slow one.
                Err(SdkError::Transport { .. }) if attempt < 99 => {
                    std::thread::sleep(core::time::Duration::from_millis(50));
                }
                Err(error) => panic!("the service did not come up: {error}"),
            }
        }

        panic!("the service did not come up");
    }
}

/// Everything against one running service, in one test.
///
/// One test rather than a dozen because starting the service is the expensive part, and
/// because these assertions are about one conversation: a client that can read but not
/// write would pass six separate tests and still be wrong.
#[test]
fn the_client_and_the_service_agree() {
    let live = Live::start();
    let client = live.client();

    // -- health: reachable, and saying what it enforces --------------------------------
    let health = client.health().expect("health");
    assert_eq!(health.status, "ok");
    assert!(!health.sealed, "a sealed service serves nothing");
    assert_eq!(health.api_version, "v1");
    assert_eq!(health.key_source, "supplied");
    assert_eq!(health.audit_devices.len(), 1);

    // -- read ---------------------------------------------------------------------------
    let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid");
    let secret = client.get(&path).expect("read");
    assert_eq!(secret.value.expose(), b"seeded-db");
    assert_eq!(secret.path, path);
    assert_eq!(secret.version.get(), 1);
    assert_eq!(secret.created_by, "operator");

    // -- write, then read back the new version ------------------------------------------
    let written = client
        .put(&path, &Plaintext::from(&b"rotated"[..]))
        .expect("write");
    assert_eq!(written.version.get(), 2);
    assert_eq!(client.get(&path).expect("read").value.expose(), b"rotated");

    // An explicit older version still serves the older value: this is the call that
    // would break if the query parameter were spelled wrong, and a client that silently
    // returned the *current* value instead would be worse than one that failed.
    let first = client
        .get_version(&path, ciphr_core::SecretVersion::FIRST)
        .expect("read version 1");
    assert_eq!(first.value.expose(), b"seeded-db");

    // -- versions and list --------------------------------------------------------------
    let history = client.versions(&path).expect("versions");
    assert_eq!(history.versions.len(), 2);
    assert!(history.versions.iter().all(|entry| !entry.destroyed));

    // The classification arrives with the history, over the wire, from the real
    // service: nothing here wrote a class, so nobody has classified this secret --
    // and the service says that rather than reporting the safe-sounding default it
    // used to invent.
    assert_eq!(history.rotation.class, "unclassified");
    assert!(history.rotation.needs_care);
    assert!(history.rotation.advice.contains("ciphr rotation"));

    let prefix = SecretPath::parse("infra/service-a").expect("valid");
    let mut listed: Vec<String> = client
        .list(&prefix)
        .expect("list")
        .iter()
        .map(|path| path.as_str().to_owned())
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        ["infra/service-a/API_TOKEN", "infra/service-a/DB_PASSWORD"]
    );

    // -- export -------------------------------------------------------------------------
    let exported = client
        .export(&[
            SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid"),
            SecretPath::parse("infra/service-a/API_TOKEN").expect("valid"),
        ])
        .expect("export");
    assert_eq!(exported.len(), 2);

    // -- the whole prefix as an environment: route C ------------------------------------
    let environment = client.environment(&prefix).expect("an environment");
    assert_eq!(environment.len(), 2);
    assert_eq!(
        environment.get("DB_PASSWORD").expect("present").expose(),
        b"rotated"
    );
    assert_eq!(
        environment.get("API_TOKEN").expect("present").expose(),
        b"seeded-api"
    );

    // -- delete -------------------------------------------------------------------------
    client.delete(&path).expect("delete");
    match client.get(&path) {
        Err(SdkError::NotFound { .. }) => {}
        Err(other) => panic!("expected a 404 after a delete, got {other}"),
        Ok(_) => panic!("a deleted secret was still served"),
    }
}

/// The refusals, which are the half a client gets wrong quietly.
#[test]
fn refusals_arrive_as_the_variant_a_caller_can_act_on() {
    let live = Live::start();
    let client = live.client();

    // A path this identity has no rule for. The evaluator refuses it; the response says
    // nothing about which rule did, and neither does the error.
    let elsewhere = SecretPath::parse("infra/service-b/DB_PASSWORD").expect("valid");
    match client.get(&elsewhere) {
        Err(SdkError::Forbidden { path }) => assert_eq!(path, elsewhere.as_str()),
        Err(other) => panic!("expected a 403, got {other}"),
        Ok(_) => panic!("a secret outside the policy was served"),
    }

    // Present and permitted, but not there.
    let missing = SecretPath::parse("infra/service-a/ABSENT").expect("valid");
    match client.get(&missing) {
        Err(SdkError::NotFound { path }) => assert_eq!(path, missing.as_str()),
        Err(other) => panic!("expected a 404, got {other}"),
        Ok(_) => panic!("a secret that does not exist was served"),
    }

    // The reserved prefix cannot hold secrets, so a write there is refused as malformed
    // rather than as forbidden.
    let reserved = SecretPath::parse("sys/audit").expect("valid");
    match client.put(&reserved, &Plaintext::from(&b"x"[..])) {
        Err(SdkError::BadRequest { .. }) => {}
        Err(other) => panic!("expected a 400, got {other}"),
        Ok(_) => panic!("a write under the reserved prefix succeeded"),
    }

    // A token that is not a token. The service does not say which part was wrong.
    let stranger = Client::builder(&live.base_url, "not-a-token", &live.certificate_authority)
        .build()
        .expect("a client");
    match stranger.get(&SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid")) {
        Err(SdkError::Unauthenticated) => {}
        Err(other) => panic!("expected a 401, got {other}"),
        Ok(_) => panic!("an invalid token was accepted"),
    }

    // An identity with no rule reaching the prefix sees an empty listing, because
    // `GET /v1/list` authorizes each path it would return. `environment` refuses that
    // rather than handing back an empty environment a service would boot with.
    let outsider = live.client_with(&live.outsider_token, &live.certificate_authority);
    let prefix = SecretPath::parse("infra/service-a").expect("valid");
    assert!(
        outsider
            .list(&prefix)
            .expect("list is authenticated only")
            .is_empty(),
        "an unauthorized listing is empty, not an error"
    );
    match outsider.environment(&prefix) {
        Err(SdkError::NothingUnderPrefix { .. }) => {}
        Err(other) => panic!("expected a refusal, got {other}"),
        Ok(_) => panic!("an empty environment was handed to a consumer"),
    }
}

/// The property ADR-17 is about: this client trusts one key, and not a set.
#[test]
fn a_certificate_from_another_authority_is_refused() {
    let live = Live::start();
    // Wait for the service using the correct anchor, so that the failure below is about
    // the anchor and not about a service that has not started.
    let _ready = live.client();

    let other = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("generate a second certificate");
    let stranger = live.client_with_untrusted(&other.cert.pem().into_bytes());

    match stranger.get(&SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid")) {
        // A handshake that does not verify is a transport failure, which is also the one
        // class this client calls retryable — the honest classification, since a client
        // cannot tell a rejected certificate from a broken network without trusting the
        // peer to explain itself.
        Err(SdkError::Transport { .. }) => {}
        Err(other) => panic!("expected the handshake to fail, got {other}"),
        Ok(_) => panic!("a certificate from an unrelated authority was accepted"),
    }
}

impl Live {
    /// A client whose trust anchor is deliberately wrong, built without waiting for
    /// health — the health check is what is expected to fail.
    fn client_with_untrusted(&self, authority: &[u8]) -> Client {
        Client::builder(&self.base_url, &self.token, authority)
            .timeout(core::time::Duration::from_secs(5))
            .build()
            .expect("a client can be built; the handshake is what fails")
    }
}
