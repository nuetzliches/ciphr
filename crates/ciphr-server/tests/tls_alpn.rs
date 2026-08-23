//! What the listener advertises, measured against a real handshake.
//!
//! **This file exists because issue #6 was a reading of source and asked to be checked
//! against a running instance.** The reading: `axum-server 0.8.0` requests
//! `hyper/http2` unconditionally, and its `RustlsConfig::from_pem` — the constructor
//! `crate::tls::load` uses — sets `alpn_protocols = ["h2", "http/1.1"]` where nothing in
//! this repository mentions ALPN at all. So the listener that holds plaintext secrets
//! advertised a second framing implementation that ADR-9's narrow-stack argument never
//! chose, and `grep -rn alpn crates/` found nothing to explain it.
//!
//! What is measured here is the handshake produced by `crate::tls::load`, which is the
//! one place this repository configures TLS. The router behind it is a stub on purpose:
//! ALPN is settled before any request reaches a handler, so building an `AppState` here
//! would add a store, a seal and an audit sink to a test about a byte on the wire.
//!
//! The test is the pin ADR-9's amendment asks for: a dependency bump that restores `h2`
//! to the ALPN list fails here rather than in a deployment.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use rustls::pki_types::CertificateDer;

/// Start a listener with the service's own TLS configuration, and return where it is
/// plus the certificate a client has to trust.
///
/// Bound before the serving thread is spawned, so the address really is the one being
/// served rather than one that was free a moment ago — the same reason
/// `ciphr-sdk/tests/live.rs` does it in that order.
///
/// The certificate comes back as DER rather than PEM to keep a PEM parser out of the
/// dependency list for one test: `rcgen` has the DER already, and the client below wants
/// exactly that.
fn serve() -> (SocketAddr, CertificateDer<'static>) {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("generate a certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der = generated.cert.der().clone();
    let key_pem = generated.signing_key.serialize_pem();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let address = listener.local_addr().expect("the bound address");
    listener
        .set_nonblocking(true)
        .expect("the listener accepts non-blocking mode");

    let directory = tempfile::tempdir().expect("temp dir");
    let certificate_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&certificate_path, certificate_pem.as_bytes()).expect("write the cert");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write the key");

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");

        runtime.block_on(async move {
            // The service's own loader, which is the subject of the measurement.
            let tls = ciphr_server::tls::load(&certificate_path, &key_path)
                .await
                .expect("the generated material is usable");
            let _held = directory;

            let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));

            axum_server::from_tcp_rustls(listener, tls)
                .expect("the bound listener is usable")
                .serve(router.into_make_service())
                .await
                .expect("serve");
        });
    });

    (address, certificate_der)
}

/// A client that trusts one certificate and offers exactly these protocols.
fn client(authority: &CertificateDer<'static>, offer: &[&[u8]]) -> rustls::ClientConfig {
    // Idempotent in effect, and needed because a test may reach the client before the
    // server thread has called `tls::load`, which is where the service installs it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(authority.clone())
        .expect("the generated certificate is usable as a root");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = offer.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

/// Complete a handshake against `address` and report the protocol that was selected.
///
/// The handshake is driven to completion and nothing is sent afterwards: ALPN is decided
/// in the hello exchange, so no request is needed and none would be meaningful before
/// knowing which framing to use.
fn handshake(
    address: SocketAddr,
    config: rustls::ClientConfig,
) -> Result<Option<String>, rustls::Error> {
    let server = rustls::pki_types::ServerName::try_from("127.0.0.1").expect("a valid name");
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server)?;
    let mut socket = TcpStream::connect(address).expect("connect to the listener");

    while connection.is_handshaking() {
        // An I/O error here means the peer closed the connection, which is how a
        // handshake refused for want of a common protocol arrives at this end.
        connection.complete_io(&mut socket).map_err(|error| {
            rustls::Error::General(format!("the handshake did not complete: {error}"))
        })?;
    }

    Ok(connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned()))
}

/// The measurement issue #6 asked for, and the pin for the decision that followed it.
///
/// A client that offers both gets `http/1.1`. Before ADR-9's amendment it got `h2`,
/// because the ALPN list came from `axum-server` rather than from this repository.
#[test]
fn a_client_offering_h2_and_http1_1_is_given_http1_1() {
    let (address, authority) = serve();

    let chosen = handshake(address, client(&authority, &[b"h2", b"http/1.1"]))
        .expect("a client offering http/1.1 has something in common with this listener");

    assert_eq!(
        chosen.as_deref(),
        Some("http/1.1"),
        "the listener must not offer a second framing implementation"
    );
}

/// A client that will speak nothing but HTTP/2 gets no connection.
///
/// The other half of the same property, and the one that says the list is not merely
/// *ordered* in our favour: with `h2` alone on offer there is no overlap, so the
/// handshake fails. A listener that still had `h2` in its list would answer this one
/// happily.
#[test]
fn a_client_offering_only_h2_gets_no_handshake() {
    let (address, authority) = serve();

    let outcome = handshake(address, client(&authority, &[b"h2"]));

    assert!(
        outcome.is_err(),
        "an h2-only client has nothing in common with this listener, got {outcome:?}"
    );
}
