//! TLS material.
//!
//! The listener terminates TLS itself (ADR-8). That deviates from the common
//! arrangement — plaintext behind a reverse proxy — on purpose: the content of these
//! connections is plaintext secrets, and on a shared container network a compromised
//! neighbour is a realistic adversary (A2 in the threat model). Everything the design
//! does to keep plaintext off disk is undone if it crosses a bridge network in the
//! clear.
//!
//! Only the certificate and key are configured here. There is no option to disable
//! TLS, and no "insecure" mode: a flag that turns off transport encryption is a flag
//! that ends up set in production.
//!
//! # This is the one place the handshake is decided, and it was not always
//!
//! **The listener advertised HTTP/2 and nothing here asked for it.** `axum-server`
//! requests `hyper/http2` unconditionally, and its `RustlsConfig::from_pem` sets
//! `alpn_protocols = ["h2", "http/1.1"]` — so `grep -rn alpn crates/` found nothing while
//! a real handshake against the listener returned `h2`. Issue #6 read that out of the
//! sources and asked for the measurement; `tests/tls_alpn.rs` performed it, and the
//! reading was right.
//!
//! That mattered for one reason and it is ADR-9's: a second framing implementation —
//! HPACK, stream multiplexing, flow control, CONTINUATION — on the connection path of the
//! one process that holds plaintext secrets, arrived through a transitive feature rather
//! than through a decision, and outside what the accepted review read. [`load`] now sets
//! the list itself, `tests/tls_alpn.rs` pins it, and ADR-9 describes the artefact rather
//! than the manifest.

use std::path::Path;
use std::sync::Arc;

use crate::error::StartupError;

/// What this listener will speak, in the order it prefers.
///
/// One entry, and the shape is deliberate: a *list* rather than an empty vector, because
/// empty means "advertise no ALPN extension at all" and this says the opposite — HTTP/1.1
/// and nothing else. A client that offers only `h2` gets no handshake, which is the honest
/// answer for a service that cannot speak it.
const ALPN: &[&[u8]] = &[b"http/1.1"];

/// Load a certificate chain and private key from PEM files.
///
/// # Errors
///
/// Returns [`StartupError::Tls`] if either file is missing, unreadable, or does not
/// contain what it should. The message names the file and the problem, never the key
/// material.
pub async fn load(
    cert: &Path,
    key: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig, StartupError> {
    // Install the process-wide crypto provider before building any configuration.
    // Doing it here rather than in `main` means a library user cannot forget it, and
    // the call is idempotent in effect: a provider already installed is left alone.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certificates = std::fs::read(cert).map_err(|error| {
        StartupError::Tls(format!(
            "cannot read certificate {}: {error}",
            cert.display()
        ))
    })?;
    let private_key = std::fs::read(key).map_err(|error| {
        StartupError::Tls(format!("cannot read key {}: {error}", key.display()))
    })?;

    // Checked here rather than at the first handshake. A certificate problem should
    // stop the process from starting, not surface as an unexplained connection failure
    // for the first client that tries.
    if !looks_like_pem(&certificates, "CERTIFICATE") {
        return Err(StartupError::Tls(format!(
            "{} does not contain a PEM certificate",
            cert.display()
        )));
    }
    if !looks_like_pem(&private_key, "PRIVATE KEY") {
        return Err(StartupError::Tls(format!(
            "{} does not contain a PEM private key",
            key.display()
        )));
    }

    let config = axum_server::tls_rustls::RustlsConfig::from_pem(certificates, private_key)
        .await
        .map_err(|error| StartupError::Tls(format!("the TLS material is unusable: {error}")))?;

    // **The ALPN list is ours from here on**, and this is the whole of the fix for
    // issue #6. `from_pem` has just set `["h2", "http/1.1"]`; the loop below replaces it
    // with [`ALPN`].
    //
    // Load-then-correct rather than building the `ServerConfig` from scratch, and the
    // reason is the dependency budget: constructing it here means parsing the PEM
    // ourselves, which means a PEM parser in the tree for one field. `axum-server`
    // already parses, so what is left is to set the one thing it should not have decided
    // for us. The cost is that a version of it which stopped setting the field would
    // leave this working and this comment stale — `tests/tls_alpn.rs` is what would say
    // so, because it asserts the negotiated protocol rather than the absence of `h2`.
    //
    // This is also the only place that could ever state a TLS version or cipher policy,
    // and today it states neither: rustls' defaults are TLS 1.2 and 1.3 with its own
    // suite list, and narrowing that is a decision nobody has made yet. Said here so the
    // next reader knows it is unstated rather than considered and rejected.
    let mut server_config = (*config.get_inner()).clone();
    server_config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
    config.reload_from_config(Arc::new(server_config));

    Ok(config)
}

/// Whether a PEM file contains a block of the expected type.
///
/// A shallow check on purpose: rustls does the real parsing. This exists to turn the
/// two mistakes people actually make — swapping the two paths, or pointing at a
/// certificate request — into a message that says which file is wrong.
fn looks_like_pem(bytes: &[u8], label: &str) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .any(|line| line.starts_with("-----BEGIN") && line.contains(label))
}

#[cfg(test)]
mod tests {
    use super::{load, looks_like_pem};

    #[test]
    fn recognizes_the_two_block_types() {
        assert!(looks_like_pem(
            b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            "CERTIFICATE"
        ));
        assert!(looks_like_pem(
            b"-----BEGIN PRIVATE KEY-----\nabc\n",
            "PRIVATE KEY"
        ));
        assert!(looks_like_pem(
            b"-----BEGIN RSA PRIVATE KEY-----\nabc\n",
            "PRIVATE KEY"
        ));

        assert!(!looks_like_pem(b"not pem at all", "CERTIFICATE"));
        assert!(!looks_like_pem(
            b"-----BEGIN CERTIFICATE REQUEST-----\n",
            "PRIVATE KEY"
        ));
    }

    /// A tiny runtime, because `load` is async and these two tests are the only
    /// callers in the crate that are not already inside one.
    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime")
            .block_on(future)
    }

    #[test]
    fn a_missing_file_is_reported_with_its_name() {
        let directory = tempfile::tempdir().expect("temp dir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");

        let error = block_on(load(&cert, &key)).expect_err("must fail");
        assert!(error.to_string().contains("cert.pem"), "got {error}");
    }

    #[test]
    fn swapped_files_are_reported_rather_than_failing_at_the_first_handshake() {
        // The mistake people actually make. Catching it at startup means the operator
        // sees which file is wrong instead of a client seeing a handshake failure.
        let directory = tempfile::tempdir().expect("temp dir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, b"-----BEGIN PRIVATE KEY-----\nabc\n").expect("write");
        std::fs::write(&key, b"-----BEGIN CERTIFICATE-----\nabc\n").expect("write");

        let error = block_on(load(&cert, &key)).expect_err("must fail");
        assert!(
            error
                .to_string()
                .contains("does not contain a PEM certificate"),
            "got {error}"
        );
    }
}
