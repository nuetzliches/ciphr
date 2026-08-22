//! The client, and the three things it refuses to be built without.
//!
//! # Why the certificate authority is required
//!
//! There is no way to construct a [`Client`] that trusts the public CA set. That is not
//! a convenience left out; it is [ADR-17](../../../docs/adr/0017-certificate-provenance.md)
//! expressed in a signature. The machine path to ciphr is pinned on a CA this deployment
//! owns, because `--cacert` *replaces* the trust store for that call rather than
//! extending it: a client that trusted the `WebPKI` would trust every public root on the
//! one hop whose content is plaintext secrets.
//!
//! The transport is compiled without `webpki-roots` (ADR-19), so the public root set is
//! not merely unused here — it is not linked into the binary. A future refactor cannot
//! reintroduce it by forgetting a builder call.
//!
//! # Why it is blocking
//!
//! The call this client exists for is one fetch during startup. An async runtime in
//! every consuming application would be a dependency with nothing behind it, and the
//! same client has to work inside `ciphr run`, which is a single-purpose static binary
//! (ADR-14). A service that already runs an async runtime calls this before starting it,
//! or on a blocking task.

use core::time::Duration;
use std::sync::Arc;

use ciphr_core::{EnvVarName, Plaintext, Rotation, SecretPath, SecretVersion};
use secrecy::{ExposeSecret, SecretString};

use crate::environment::Environment;
use crate::error::SdkError;
use crate::types::{
    Classification, DeviceHealth, DeviceHealthWire, ErrorWire, ExportWire, Health, HealthWire,
    History, ListingWire, Secret, SecretWire, VersionSummary, VersionsWire, Written, WrittenWire,
};

/// How long a request may take in total, if the caller states nothing else.
///
/// Chosen for the case this client exists for: a container start that is waiting on it.
/// Long enough for a slow handshake on a cold service, short enough that a wedged
/// connection surfaces as a failed start rather than as a container that hangs.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response body this client will read.
///
/// An export of a whole prefix is the biggest legitimate response, and secret values are
/// text. The limit is here because `read_to_string` without one is an unbounded
/// allocation driven by whatever answered the socket.
const MAX_BODY: u64 = 8 * 1024 * 1024;

/// A client for one ciphr instance, authenticating as one identity.
///
/// Cheap to clone in the sense that matters — the connection pool is shared — but there
/// is no `Clone`, because a second handle to the same credential is a thing to pass
/// deliberately rather than to copy.
///
/// No `Debug`: it holds a token.
pub struct Client {
    agent: ureq::Agent,
    /// `https://host:port`, without a trailing slash.
    base: String,
    /// The whole `Bearer …` header line, built once.
    ///
    /// Built once rather than per request so that exactly one copy of the token exists in
    /// this process, and it is wiped when the client is dropped. Formatting it per call
    /// would leave a `String` containing the token behind on every request.
    authorization: SecretString,
}

impl Client {
    /// Start building a client.
    ///
    /// All three arguments are required, and each of them is required for a reason rather
    /// than for tidiness: a base URL that is not `https` is refused (ADR-8 terminates TLS
    /// at the service), a client without a token can do nothing but ask about health, and
    /// a client without a trust anchor would have to fall back on the platform's.
    pub fn builder(base_url: &str, token: &str, certificate_authority_pem: &[u8]) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.to_owned(),
            token: SecretString::from(token.to_owned()),
            certificate_authority_pem: certificate_authority_pem.to_vec(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Read the current version of a secret.
    ///
    /// Requires the `read` capability. Produces exactly one audit entry, under the
    /// identity of this client's token — which is the point of route C: the trail then
    /// names the service that used the secret rather than the runner that deployed it.
    ///
    /// # Errors
    ///
    /// [`SdkError::NotFound`] if there is no such secret, [`SdkError::Forbidden`] if the
    /// policy refused, and see [`SdkError`] for the rest.
    pub fn get(&self, path: &SecretPath) -> Result<Secret, SdkError> {
        self.read_secret(path, None)
    }

    /// Read one specific version of a secret.
    ///
    /// # Errors
    ///
    /// As [`Client::get`]. A version that never existed is [`SdkError::NotFound`].
    pub fn get_version(
        &self,
        path: &SecretPath,
        version: SecretVersion,
    ) -> Result<Secret, SdkError> {
        self.read_secret(path, Some(version))
    }

    /// Write a value, creating a new version.
    ///
    /// Requires the `write` capability. Writing is included because the SDK is the
    /// client for the API and the API has the operation; the expected caller is not a
    /// service fetching its own secrets but a tool that provisions them.
    ///
    /// Leaves the rotation class alone — `unclassified` on a path that is new. Use
    /// [`Client::put_classified`] where the caller knows what the value is safe for.
    ///
    /// # Errors
    ///
    /// [`SdkError::BadRequest`] for a reserved path (`sys/**` cannot hold secrets), and
    /// see [`SdkError`].
    pub fn put(&self, path: &SecretPath, value: &Plaintext) -> Result<Written, SdkError> {
        self.write(path, value, None)
    }

    /// Write a value and record how safe it is to rotate, in one call.
    ///
    /// The method the migration of an existing estate wants. `ciphr rotation` needs the
    /// store lock and therefore the service stopped, so classifying an import through
    /// the CLI costs exactly the downtime this client exists to avoid; the class travels
    /// with the value instead. Requires `write` and nothing more — the class is metadata
    /// and reaches no authorization decision.
    ///
    /// A [`Rotation`] rather than a string, so a typo is a compile error rather than a
    /// `400` in the middle of a migration. The asymmetry with [`Classification::class`],
    /// which stays an open string on the way out, is deliberate: reading has to tolerate
    /// a class this build does not know, writing must never invent one.
    ///
    /// # Errors
    ///
    /// [`SdkError::BadRequest`] for a reserved path, or if the service does not know the
    /// class — which is also what a service older than the field looks like, except that
    /// it accepts the write and ignores the class in silence. Confirm with
    /// [`Client::versions`] once when migrating against a service you do not deploy.
    /// See [`SdkError`].
    pub fn put_classified(
        &self,
        path: &SecretPath,
        value: &Plaintext,
        rotation: Rotation,
    ) -> Result<Written, SdkError> {
        self.write(path, value, Some(rotation))
    }

    /// One request builder for both write methods.
    ///
    /// Not two, deliberately. In the CLI the same pair drifted — the standalone
    /// classification recorded what it did and the one folded into a write did not —
    /// and the fix there was also to funnel both through one function.
    fn write(
        &self,
        path: &SecretPath,
        value: &Plaintext,
        rotation: Option<Rotation>,
    ) -> Result<Written, SdkError> {
        // The body is built by hand rather than through `serde_json::to_string` on a
        // struct holding the value: this way the only owned copy of the plaintext in
        // this function is the one inside the body, and `serde_json` never holds a
        // second `String` of it.
        let text = core::str::from_utf8(value.expose()).map_err(|_| SdkError::BadRequest {
            detail: "the value is not valid UTF-8; the API carries values as text".to_owned(),
        })?;
        let body = match rotation {
            // Absent rather than `null`: the field means "unchanged" by being missing,
            // and a client that sends an explicit null for it is stating something the
            // API does not define.
            None => serde_json::json!({ "value": text }),
            Some(class) => serde_json::json!({ "value": text, "rotation": class.as_str() }),
        }
        .to_string();

        let url = self.url(&["secrets", path.as_str()], None);
        let response = self
            .agent
            .put(&url)
            .header("content-type", "application/json")
            .header("authorization", self.header())
            .send(body.as_bytes());

        let wire: WrittenWire = decode(response, path.as_str())?;
        Ok(Written {
            path: SecretPath::parse(&wire.path)?,
            version: parse_version(wire.version)?,
        })
    }

    /// Soft-delete the current version. Reversible.
    ///
    /// # Errors
    ///
    /// See [`SdkError`].
    pub fn delete(&self, path: &SecretPath) -> Result<(), SdkError> {
        let url = self.url(&["secrets", path.as_str()], None);
        let response = self
            .agent
            .delete(&url)
            .header("authorization", self.header())
            .call();

        // The body is not read for its content, only far enough to release the
        // connection back to the pool.
        status_only(response, path.as_str())
    }

    /// The version history of one secret, oldest first, without values.
    ///
    /// Requires the `list` capability on the path.
    ///
    /// # Errors
    ///
    /// See [`SdkError`].
    pub fn versions(&self, path: &SecretPath) -> Result<History, SdkError> {
        let url = self.url(&["versions", path.as_str()], None);
        let response = self
            .agent
            .get(&url)
            .header("authorization", self.header())
            .call();

        let wire: VersionsWire = decode(response, path.as_str())?;
        Ok(History {
            rotation: Classification {
                class: wire.rotation.class,
                needs_care: wire.rotation.needs_care,
                advice: wire.rotation.advice,
            },
            versions: wire
                .versions
                .into_iter()
                .map(|entry| {
                    Ok(VersionSummary {
                        version: parse_version(entry.version)?,
                        created_at: entry.created_at,
                        created_by: entry.created_by,
                        deleted: entry.deleted,
                        destroyed: entry.destroyed,
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?,
        })
    }

    /// The paths under a prefix that this identity may see.
    ///
    /// **An empty result is ambiguous by design.** Every path is authorized individually
    /// against `list`, so "you may list nothing here" and "there is nothing here" are the
    /// same empty array. This method reports it as it is; [`Client::environment`] refuses
    /// it, because a consumer asking for its own prefix is misconfigured either way.
    ///
    /// # Errors
    ///
    /// See [`SdkError`]. Note that an unauthorized *prefix* is not an error: the
    /// operation itself needs only authentication.
    pub fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SdkError> {
        let url = self.url(&["list", prefix.as_str()], None);
        let response = self
            .agent
            .get(&url)
            .header("authorization", self.header())
            .call();

        let wire: ListingWire = decode(response, prefix.as_str())?;
        wire.paths
            .iter()
            .map(|path| SecretPath::parse(path).map_err(SdkError::from))
            .collect()
    }

    /// Read several secrets in one call, named explicitly.
    ///
    /// Requires `read` on **every** path; the service refuses the whole call otherwise,
    /// and writes one audit entry per secret served rather than one per call — bulk
    /// retrieval is not a blind spot in the trail.
    ///
    /// Paths are named rather than taken from a prefix because an export is the operation
    /// most likely to hand over more than intended.
    ///
    /// # Errors
    ///
    /// See [`SdkError`]. An empty `paths` is [`SdkError::BadRequest`] from the service.
    pub fn export(&self, paths: &[SecretPath]) -> Result<Vec<Secret>, SdkError> {
        let requested: Vec<&str> = paths.iter().map(SecretPath::as_str).collect();
        let body = serde_json::json!({ "paths": requested }).to_string();

        let url = self.url(&["export"], None);
        let response = self
            .agent
            .post(&url)
            .header("content-type", "application/json")
            .header("authorization", self.header())
            .send(body.as_bytes());

        let wire: ExportWire = decode(response, "export")?;
        wire.secrets
            .into_iter()
            .map(|entry| {
                Ok(Secret {
                    path: SecretPath::parse(&entry.path)?,
                    version: parse_version(entry.version)?,
                    value: Plaintext::new(entry.value.into_bytes()),
                    // The export response carries no metadata beyond the version, so
                    // these are the honest values for "not reported" rather than
                    // invented ones.
                    created_at: 0,
                    created_by: String::new(),
                })
            })
            .collect()
    }

    /// Everything under a prefix, as an environment: route C, in one call site.
    ///
    /// Two requests, because the API has no "export a prefix" operation and deliberately
    /// so: `GET /v1/list` to learn the paths, `POST /v1/export` to read them. The
    /// identity therefore needs **`list` and `read`** under the prefix, which is more
    /// than [`Client::export`] needs — an identity holding only `read` must name its
    /// paths and use [`Client::environment_of`].
    ///
    /// Names come from [`EnvVarName`], so they are the same names `ciphr export` and
    /// `ciphr run` produce for the same paths (ADR-18), and a colliding or unusable set
    /// is refused rather than delivered.
    ///
    /// This does **not** set any environment variable. It cannot: modifying the process
    /// environment is `unsafe` in this edition and this crate forbids `unsafe_code`. What
    /// it hands back is the mapping, and the caller either reads from it directly — the
    /// better option, since the value then never enters `/proc/<pid>/environ` at all — or
    /// passes it to a child process with `Command::env`.
    ///
    /// # Errors
    ///
    /// [`SdkError::NothingUnderPrefix`] if the listing is empty, which is both "nothing
    /// there" and "no `list` capability here". [`SdkError::EnvName`] if the set has no
    /// usable names. Otherwise see [`SdkError`].
    pub fn environment(&self, prefix: &SecretPath) -> Result<Environment, SdkError> {
        let paths = self.list(prefix)?;
        if paths.is_empty() {
            return Err(SdkError::NothingUnderPrefix {
                prefix: prefix.as_str().to_owned(),
            });
        }

        self.environment_of(&paths)
    }

    /// The same mapping, for paths the caller names.
    ///
    /// Needs only `read`. Use this where the set of secrets a service consumes is known
    /// at build time, which is the stricter and better-audited arrangement: the request
    /// says what it wants instead of asking what exists.
    ///
    /// # Errors
    ///
    /// [`SdkError::EnvName`] if two paths want the same variable name or one of them is
    /// not a usable name. Otherwise see [`SdkError`].
    pub fn environment_of(&self, paths: &[SecretPath]) -> Result<Environment, SdkError> {
        // Names are assigned before the values are fetched, so a layout that cannot
        // produce an environment is refused without reading a single secret — and
        // without the audit entries that reading them would have written.
        EnvVarName::assign(paths)?;

        let secrets = self.export(paths)?;
        Environment::assemble(secrets)
    }

    /// What the service reports about itself. No authentication required, though this
    /// client sends its token anyway — the route ignores it.
    ///
    /// # Errors
    ///
    /// See [`SdkError`]. A reachable but sealed service answers `200` with
    /// [`Health::sealed`] set, which is the case an `HTTP 200` check alone misses.
    pub fn health(&self) -> Result<Health, SdkError> {
        let url = self.url(&["health"], None);
        let response = self.agent.get(&url).call();

        let wire: HealthWire = decode(response, "health")?;
        Ok(Health {
            status: wire.status,
            sealed: wire.sealed,
            seal: wire.seal,
            key_source: wire.key_source,
            audit_devices: wire
                .audit_devices
                .into_iter()
                .map(|device: DeviceHealthWire| DeviceHealth {
                    name: device.name,
                    accepting: device.accepting,
                })
                .collect(),
            api_version: wire.api_version,
        })
    }

    // -- the plumbing ------------------------------------------------------------------

    /// One secret, with or without an explicit version.
    fn read_secret(
        &self,
        path: &SecretPath,
        version: Option<SecretVersion>,
    ) -> Result<Secret, SdkError> {
        let url = self.url(&["secrets", path.as_str()], version);
        let response = self
            .agent
            .get(&url)
            .header("authorization", self.header())
            .call();

        let wire: SecretWire = decode(response, path.as_str())?;
        Ok(Secret {
            path: SecretPath::parse(&wire.path)?,
            version: parse_version(wire.version)?,
            value: Plaintext::new(wire.value.into_bytes()),
            created_at: wire.created_at,
            created_by: wire.created_by,
        })
    }

    /// The `Authorization` header value.
    ///
    /// The one place the token is exposed, and it is exposed as the whole header line
    /// rather than as the credential, so nothing here can accidentally log "the token"
    /// on its own.
    fn header(&self) -> &str {
        self.authorization.expose_secret()
    }

    /// Build a URL. Segments are already-normalized paths, which contain no character
    /// that needs escaping — `SecretPath` refuses everything outside letters, digits,
    /// `-`, `_`, `.` and the separator.
    fn url(&self, segments: &[&str], version: Option<SecretVersion>) -> String {
        let mut url = format!("{}/v1/{}", self.base, segments.join("/"));
        if let Some(version) = version {
            url.push_str("?version=");
            url.push_str(&version.get().to_string());
        }
        url
    }
}

/// Turn a transport result into either a deserialized body or an [`SdkError`].
///
/// A free function rather than a method: it needs nothing from the client, and keeping it
/// out of the impl block makes that checkable rather than a claim.
fn decode<T: serde::de::DeserializeOwned>(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    subject: &str,
) -> Result<T, SdkError> {
    let mut response = response.map_err(|error| transport_error(&error))?;
    let status = response.status().as_u16();
    let body = read_body(&mut response)?;

    if !(200..300).contains(&status) {
        return Err(status_error(status, &body, subject));
    }

    serde_json::from_str(&body).map_err(|error| SdkError::Unexpected {
        status: Some(status),
        // Only the *category*, never the parser's message and never the body. A `200`
        // body contains a secret, and `serde_json` quotes the offending token in a type
        // mismatch — so a parse failure must not be the thing that logs the value it
        // failed to parse.
        detail: format!(
            "the response is not the documented shape ({:?})",
            error.classify()
        ),
    })
}

/// The same, for a response whose body carries nothing the caller needs.
fn status_only(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    subject: &str,
) -> Result<(), SdkError> {
    let mut response = response.map_err(|error| transport_error(&error))?;
    let status = response.status().as_u16();
    let body = read_body(&mut response)?;

    if (200..300).contains(&status) {
        return Ok(());
    }
    Err(status_error(status, &body, subject))
}

/// Everything a [`Client`] needs, and the one thing it may be told.
///
/// No `Debug`: it holds a token.
pub struct ClientBuilder {
    base_url: String,
    token: SecretString,
    certificate_authority_pem: Vec<u8>,
    timeout: Duration,
}

impl ClientBuilder {
    /// How long one request may take in total. Ten seconds if not set.
    ///
    /// A total budget rather than a per-stage one: the caller is a container start
    /// waiting on this, and what it needs bounded is the wall clock, not the handshake.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// [`SdkError::Configuration`] if the base URL is not an `https` URL, or if the PEM
    /// contains no certificate. Both are refused here rather than at the first request:
    /// a client that cannot work should not exist, and a misconfiguration found at
    /// startup is a failed start instead of a failed fetch later.
    pub fn build(self) -> Result<Client, SdkError> {
        let base = normalize_base_url(&self.base_url)?;

        let authorities = read_authorities(&self.certificate_authority_pem)?;

        // The provider is passed explicitly rather than installed as the process
        // default. A library that installs a process-wide crypto provider makes a
        // decision on behalf of an application that may have made its own.
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(provider)
            .root_certs(ureq::tls::RootCerts::from(authorities))
            .build();

        let config = agent_config(tls, self.timeout);

        Ok(Client {
            agent: config.new_agent(),
            base,
            authorization: SecretString::from(format!("Bearer {}", self.token.expose_secret())),
        })
    }
}

/// The agent configuration, in one place so that a test can read the same one `build`
/// uses.
///
/// Extracted for exactly that reason: the two settings below are the client's transport
/// contract, and a test that rebuilt the chain itself could pass while this one drifted.
fn agent_config(tls: ureq::tls::TlsConfig, timeout: Duration) -> ureq::config::Config {
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(timeout))
        // Status codes are not errors here: a `403` body says which class of refusal
        // it is, and this client reads it rather than throwing it away.
        .http_status_as_error(false)
        // **No redirects**, and that is a transport decision rather than a preference.
        // Finding F7 of `docs/review-2026-08-21-current-tree.md`: the builder refused a
        // non-`https` base URL and installed only the deployment CA, and then followed
        // whatever redirect it was handed. `ureq` strips the authorization header across
        // those boundaries, so the token was never at risk — but a redirected plaintext
        // response substituted for a secret is an integrity failure, and a consumer that
        // fetches its own secrets at startup is the code path least likely to notice one.
        //
        // ADR-19 makes a point of what this client cannot do: built without
        // `webpki-roots`, so a client trusting the public CA set cannot be constructed at
        // all. Redirects were the one door left open in that story, and **this API has no
        // redirect contract** — so following one preserves nothing and can only turn a
        // configuration failure into a substituted value.
        //
        // Zero rather than "https only": there is nothing to keep working. A 3xx from this
        // service is a misconfiguration or an interception, and either way the caller
        // should see it rather than have it resolved on their behalf.
        .max_redirects(0)
        .build()
}

/// `https://host:port`, without a trailing slash.
///
/// # Errors
///
/// [`SdkError::Configuration`] for anything that is not `https`. Refusing `http` is not
/// pedantry: the payload is plaintext secrets, and the one scheme that protects it is
/// the one the service terminates itself (ADR-8).
fn normalize_base_url(input: &str) -> Result<String, SdkError> {
    let trimmed = input.trim_end_matches('/');

    if !trimmed.starts_with("https://") {
        return Err(SdkError::Configuration {
            detail: format!(
                "{input:?} is not an https URL; this client refuses plaintext transport for \
                 plaintext secrets"
            ),
        });
    }
    if trimmed.len() <= "https://".len() {
        return Err(SdkError::Configuration {
            detail: format!("{input:?} has no host"),
        });
    }

    Ok(trimmed.to_owned())
}

/// The certificates in a PEM bundle.
///
/// # Errors
///
/// [`SdkError::Configuration`] if the bundle contains no certificate. An empty trust
/// anchor is the one configuration mistake that would otherwise fail open somewhere else.
fn read_authorities(pem: &[u8]) -> Result<Vec<ureq::tls::Certificate<'static>>, SdkError> {
    let mut certificates = Vec::new();

    for item in ureq::tls::parse_pem(pem) {
        match item {
            Ok(ureq::tls::PemItem::Certificate(certificate)) => certificates.push(certificate),
            // A private key in what should be a CA bundle is a packaging mistake worth
            // naming, because the mistake it usually indicates is that the *service's*
            // key material was mounted here.
            Ok(ureq::tls::PemItem::PrivateKey(_)) => {
                return Err(SdkError::Configuration {
                    detail: "the certificate authority bundle contains a private key; a client \
                             needs the certificate only"
                        .to_owned(),
                });
            }
            Err(error) => {
                return Err(SdkError::Configuration {
                    detail: format!("the certificate authority bundle could not be read: {error}"),
                });
            }
            // `PemItem` is `#[non_exhaustive]`: a future kind is not a certificate, and
            // skipping it is what `parse_pem` documents for unrecognized sections.
            Ok(_) => {}
        }
    }

    if certificates.is_empty() {
        return Err(SdkError::Configuration {
            detail: "the certificate authority bundle contains no certificate".to_owned(),
        });
    }

    Ok(certificates)
}

/// Read a bounded amount of the body as text.
fn read_body(response: &mut ureq::http::Response<ureq::Body>) -> Result<String, SdkError> {
    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_string()
        .map_err(|error| SdkError::Unexpected {
            status: Some(response.status().as_u16()),
            detail: format!("the response body could not be read: {error}"),
        })
}

/// Map a transport failure. The message is ureq's, which names the cause without naming
/// a payload.
fn transport_error(error: &ureq::Error) -> SdkError {
    SdkError::Transport {
        detail: error.to_string(),
    }
}

/// Map a non-2xx response onto the variant a caller can act on.
///
/// The status decides, and the documented `error` code in the body confirms it. Where the
/// two disagree the status wins: it is the one the caller's own proxy or gateway would
/// also have produced, and a body claiming otherwise is not a reason to treat a `403` as
/// something else.
fn status_error(status: u16, body: &str, subject: &str) -> SdkError {
    let wire: Option<ErrorWire> = serde_json::from_str(body).ok();
    let detail = wire.as_ref().and_then(|error| error.detail.clone());

    match status {
        400 => SdkError::BadRequest {
            detail: detail.unwrap_or_else(|| "the service did not say why".to_owned()),
        },
        401 => SdkError::Unauthenticated,
        403 => SdkError::Forbidden {
            path: subject.to_owned(),
        },
        404 => SdkError::NotFound {
            path: subject.to_owned(),
        },
        503 => SdkError::AuditUnavailable,
        // A redirect, which `max_redirects(0)` turns into a response instead of a hop.
        // Named here rather than falling into `Unexpected`, which would report an "error
        // class" for a body that carries none -- and this is the one status where the
        // useful thing to tell an operator is what was *not* done.
        300..=399 => SdkError::Unexpected {
            status: Some(status),
            detail: "the service answered with a redirect, which was not followed: this \
                     API has no redirect contract, so a 3xx is a transport or \
                     configuration failure rather than a hop to take"
                .to_owned(),
        },
        other => SdkError::Unexpected {
            status: Some(other),
            detail: wire.map_or_else(
                || "no error body".to_owned(),
                |error| format!("error class {:?}", error.error),
            ),
        },
    }
}

/// A version from the wire, refusing zero.
fn parse_version(version: u32) -> Result<SecretVersion, SdkError> {
    SecretVersion::new(version).ok_or_else(|| SdkError::Unexpected {
        status: None,
        detail: "the service reported version 0, which does not exist".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{normalize_base_url, read_authorities, status_error};
    use crate::SdkError;

    /// Finding F7: the client used to follow redirects it had validated nothing about.
    ///
    /// Asserted on the configuration rather than against a redirecting server, and that is
    /// the stronger form here: at zero there is no code path that looks at the target, so
    /// "HTTPS to HTTP" and "same origin" are the same test — a redirect is not followed
    /// because redirects are not followed. A pair of behavioural tests would be asserting
    /// two branches of a decision nothing makes any more.
    ///
    /// Read from the same function `build` uses, so the two cannot drift.
    #[test]
    fn the_agent_follows_no_redirects() {
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .build();
        let config = super::agent_config(tls, std::time::Duration::from_secs(5));

        assert_eq!(config.max_redirects(), 0, "no redirect may be followed");
        // The other half of the transport contract, pinned in the same place: a `403` body
        // is read rather than thrown away as an error.
        assert!(!config.http_status_as_error());
    }

    #[test]
    fn a_redirect_says_it_was_not_followed() {
        // What arrives at `decode` once nothing follows the hop. `Unexpected` would report
        // an "error class" for a 3xx body that has none, and an operator reading that would
        // look for a broken response instead of a redirect they did not configure.
        for status in [301, 302, 307, 308] {
            let error = status_error(status, "", "infra/service-a/DB_PASSWORD");
            let SdkError::Unexpected { detail, .. } = &error else {
                panic!("a {status} has to be reported as unexpected, got {error:?}");
            };
            assert!(
                detail.contains("redirect"),
                "the message has to name what happened, got {detail:?}"
            );
        }
    }
    #[test]
    fn plaintext_transport_is_refused_at_construction() {
        // Not a preference: the payload is plaintext secrets.
        for input in ["http://localhost:4400", "localhost:4400", "ftp://host"] {
            assert!(
                matches!(
                    normalize_base_url(input),
                    Err(SdkError::Configuration { .. })
                ),
                "{input} was accepted"
            );
        }
    }

    #[test]
    fn a_trailing_slash_is_not_a_different_service() {
        assert_eq!(
            normalize_base_url("https://localhost:4400/").expect("valid"),
            "https://localhost:4400"
        );
        assert_eq!(
            normalize_base_url("https://localhost:4400").expect("valid"),
            "https://localhost:4400"
        );
    }

    #[test]
    fn a_scheme_without_a_host_is_refused() {
        assert!(matches!(
            normalize_base_url("https://"),
            Err(SdkError::Configuration { .. })
        ));
    }

    #[test]
    fn an_empty_trust_anchor_is_refused_rather_than_ignored() {
        // The mistake this catches: a mounted file that is present and empty, which
        // would otherwise become "trusts nothing" and fail as a handshake error much
        // later, or "trusts the platform" in a client that allowed that.
        assert!(matches!(
            read_authorities(b""),
            Err(SdkError::Configuration { .. })
        ));
        assert!(matches!(
            read_authorities(b"not a pem file at all\n"),
            Err(SdkError::Configuration { .. })
        ));
    }

    #[test]
    fn a_private_key_in_the_ca_bundle_is_named_as_such() {
        // The realistic version of this mistake is mounting the service's own key
        // material where the CA certificate belongs.
        let pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHt1c3RhbmRvbWtleWJ5dGVzZm9ydGVzdGluZ29ubHk=\n-----END PRIVATE KEY-----\n";
        let error = read_authorities(pem).expect_err("must be refused");
        let SdkError::Configuration { detail } = error else {
            panic!("expected a configuration error");
        };
        assert!(detail.contains("private key"), "{detail}");
    }

    #[test]
    fn the_status_decides_which_error_a_caller_sees() {
        let body = r#"{"error":"forbidden","message":"not permitted"}"#;
        assert!(matches!(
            status_error(403, body, "infra/a/DB_PASSWORD"),
            SdkError::Forbidden { .. }
        ));
        assert!(matches!(
            status_error(401, body, "infra/a/DB_PASSWORD"),
            SdkError::Unauthenticated
        ));
        assert!(matches!(
            status_error(503, body, "infra/a/DB_PASSWORD"),
            SdkError::AuditUnavailable
        ));

        // A body that disagrees with the status does not get to reclassify it.
        let lying = r#"{"error":"not_found","message":"no"}"#;
        assert!(matches!(
            status_error(403, lying, "infra/a/DB_PASSWORD"),
            SdkError::Forbidden { .. }
        ));

        // And no body at all is still a usable error.
        assert!(matches!(
            status_error(500, "", "infra/a/DB_PASSWORD"),
            SdkError::Unexpected { .. }
        ));
    }

    #[test]
    fn a_bad_request_carries_the_detail_the_service_gave() {
        let body = r#"{"error":"bad_request","message":"refused","detail":"'sys/' is reserved"}"#;
        let SdkError::BadRequest { detail } = status_error(400, body, "sys/audit") else {
            panic!("expected a bad request");
        };
        assert!(detail.contains("reserved"), "{detail}");
    }
}
