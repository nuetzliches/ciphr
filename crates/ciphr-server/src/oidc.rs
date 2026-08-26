//! OIDC federation: exchanging a provider-issued ID token for a ciphr token.
//!
//! ADR-6 named this as the one authentication method that would follow the bearer
//! token, and `openapi.yaml` has reserved `POST /v1/auth/oidc/login` for it since
//! phase 3. This module is the half that decides: given a presented ID token, does a
//! configured provider vouch for it, and does a configured binding name an identity
//! for the claims it carries. Minting the ciphr token afterwards is
//! [`crate::api`]'s job, because that is where the store and the audit trail are.
//!
//! # What this module deliberately does not do
//!
//! **It makes no network call, and the keys are configuration.** A JWKS fetch would be
//! the first outbound request from the process that holds plaintext secrets, and ADR-17
//! rejected exactly that position for the ACME client: *"an ACME client puts outbound
//! internet access, an account key, and a writable certificate path into the process
//! that holds plaintext secrets — ADR-8 exists to remove positions like that, not to
//! add one."* It could not be built here even if it were wanted: `ureq` and `rustls` in
//! this workspace link no public root certificates on purpose (ADR-19), so a client that
//! trusts the `WebPKI` cannot be constructed at all.
//!
//! So a provider's signing keys are written into the configuration file, beside the
//! policies, in version control — which is where ADR-3 puts everything else that
//! decides who may read what. The cost is real and belongs next to the feature: when a
//! provider rotates its signing key, federation stops working until an operator copies
//! the new one in. It stops **closed** — the exchange is refused, and every token
//! already issued and every bootstrap credential keeps working —
//! and `docs/operations/federation.md` says how to see it coming.
//!
//! **It matches claims by equality, and there is no wildcard.** Plan section 14
//! sketched glob bindings using "the same code as the policy evaluator", and that
//! sketch does not survive contact with the code it names. [`ciphr_core::pattern`]
//! rejects a partial wildcard by design, so the plan's own example
//! (`repo:acme/*:ref:refs/heads/main`) does not parse; and a claim value is not a path
//! — `/` is a segment separator there and an ordinary character in a `sub`. Reusing the
//! path matcher would be a category error, and writing a second matcher is the thing
//! the plan was right to forbid. Exact equality needs no matcher at all, and a
//! deployment that federates many branches lists them, in a file that has a diff and a
//! reviewer.
//!
//! # Two algorithms, and why the header does not choose
//!
//! `RS256` and `ES256`, verified with `ring` — which is already in this graph because
//! `rustls` uses it, so this adds a direct dependency and no new code. Nothing else is
//! accepted, `none` least of all.
//!
//! **The configured key decides the algorithm, and the token's header only has to
//! agree.** A verifier that reads `alg` from the header and then looks for a key is the
//! shape every algorithm-confusion attack is written against. Here the key is found by
//! `kid` among the keys a deployment wrote down, and a header naming a different
//! algorithm than that key is refused rather than accommodated.

use std::collections::BTreeMap;

use ciphr_core::base64url;
use serde::Deserialize;

use crate::error::ConfigError;

/// The surface entry that makes federation reachable (ADR-20).
///
/// Named here rather than spelled out at each use, because `config.rs` checks the
/// entry against the providers and `api.rs` checks it before registering the route.
pub const SURFACE_ENTRY: &str = "oidc_login";

/// The most bytes a presented ID token may have.
///
/// A provider's token is a few hundred bytes; eight kibibytes is room for an unusually
/// generous claim set and still a bound. The body extractor bounds the request too, and
/// this bounds the field inside it — base64-decoding an arbitrary caller-supplied string
/// before anything has been verified is work worth capping.
const MAX_ID_TOKEN_LEN: usize = 8 * 1024;

/// The shortest RSA modulus this accepts, in bytes: 2048 bits.
///
/// `ring` enforces the same floor at verification time. Checked here as well so a
/// deployment learns at startup rather than at the first exchange.
const MIN_RSA_MODULUS_LEN: usize = 256;

/// Claim names a binding may not select on.
///
/// Every one of them is *verified* rather than matched: `iss` picks the provider, `aud`
/// is compared against the configured audience, and the three times decide validity. A
/// binding that also matched on one would express the same rule twice, in a place where
/// the two spellings could disagree.
const VERIFIED_CLAIMS: &[&str] = &["iss", "aud", "exp", "nbf", "iat"];

/// One `[[auth.oidc]]` stanza, as written in the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// A short label for this provider, used in the audit trail and in refusals.
    pub name: String,
    /// The issuer, compared byte for byte against the `iss` claim.
    ///
    /// Not normalized: a trailing slash is part of what a provider issues, and
    /// two spellings of one issuer is exactly the ambiguity this compares away.
    pub issuer: String,
    /// The audience, compared exactly against `aud`. Mandatory.
    ///
    /// A token issued for a third-party service must not be valid here. That is the
    /// confused-deputy case, and it is the reason there is no default.
    pub audience: String,
    /// How much clock difference to tolerate, in seconds.
    #[serde(default = "default_skew_seconds")]
    pub skew_seconds: u32,
    /// The lifetime of the token an exchange hands back, as `15m`, `900s`, `1h`.
    ///
    /// A ceiling as well as a default: a caller may ask for less and never for more.
    #[serde(default = "default_ttl")]
    pub ttl: String,
    /// The provider's signing keys. At least one.
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyConfig>,
    /// Which claims name which identity. At least one.
    #[serde(default, rename = "binding")]
    pub bindings: Vec<BindingConfig>,
}

fn default_skew_seconds() -> u32 {
    60
}

fn default_ttl() -> String {
    "15m".to_owned()
}

/// One `[[auth.oidc.key]]` stanza.
///
/// Tagged by `alg`, like `[seal]` and `[[audit]]`, so a deployment cannot write a key
/// whose algorithm is inferred from its fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "alg")]
pub enum KeyConfig {
    /// RSASSA-PKCS1-v1_5 with SHA-256, as `n` and `e` from the provider's JWKS.
    #[serde(rename = "RS256")]
    Rs256 {
        /// The key identifier, matched against the token header's `kid`.
        kid: String,
        /// The modulus, unpadded base64url.
        n: String,
        /// The public exponent, unpadded base64url.
        e: String,
    },
    /// ECDSA on P-256 with SHA-256, as `x` and `y` from the provider's JWKS.
    #[serde(rename = "ES256")]
    Es256 {
        /// The key identifier, matched against the token header's `kid`.
        kid: String,
        /// The affine x coordinate, unpadded base64url.
        x: String,
        /// The affine y coordinate, unpadded base64url.
        y: String,
    },
}

/// One `[[auth.oidc.binding]]` stanza.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingConfig {
    /// The identity this binding names. It must exist in the policy file.
    pub identity: String,
    /// The claims that have to match, all of them, by exact string equality.
    pub claims: BTreeMap<String, String>,
}

/// Every configured provider, resolved and checked.
///
/// Empty is the ordinary case: federation is a surface entry, and a deployment that
/// does not name it has no providers to resolve.
#[derive(Debug, Default)]
pub struct Federation {
    providers: Vec<Provider>,
}

/// One provider, ready to verify against.
#[derive(Debug)]
struct Provider {
    name: String,
    issuer: String,
    audience: String,
    skew_ms: i64,
    ttl_ms: i64,
    keys: Vec<Key>,
    bindings: Vec<Binding>,
}

/// One signing key, decoded.
#[derive(Debug)]
enum Key {
    Rs256 {
        kid: String,
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Es256 {
        kid: String,
        /// The uncompressed point, `0x04 || x || y`, which is what `ring` verifies with.
        point: Vec<u8>,
    },
}

impl Key {
    const fn kid(&self) -> &String {
        match self {
            Self::Rs256 { kid, .. } | Self::Es256 { kid, .. } => kid,
        }
    }

    /// The name of the algorithm this key is for, as it appears in a token header.
    const fn algorithm(&self) -> &'static str {
        match self {
            Self::Rs256 { .. } => "RS256",
            Self::Es256 { .. } => "ES256",
        }
    }

    /// Whether this key signed `message`.
    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Rs256 {
                modulus, exponent, ..
            } => ring::signature::RsaPublicKeyComponents {
                n: modulus.as_slice(),
                e: exponent.as_slice(),
            }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signature,
            )
            .is_ok(),
            Self::Es256 { point, .. } => ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                point.as_slice(),
            )
            .verify(message, signature)
            .is_ok(),
        }
    }
}

/// One claim-set-to-identity binding.
#[derive(Debug)]
struct Binding {
    identity: String,
    claims: BTreeMap<String, String>,
}

impl Federation {
    /// Check every `[[auth.oidc]]` stanza and decode its keys.
    ///
    /// Everything that can be wrong with a provider is wrong here, at startup, with
    /// nothing waiting on it — the same reason the audit device and the surface stanzas
    /// are checked before the listener binds.
    ///
    /// # Errors
    ///
    /// Returns the [`ConfigError`] naming the first stanza that cannot be used.
    pub fn resolve(configs: &[ProviderConfig]) -> Result<Self, ConfigError> {
        let mut providers = Vec::with_capacity(configs.len());

        for config in configs {
            let name = config.name.trim();
            if name.is_empty() {
                return Err(ConfigError::OidcName);
            }
            if config.issuer.trim().is_empty() {
                return Err(ConfigError::OidcIssuer {
                    name: name.to_owned(),
                });
            }
            // Mandatory, and the one field with no defensible default: a token issued
            // for somebody else's service must not be valid here.
            if config.audience.trim().is_empty() {
                return Err(ConfigError::OidcAudience {
                    name: name.to_owned(),
                });
            }
            if configs
                .iter()
                .filter(|other| other.issuer == config.issuer && other.audience == config.audience)
                .count()
                > 1
            {
                return Err(ConfigError::OidcDuplicateProvider {
                    issuer: config.issuer.clone(),
                    audience: config.audience.clone(),
                });
            }

            let ttl_ms =
                parse_duration_millis(&config.ttl).ok_or_else(|| ConfigError::OidcTtl {
                    name: name.to_owned(),
                    found: config.ttl.clone(),
                })?;

            let keys = resolve_keys(name, &config.keys)?;
            let bindings = resolve_bindings(name, &config.bindings)?;

            providers.push(Provider {
                name: name.to_owned(),
                issuer: config.issuer.clone(),
                audience: config.audience.clone(),
                skew_ms: i64::from(config.skew_seconds) * 1000,
                ttl_ms,
                keys,
                bindings,
            });
        }

        Ok(Self { providers })
    }

    /// Whether any provider is configured.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// The provider names, for the `--check-config` report.
    pub fn names(&self) -> Vec<&str> {
        self.providers
            .iter()
            .map(|provider| provider.name.as_str())
            .collect()
    }

    /// Every identity a binding names, for the reachability check.
    ///
    /// A binding that names an identity the policy file does not have can never
    /// produce a usable token, and the check that says so belongs where the policy set
    /// is — not here.
    pub fn bound_identities(&self) -> Vec<&str> {
        self.providers
            .iter()
            .flat_map(|provider| provider.bindings.iter())
            .map(|binding| binding.identity.as_str())
            .collect()
    }

    /// Examine a presented ID token.
    ///
    /// `now_ms` is milliseconds since the Unix epoch, so a test can decide what "now"
    /// is rather than waiting for it.
    ///
    /// The return value distinguishes four rejections and does not collapse them into
    /// one — see [`Exchange`] for which of them reach the audit trail and why the rest
    /// deliberately do not.
    pub fn exchange(&self, presented: &str, now_ms: i64) -> Exchange {
        if presented.is_empty() || presented.len() > MAX_ID_TOKEN_LEN {
            return Exchange::Unverifiable(Unverifiable::Malformed);
        }

        let Some((header, payload, signed, signature)) = split(presented) else {
            return Exchange::Unverifiable(Unverifiable::Malformed);
        };

        let Some(algorithm) = string_claim(&header, "alg") else {
            return Exchange::Unverifiable(Unverifiable::Malformed);
        };
        let kid = string_claim(&header, "kid");

        let Some(issuer) = string_claim(&payload, "iss") else {
            return Exchange::Unverifiable(Unverifiable::Malformed);
        };

        // The issuer selects the candidates; the key selects the algorithm. A header
        // that names an algorithm the chosen key is not for is refused, never
        // accommodated.
        let mut saw_issuer = false;
        let mut saw_candidate_key = false;
        let mut verified: Option<&Provider> = None;
        for provider in self
            .providers
            .iter()
            .filter(|provider| provider.issuer == issuer)
        {
            saw_issuer = true;
            for key in provider
                .keys
                .iter()
                .filter(|key| kid.as_deref().is_none_or(|kid| key.kid() == kid))
                .filter(|key| key.algorithm() == algorithm)
            {
                saw_candidate_key = true;
                if key.verifies(signed.as_bytes(), &signature) {
                    verified = Some(provider);
                    break;
                }
            }
            if verified.is_some() {
                break;
            }
        }

        let Some(provider) = verified else {
            return Exchange::Unverifiable(if saw_candidate_key {
                Unverifiable::Signature
            } else if saw_issuer {
                Unverifiable::UnknownKey
            } else {
                Unverifiable::UnknownIssuer
            });
        };

        // Everything from here on is recorded: a provider this deployment trusts has
        // signed for the claims below, so the caller is not anonymous any more.
        //
        // **The subject is read now and required at the end**, so every refusal below
        // can name the workload it was about. Requiring it here instead would report a
        // token that is also expired and also for another audience as *"no sub"*, which
        // is the least useful of the three things wrong with it.
        let subject = string_claim(&payload, "sub");

        let Some(expiry) = seconds_claim(&payload, "exp") else {
            return provider.refuse(subject, Refusal::MissingExpiry);
        };
        if now_ms > expiry.saturating_add(provider.skew_ms) {
            return provider.refuse(subject, Refusal::Expired);
        }
        if let Some(not_before) = seconds_claim(&payload, "nbf")
            && now_ms < not_before.saturating_sub(provider.skew_ms)
        {
            return provider.refuse(subject, Refusal::NotYetValid);
        }

        if !audience_matches(&payload, &provider.audience) {
            return provider.refuse(subject, Refusal::Audience);
        }

        // Required from here: it is what the binding resolves and what the entry names.
        let Some(subject) = subject else {
            return provider.refuse(None, Refusal::MissingSubject);
        };

        let mut matched = provider
            .bindings
            .iter()
            .filter(|binding| binding.matches(&payload));
        let Some(binding) = matched.next() else {
            return provider.refuse(Some(subject), Refusal::NoBinding);
        };
        // **Two bindings matching one token is a refusal, not a choice.** Identical
        // claim sets are refused at startup, but two bindings selecting on different
        // claim names can both match a token that carries all of them, and there is no
        // honest way to pick. Ordering would make the answer depend on the order of
        // lines in a file, which is not a property a deployment should have to know
        // about the thing that decides which identity a job gets.
        if matched.next().is_some() {
            return provider.refuse(Some(subject), Refusal::AmbiguousBinding);
        }

        Exchange::Accepted(Accepted {
            provider: provider.name.clone(),
            subject,
            identity: binding.identity.clone(),
            ttl_ms: provider.ttl_ms,
        })
    }
}

impl Provider {
    fn refuse(&self, subject: Option<String>, reason: Refusal) -> Exchange {
        Exchange::Refused {
            provider: self.name.clone(),
            subject,
            reason,
        }
    }
}

impl Binding {
    fn matches(&self, payload: &serde_json::Map<String, serde_json::Value>) -> bool {
        self.claims.iter().all(|(name, expected)| {
            payload.get(name).and_then(serde_json::Value::as_str) == Some(expected.as_str())
        })
    }
}

/// What examining a presented ID token concluded.
///
/// **The split between [`Exchange::Unverifiable`] and the other two is where the audit
/// trail begins, and it is a decision rather than a convenience.** This route is
/// unauthenticated, so a recorded entry per attempt would be an anonymous write into a
/// fail-closed trail: fill it, or make one device refuse, and every request afterwards
/// is a `503`. The router fallback and [`crate::api::AuditedJson`] already answer that
/// question the same way — *"an anonymous caller still writes nothing … letting anybody
/// write to it by posting garbage would turn a `400` into an outage"* — and ADR-16
/// deferred a whole phase over the same cost.
///
/// A signature that verifies is what changes the answer. From that point the caller
/// demonstrably holds a token a provider this deployment trusts issued, which is not
/// anonymous, and ADR-22's rule applies in the ordinary way: the entry names the
/// identity it resolved to, or the reason it was refused. What is lost is that a
/// forged or unknown-issuer token leaves no line, and
/// `docs/operations/federation.md` says so rather than letting a reader assume
/// otherwise.
#[derive(Debug)]
pub enum Exchange {
    /// Nothing vouched for this token. Refused, and deliberately not recorded.
    Unverifiable(Unverifiable),
    /// A configured provider signed it, and it was refused anyway.
    Refused {
        /// Which provider's key verified the signature.
        provider: String,
        /// The verified `sub`, where the token carried one.
        subject: Option<String>,
        /// Why it was refused.
        reason: Refusal,
    },
    /// A configured provider signed it and exactly one binding named an identity.
    Accepted(Accepted),
}

/// A verified exchange: which identity, for how long, on whose word.
#[derive(Debug)]
pub struct Accepted {
    /// Which provider vouched.
    pub provider: String,
    /// The verified `sub` claim, which goes into the audit entry beside the identity.
    pub subject: String,
    /// The identity the binding named.
    pub identity: String,
    /// The provider's configured lifetime, in milliseconds. A ceiling, not only a
    /// default.
    pub ttl_ms: i64,
}

/// Why a presented token was not verifiable, and therefore not recorded.
///
/// Kept apart from [`Refusal`] by exactly one property: anybody can produce any of
/// these without holding anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unverifiable {
    /// Not three base64url parts with JSON in the first two, or larger than the cap.
    Malformed,
    /// No configured provider issues under this `iss`.
    UnknownIssuer,
    /// No configured key for that issuer matches this `kid` and algorithm.
    UnknownKey,
    /// A key matched and did not sign this token.
    Signature,
}

impl Unverifiable {
    /// A short, stable label. Not sent to a client: a `401` here says nothing, like
    /// every other `401` this API answers.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownIssuer => "unknown-issuer",
            Self::UnknownKey => "unknown-key",
            Self::Signature => "signature",
        }
    }
}

/// Why a verified token was refused. These are the ones the trail carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No `sub`, so there is nothing to record and nothing to bind.
    MissingSubject,
    /// No `exp`. A token without an expiry is not a short-lived credential.
    MissingExpiry,
    /// `exp` is in the past, beyond the tolerated skew.
    Expired,
    /// `nbf` is in the future, beyond the tolerated skew.
    NotYetValid,
    /// `aud` does not contain the configured audience.
    Audience,
    /// No binding matches the claims.
    NoBinding,
    /// More than one binding matches, so which identity was meant is unanswerable.
    AmbiguousBinding,
}

impl Refusal {
    /// The label the audit entry carries as its deny reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingSubject => "missing-subject",
            Self::MissingExpiry => "missing-expiry",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
            Self::Audience => "audience-mismatch",
            Self::NoBinding => "no-binding",
            Self::AmbiguousBinding => "ambiguous-binding",
        }
    }
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

fn resolve_keys(name: &str, configs: &[KeyConfig]) -> Result<Vec<Key>, ConfigError> {
    if configs.is_empty() {
        return Err(ConfigError::OidcNoKeys {
            name: name.to_owned(),
        });
    }

    let mut keys = Vec::with_capacity(configs.len());
    for config in configs {
        let key = match config {
            KeyConfig::Rs256 { kid, n, e } => {
                let modulus = decode_key_field(name, kid, "n", n)?;
                let exponent = decode_key_field(name, kid, "e", e)?;
                if modulus.len() < MIN_RSA_MODULUS_LEN {
                    return Err(ConfigError::OidcKeySize {
                        name: name.to_owned(),
                        kid: kid.clone(),
                        bits: modulus.len() * 8,
                    });
                }
                Key::Rs256 {
                    kid: kid.clone(),
                    modulus,
                    exponent,
                }
            }
            KeyConfig::Es256 { kid, x, y } => {
                let x = decode_key_field(name, kid, "x", x)?;
                let y = decode_key_field(name, kid, "y", y)?;
                // P-256 coordinates are 32 bytes each, and the uncompressed point
                // `ring` verifies with is `0x04 || x || y`. A short coordinate is a
                // left-stripped one, which would make a valid key fail at the first
                // exchange rather than here.
                if x.len() != 32 || y.len() != 32 {
                    return Err(ConfigError::OidcKeySize {
                        name: name.to_owned(),
                        kid: kid.clone(),
                        bits: x.len().max(y.len()) * 8,
                    });
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Key::Es256 {
                    kid: kid.clone(),
                    point,
                }
            }
        };

        if keys.iter().any(|other: &Key| other.kid() == key.kid()) {
            return Err(ConfigError::OidcDuplicateKey {
                name: name.to_owned(),
                kid: key.kid().clone(),
            });
        }
        keys.push(key);
    }

    Ok(keys)
}

fn decode_key_field(
    name: &str,
    kid: &str,
    field: &'static str,
    value: &str,
) -> Result<Vec<u8>, ConfigError> {
    base64url::decode(value).map_err(|_| ConfigError::OidcKeyEncoding {
        name: name.to_owned(),
        kid: kid.to_owned(),
        field,
    })
}

fn resolve_bindings(name: &str, configs: &[BindingConfig]) -> Result<Vec<Binding>, ConfigError> {
    if configs.is_empty() {
        return Err(ConfigError::OidcNoBindings {
            name: name.to_owned(),
        });
    }

    let mut bindings: Vec<Binding> = Vec::with_capacity(configs.len());
    for config in configs {
        if config.identity.trim().is_empty() {
            return Err(ConfigError::OidcBindingIdentity {
                name: name.to_owned(),
            });
        }
        if config.claims.is_empty() {
            return Err(ConfigError::OidcBindingNoClaims {
                name: name.to_owned(),
                identity: config.identity.clone(),
            });
        }
        for claim in config.claims.keys() {
            if VERIFIED_CLAIMS.contains(&claim.as_str()) {
                return Err(ConfigError::OidcBindingVerifiedClaim {
                    name: name.to_owned(),
                    claim: claim.clone(),
                });
            }
        }
        if bindings.iter().any(|other| other.claims == config.claims) {
            return Err(ConfigError::OidcDuplicateBinding {
                name: name.to_owned(),
            });
        }
        bindings.push(Binding {
            identity: config.identity.clone(),
            claims: config.claims.clone(),
        });
    }

    Ok(bindings)
}

/// Parse `15m`, `900s`, `1h`.
///
/// The same language as `ciphr token issue --ttl`, down to refusing a bare number, and
/// deliberately a second small parser rather than a shared one: the CLI's lives in
/// `ciphr-cli`, and the only crate both could reach is `ciphr-core` — the crate an
/// external review read line by line, where a duration parser has no business being.
/// Neither parser decides access, and both refuse everything they do not understand.
fn parse_duration_millis(input: &str) -> Option<i64> {
    let text = input.trim();
    let (digits, unit_millis) = match text.chars().last()? {
        'd' => (&text[..text.len() - 1], 24 * 60 * 60 * 1000),
        'h' => (&text[..text.len() - 1], 60 * 60 * 1000),
        'm' => (&text[..text.len() - 1], 60 * 1000),
        's' => (&text[..text.len() - 1], 1000),
        // A bare number is refused rather than assumed to be seconds, for the reason
        // `ciphr token issue` refuses it: "900" meaning seconds when minutes were
        // meant is a credential that expires mid-deploy.
        _ => return None,
    };

    digits
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .and_then(|value| value.checked_mul(unit_millis))
}

// ---------------------------------------------------------------------------
// Token parsing
// ---------------------------------------------------------------------------

type Claims = serde_json::Map<String, serde_json::Value>;

/// Split a compact JWS into its header, payload, signed input and signature.
///
/// Returns `None` for anything that is not three base64url parts with a JSON object in
/// the first two. The signed input is returned as a borrowed `&str` of the original,
/// because that — and not a re-encoding of the decoded parts — is what a signature
/// covers.
fn split(presented: &str) -> Option<(Claims, Claims, &str, Vec<u8>)> {
    let mut parts = presented.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let signed_len = header.len() + 1 + payload.len();
    let signed = presented.get(..signed_len)?;

    let header = json_object(header)?;
    let payload = json_object(payload)?;
    let signature = base64url::decode(signature).ok()?;

    Some((header, payload, signed, signature))
}

fn json_object(part: &str) -> Option<Claims> {
    let bytes = base64url::decode(part).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn string_claim(claims: &Claims, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// A time claim, in seconds, as milliseconds.
///
/// `None` for a missing claim and for one that is not a whole number of seconds — a
/// float or a string there is a token this does not understand, and guessing is not
/// what a verifier does.
fn seconds_claim(claims: &Claims, name: &str) -> Option<i64> {
    claims
        .get(name)?
        .as_i64()
        .and_then(|seconds| seconds.checked_mul(1000))
}

/// Whether `aud` contains the configured audience.
///
/// `aud` is a string or an array of strings, and both spellings mean the same thing.
/// Compared by equality either way: a prefix or suffix match here is how a token for
/// `ciphr-staging` becomes valid for `ciphr`.
fn audience_matches(claims: &Claims, expected: &str) -> bool {
    match claims.get("aud") {
        Some(serde_json::Value::String(one)) => one == expected,
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|one| one == expected),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Exchange, Federation, ProviderConfig, Refusal, Unverifiable, parse_duration_millis,
    };
    use ciphr_core::base64url;

    /// RFC 7515 appendix A.2: an RS256 JWS with its public key, from the standard.
    ///
    /// A known-answer test for the verification path, and the only honest way to have
    /// one here. `ring` cannot generate an RSA key, and a checked-in private key is
    /// test fixture material that looks like real key material -- the one thing
    /// `AGENTS.md` rules out, and the reason `rcgen` generates the TLS material for
    /// the end-to-end tests instead. What is checked in is a public modulus and a
    /// signature, both printed in a public standards document.
    const RFC7515_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\
                             HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\
                             D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\
                             SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\
                             MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\
                             NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const RFC7515_E: &str = "AQAB";
    const RFC7515_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    fn provider(keys: &str, bindings: &str) -> Vec<ProviderConfig> {
        let text = format!(
            "[[oidc]]\nname = \"forge\"\nissuer = \"joe\"\naudience = \"ciphr\"\n{keys}\n{bindings}\n"
        );
        toml::from_str::<Wrapper>(&text)
            .expect("the fixture is valid TOML")
            .oidc
    }

    /// What a `[[auth.oidc]]` array looks like once it is one level shallower.
    #[derive(serde::Deserialize)]
    struct Wrapper {
        oidc: Vec<ProviderConfig>,
    }

    fn rfc7515_key() -> String {
        format!(
            "[[oidc.key]]\nalg = \"RS256\"\nkid = \"a\"\nn = \"{RFC7515_N}\"\ne = \"{RFC7515_E}\"\n"
        )
    }

    const JOE_BINDING: &str =
        "[[oidc.binding]]\nidentity = \"ci-widget\"\nclaims = { sub = \"joe\" }\n";

    /// The verification itself, against a vector from the standard.
    ///
    /// The RFC's payload has no `aud` and no `sub`, so the token cannot be accepted --
    /// and the refusal it earns is the proof that verification succeeded. An
    /// unverifiable token never reaches a `Refused`.
    #[test]
    fn an_rs256_signature_from_the_standard_verifies() {
        let federation =
            Federation::resolve(&provider(&rfc7515_key(), JOE_BINDING)).expect("resolves");

        // Before the RFC's `exp` of 1300819380 seconds, so expiry is not what refuses it.
        let outcome = federation.exchange(RFC7515_TOKEN, 1_300_000_000_000);
        match outcome {
            Exchange::Refused {
                provider, reason, ..
            } => {
                assert_eq!(provider, "forge");
                assert_eq!(
                    reason,
                    Refusal::Audience,
                    "the RFC's payload carries no aud, and that is the first thing missing"
                );
            }
            other => panic!("the signature must verify: {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let federation =
            Federation::resolve(&provider(&rfc7515_key(), JOE_BINDING)).expect("resolves");

        // One character of the signature, changed. Everything else is the RFC's token.
        let (body, signature) = RFC7515_TOKEN.rsplit_once('.').expect("three parts");
        let flipped = signature
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index == 0 && character != 'd' {
                    'd'
                } else if index == 0 {
                    'e'
                } else {
                    character
                }
            })
            .collect::<String>();

        assert!(matches!(
            federation.exchange(&format!("{body}.{flipped}"), 1_300_000_000_000),
            Exchange::Unverifiable(Unverifiable::Signature)
        ));
    }

    #[test]
    fn an_expired_token_is_refused_after_it_verified() {
        let federation =
            Federation::resolve(&provider(&rfc7515_key(), JOE_BINDING)).expect("resolves");

        // Well past the RFC's `exp`.
        assert!(matches!(
            federation.exchange(RFC7515_TOKEN, 1_800_000_000_000),
            Exchange::Refused {
                reason: Refusal::Expired,
                ..
            }
        ));
    }

    /// The whole accept path, on a token signed during the test.
    ///
    /// ES256 rather than RS256 because `ring` can generate a P-256 key and cannot
    /// generate an RSA one -- so this needs no key material in the repository.
    #[test]
    fn a_signed_token_is_exchanged_for_the_identity_its_claims_name() {
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &random,
        )
        .expect("a P-256 key");
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &random,
        )
        .expect("the key parses");

        // `0x04 || x || y`, which is what a JWK's x and y are the halves of.
        let point = ring::signature::KeyPair::public_key(&pair)
            .as_ref()
            .to_vec();
        assert_eq!(point.len(), 65, "an uncompressed P-256 point");
        let x = base64url::encode(&point[1..33]);
        let y = base64url::encode(&point[33..65]);

        let header = base64url::encode(br#"{"alg":"ES256","kid":"k1"}"#);
        let payload = base64url::encode(
            br#"{"iss":"joe","aud":"ciphr","sub":"repo:acme/widget:ref:refs/heads/main","exp":2000000000,"repository":"acme/widget"}"#,
        );
        let signed = format!("{header}.{payload}");
        let signature = pair
            .sign(&random, signed.as_bytes())
            .expect("signing succeeds");
        let token = format!("{signed}.{}", base64url::encode(signature.as_ref()));

        let keys =
            format!("[[oidc.key]]\nalg = \"ES256\"\nkid = \"k1\"\nx = \"{x}\"\ny = \"{y}\"\n");
        let bindings = "[[oidc.binding]]\nidentity = \"ci-widget\"\nclaims = { sub = \"repo:acme/widget:ref:refs/heads/main\", repository = \"acme/widget\" }\n";
        let federation = Federation::resolve(&provider(&keys, bindings)).expect("resolves");

        match federation.exchange(&token, 1_800_000_000_000) {
            Exchange::Accepted(accepted) => {
                assert_eq!(accepted.identity, "ci-widget");
                assert_eq!(accepted.subject, "repo:acme/widget:ref:refs/heads/main");
                assert_eq!(accepted.provider, "forge");
                assert_eq!(accepted.ttl_ms, 15 * 60 * 1000, "the default ceiling");
            }
            other => panic!("expected an accepted exchange: {other:?}"),
        }

        // The same token, one claim short of the binding.
        let narrower = "[[oidc.binding]]\nidentity = \"ci-widget\"\nclaims = { sub = \"repo:acme/widget:ref:refs/heads/other\" }\n";
        let federation = Federation::resolve(&provider(&keys, narrower)).expect("resolves");
        assert!(matches!(
            federation.exchange(&token, 1_800_000_000_000),
            Exchange::Refused {
                reason: Refusal::NoBinding,
                ..
            }
        ));
    }

    /// The header does not get to choose the algorithm.
    #[test]
    fn a_header_naming_another_algorithm_finds_no_key() {
        let federation =
            Federation::resolve(&provider(&rfc7515_key(), JOE_BINDING)).expect("resolves");

        // The RFC's payload and signature, under a header claiming HS256 -- and under
        // one claiming `none`, which is the shape of the oldest attack on this format.
        let (_, rest) = RFC7515_TOKEN.split_once('.').expect("three parts");
        for algorithm in [r#"{"alg":"HS256"}"#, r#"{"alg":"none"}"#] {
            let forged = format!("{}.{rest}", base64url::encode(algorithm.as_bytes()));
            assert!(
                matches!(
                    federation.exchange(&forged, 1_300_000_000_000),
                    Exchange::Unverifiable(Unverifiable::UnknownKey)
                ),
                "{algorithm} must find no key"
            );
        }
    }

    #[test]
    fn an_unknown_issuer_is_unverifiable_and_unrecorded() {
        let mut configs = provider(&rfc7515_key(), JOE_BINDING);
        configs[0].issuer = "https://somebody-else".to_owned();
        let federation = Federation::resolve(&configs).expect("resolves");

        assert!(matches!(
            federation.exchange(RFC7515_TOKEN, 1_300_000_000_000),
            Exchange::Unverifiable(Unverifiable::UnknownIssuer)
        ));
    }

    #[test]
    fn nonsense_is_refused_without_touching_a_key() {
        let federation =
            Federation::resolve(&provider(&rfc7515_key(), JOE_BINDING)).expect("resolves");

        for bad in [
            "",
            "not-a-token",
            "a.b",
            "a.b.c.d",
            "!!!.!!!.!!!",
            "eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.AAAA",
        ] {
            assert!(
                matches!(
                    federation.exchange(bad, 1_300_000_000_000),
                    Exchange::Unverifiable(Unverifiable::Malformed)
                ),
                "{bad:?} must be malformed"
            );
        }

        let oversized = format!("a.{}.c", "A".repeat(super::MAX_ID_TOKEN_LEN));
        assert!(matches!(
            federation.exchange(&oversized, 1_300_000_000_000),
            Exchange::Unverifiable(Unverifiable::Malformed)
        ));
    }

    #[test]
    fn an_empty_configuration_verifies_nothing() {
        let federation = Federation::default();
        assert!(federation.is_empty());
        assert!(matches!(
            federation.exchange(RFC7515_TOKEN, 1_300_000_000_000),
            Exchange::Unverifiable(Unverifiable::UnknownIssuer)
        ));
    }

    #[test]
    fn the_configuration_is_checked_at_startup_rather_than_at_the_first_exchange() {
        // No key.
        assert!(Federation::resolve(&provider("", JOE_BINDING)).is_err());
        // No binding.
        assert!(Federation::resolve(&provider(&rfc7515_key(), "")).is_err());
        // An RSA modulus below 2048 bits.
        let small = "[[oidc.key]]\nalg = \"RS256\"\nkid = \"a\"\nn = \"AQAB\"\ne = \"AQAB\"\n";
        assert!(Federation::resolve(&provider(small, JOE_BINDING)).is_err());
        // A coordinate that is not base64url.
        let bad = "[[oidc.key]]\nalg = \"ES256\"\nkid = \"a\"\nx = \"++++\"\ny = \"AQAB\"\n";
        assert!(Federation::resolve(&provider(bad, JOE_BINDING)).is_err());
        // Two keys under one identifier.
        let twice = format!("{}{}", rfc7515_key(), rfc7515_key());
        assert!(Federation::resolve(&provider(&twice, JOE_BINDING)).is_err());
        // A binding on a claim that is verified rather than matched.
        let verified = "[[oidc.binding]]\nidentity = \"x\"\nclaims = { aud = \"ciphr\" }\n";
        assert!(Federation::resolve(&provider(&rfc7515_key(), verified)).is_err());
        // Two bindings with the same claims.
        let duplicated = format!("{JOE_BINDING}{JOE_BINDING}");
        assert!(Federation::resolve(&provider(&rfc7515_key(), &duplicated)).is_err());
        // A binding with no claims at all would match every token.
        let empty = "[[oidc.binding]]\nidentity = \"x\"\nclaims = {}\n";
        assert!(Federation::resolve(&provider(&rfc7515_key(), empty)).is_err());
        // An audience is mandatory.
        let mut configs = provider(&rfc7515_key(), JOE_BINDING);
        configs[0].audience = String::new();
        assert!(Federation::resolve(&configs).is_err());
        // And so is a TTL that parses.
        let mut configs = provider(&rfc7515_key(), JOE_BINDING);
        configs[0].ttl = "quarter of an hour".to_owned();
        assert!(Federation::resolve(&configs).is_err());
    }

    #[test]
    fn two_providers_cannot_claim_the_same_issuer_and_audience() {
        let one = provider(&rfc7515_key(), JOE_BINDING);
        let mut both = one.clone();
        both.extend(one);
        assert!(Federation::resolve(&both).is_err());
    }

    #[test]
    fn a_ttl_uses_the_same_language_as_the_cli() {
        assert_eq!(parse_duration_millis("15m"), Some(900_000));
        assert_eq!(parse_duration_millis("900s"), Some(900_000));
        assert_eq!(parse_duration_millis("1h"), Some(3_600_000));
        assert_eq!(parse_duration_millis(" 5m "), Some(300_000));
        for bad in ["", "900", "0m", "-5m", "m", "1w", "1.5h"] {
            assert!(
                parse_duration_millis(bad).is_none(),
                "{bad} must be refused"
            );
        }
    }
}
