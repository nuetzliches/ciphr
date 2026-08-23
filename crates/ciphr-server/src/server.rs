//! Startup: assembling the pieces, or refusing to.
//!
//! Every failure below is a refusal to start rather than a degraded mode. A server
//! that runs without an audit device, or with a policy file that half-loaded, is a
//! server whose failures are silent — which is the property this project exists to
//! avoid. The order is deliberate: the cheap checks that catch configuration mistakes
//! come before the ones that need a master key, so an operator with a typo does not
//! have to supply a key to find out.

use std::net::SocketAddr;

use ciphr_audit::{AuditDevice, AuditSink, FileDevice};
use ciphr_core::{Capability, SecretPath};
use ciphr_policy::PolicySet;
use ciphr_store::{SqliteAuditDevice, SqliteStore, Store, StoreLock};

use crate::api;
use crate::config::{AuditConfig, Config, SealConfig};
use crate::error::{ConfigError, StartupError};
use crate::state::AppState;
use crate::tls;

/// A configured, ready-to-serve instance.
pub struct Server {
    state: AppState,
    config: Config,
    /// Held for the life of the process, released when it exits. Never read -- its
    /// existence is what keeps a second writer out.
    _lock: StoreLock,
}

impl Server {
    /// Load everything and check that the server *can* keep its promises.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError`] if the configuration, the policy file, the store, the
    /// seal, an audit device, or the TLS material is unusable. Each of those is a
    /// reason not to start.
    pub fn prepare(config: Config) -> Result<Self, StartupError> {
        // The two files first, in [`from_files`]: they are the cheapest to check and the
        // most likely to have a typo in them, and neither needs a key or a lock.
        let (policies, surface) = from_files(&config)?;

        // One writer per store, taken before anything else and held for the life of
        // the process. Without it a `ciphr` command run against this store while the
        // server is up moves the audit chain's head, the server's next record
        // collides on a sequence number, and fail-closed refuses every request from
        // then on -- permanently, because the chain only advances on a committed
        // record. Refusing to start is the honest failure: a restart was required
        // after such a write anyway, so this only moves the discovery earlier.
        let lock = StoreLock::acquire(&config.storage.path)?;
        let store = SqliteStore::open(&config.storage.path)?;

        // Unseal. A store that has never been initialized is not a store this server
        // can serve from, and `ciphr init` is the operation that fixes it.
        let seal_state = store
            .seal_state()?
            .ok_or(StartupError::Store(ciphr_store::StoreError::NotInitialized))?;
        let seal = match &config.seal {
            SealConfig::StaticEnv { env } => ciphr_crypto::StaticSeal::from_env(env)?,
            SealConfig::StaticFile { path } => ciphr_crypto::StaticSeal::from_file(path)?,
        };
        let root = ciphr_crypto::Seal::unseal(&seal, &seal_state.wrapped_root_key)?;

        // Audit devices, and the chain they continue. Resuming from the stored head
        // means a restart does not begin a second history in the same table; a stored
        // head that contradicts a recorded cut means records were removed without one,
        // and `audit_chain` refuses rather than continuing over the hole.
        let devices = open_devices(&config)?;
        let chain = store.audit_chain()?;
        let sink = AuditSink::new(devices, chain)
            .map_err(|error| StartupError::Audit(error.to_string()))?;

        let seal_id = seal_state.seal_id.clone();
        let key_source = seal.source().kind().to_owned();
        let state = AppState::new(store, sink, policies, root, seal_id, key_source, surface);

        // One entry naming the active surface, before the listener is bound. A
        // deployment that changes its own shape otherwise leaves no record the trail
        // can be asked about, and the trail is the artefact here that is
        // tamper-evident.
        //
        // Written through the ordinary fail-closed path, so a store that cannot record
        // it does not start. That is deliberate: this is the entry that says what the
        // process offers, and serving requests while unable to say so is the state the
        // audit requirement exists to prevent.
        //
        // Mapped rather than converted: `ApiError` is what a request sees, and a
        // `503` has no meaning before there is a listener. What an operator needs
        // here is the sentence that says the trail refused the first record.
        state.record_surface().map_err(|_| {
            StartupError::Audit(
                "no audit device accepted the startup record naming the active surface".to_owned(),
            )
        })?;

        Ok(Self {
            state,
            config,
            _lock: lock,
        })
    }

    /// Answer `--check-config` in two halves, and let the caller tell them apart.
    ///
    /// **The split is the point, and a field report is the reason.** Before this, the
    /// check was [`Self::prepare`] with the listener left off, so the *only* report a
    /// caller got — including the surface report, which is a pure function of the
    /// configuration file — arrived after the store had been opened, locked and written
    /// to. A configuration edit is exactly the change that wants review before it
    /// reaches a host, and there is no store there. The deployment in
    /// `docs/field-report-2026-08-23.md` therefore fabricated one on every deploy —
    /// scratch directory, a real key, `ciphr init`, delete — which is the shape of a
    /// gate that protects nothing and costs everyone who passes it.
    ///
    /// Three things [`Self::prepare`] does that this deliberately does not, each of
    /// which made the old check unusable exactly where it was cheapest to run:
    ///
    /// - **No store lock.** The lock keeps a second *writer* out; a check is not one.
    ///   With it, the command could not run while the service was up — so the one host
    ///   that has a store was the one host where the check was unavailable.
    /// - **No migration.** [`SqliteStore::open`] migrates on open, so checking a
    ///   `0.n` store with an `0.n+1` binary used to perform the schema move that the
    ///   pre-upgrade backup exists to make reversible. Read-only cannot.
    /// - **No audit record.** [`Self::prepare`] records the active surface, which is
    ///   right for a process about to serve and false for one that is about to exit.
    ///   A check that appends to a tamper-evident trail is a check nobody can run
    ///   twice without explaining the second line.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError`] when the *files* are unusable — an unparseable
    /// configuration, a policy file that will not load, a surface stanza this binary
    /// cannot honour. Those are refusals a caller can act on with nothing mounted.
    /// Everything that depends on this host is in [`Check::store`] instead, so a
    /// missing store cannot suppress the report about the file.
    pub fn check(config: &Config) -> Result<Check, StartupError> {
        let (policies, surface) = from_files(config)?;

        Ok(Check {
            identities: policies.identities().count(),
            rules: policies.policies().map(|policy| policy.rules().len()).sum(),
            unreachable: unreachable_entries(&policies, &surface),
            surface,
            store: store_state(config),
        })
    }

    /// The application state, for tests and for anything embedding the server.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Serve until the process is asked to stop.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError::Tls`] if the TLS material is unusable, or
    /// [`StartupError::Io`] if the listener cannot be bound.
    pub async fn serve(self) -> Result<(), StartupError> {
        let tls_config =
            tls::load(&self.config.server.tls.cert, &self.config.server.tls.key).await?;
        let router = api::router(self.state);

        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();

        // A graceful shutdown matters here for one specific reason: a request that has
        // been audited but not yet answered should be answered. Dropping it would leave
        // an audit entry describing an access that the client never received, which is
        // a confusing trail to read later.
        tokio::spawn(async move {
            if stop_requested().await {
                shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            }
        });

        axum_server::bind_rustls(self.config.server.listen, tls_config)
            .handle(handle)
            // `_with_connect_info` rather than the bare make-service: without it the
            // peer address never reaches the handlers, and the audit trail records
            // every unauthenticated denial with no source at all. Plan section 23
            // keys its rate limit on this address, so it has to exist before that
            // endpoint can.
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(StartupError::Io)
    }
}

/// Completes when something has asked this process to stop.
///
/// **SIGTERM is the one that matters, and it was the one missing.** A container runtime
/// stops a service with SIGTERM; `tokio::signal::ctrl_c` is SIGINT on Unix and nothing
/// else. So the graceful shutdown above — the one `docker-entrypoint.sh` `exec`s in
/// order to reach — never ran on an ordinary stop: SIGTERM had no handler, the default
/// action terminated the process, and any request already audited and not yet answered
/// was dropped. The trail then records an access the client never received, which is
/// exactly the confusion the graceful shutdown exists to prevent.
///
/// No data is at risk either way — `synchronous = FULL` and WAL mean an abrupt stop
/// costs no committed write — so this is about the trail telling the truth, and about
/// the write-ahead log being checkpointed away on a clean close rather than left for a
/// backup job to remember (`docs/operations/backup.md`).
///
/// Returns `false` if no signal can be waited on at all, in which case the process
/// keeps serving and is stopped the way it would have been before.
///
/// Public so that `tests/shutdown.rs` can exercise it in a **process of its own**. That
/// is not tidiness: a test for this has to raise a real signal, and if the registration
/// below ever breaks again, the signal has no handler and kills whatever process it was
/// raised in. Its own test binary is the difference between one failing test and a test
/// run that reports nothing.
pub async fn stop_requested() -> bool {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        // Registering both before awaiting either is the part that matters: a signal
        // stream replaces the default action from the moment it exists, so a SIGTERM
        // arriving during startup is queued rather than fatal.

        // Nothing here can recover from a failed registration, and pretending otherwise
        // would leave the process believing it has a graceful shutdown it does not have.
        // Fall back to SIGINT alone, which is what the previous behaviour was.
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            return tokio::signal::ctrl_c().await.is_ok();
        };

        tokio::select! {
            outcome = tokio::signal::ctrl_c() => outcome.is_ok(),
            received = terminate.recv() => received.is_some(),
        }
    }

    // Windows has no SIGTERM. `ctrl_c` covers Ctrl-C and, through tokio, the console
    // close and shutdown events that stand in for it.
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.is_ok()
    }
}

/// What `--check-config` learned, in the two halves a caller has to tell apart.
///
/// One half is a function of the files alone and travels with them; the other describes
/// this host and cannot be answered anywhere else. Keeping them in one value rather than
/// in one `Result` is what lets the report print both.
pub struct Check {
    /// Identities the policy file names.
    pub identities: usize,
    /// Rules across every policy in it.
    pub rules: usize,
    /// Entries this configuration turned on that no identity in it can call.
    ///
    /// A function of the two files and of nothing on this host, so it belongs to the
    /// half of the report that holds in review. See [`unreachable_entries`].
    pub unreachable: Vec<Unreachable>,
    /// The surface this configuration resolves to, against this binary.
    pub surface: crate::surface::Active,
    /// This host's store, seal and audit devices — or the reason they are not ready.
    pub store: Result<StoreReady, StartupError>,
}

/// A store this configuration can serve from, and what it was found to be.
///
/// Every field is something an operator would otherwise open a second tool to learn, and
/// the first two are what a pre-upgrade check is actually asking about.
pub struct StoreReady {
    /// `PRAGMA user_version`, as found. Not migrated to get it.
    pub schema_version: u32,
    /// The seal record's identifier, so two stores are distinguishable.
    pub seal_id: String,
    /// Where the master key came from, never the key.
    pub key_source: String,
    /// Every audit device that opened, by name.
    pub devices: Vec<String>,
}

/// What an entry needs before anybody can call it, where that is one grant.
///
/// **Not a field on [`ENTRIES`](crate::surface::ENTRIES), deliberately.** `viewer_api`
/// serves several control-plane paths and an identity that reaches one of them is a
/// legitimate deployment, so "what does this entry require" has no single answer there —
/// and a table where some entries carry a requirement and others carry `None` reads as
/// *this one needs nothing*, which would be false. The two below are the entries whose
/// requirement is a single literal grant, and this list says so rather than implying
/// anything about the rest.
const REACHABILITY: &[(&str, &str, Capability)] = &[
    ("token_status", "sys/tokens", Capability::Inspect),
    ("token_revoke", "sys/tokens", Capability::Revoke),
];

/// Entries that are on and that no identity in this policy file can call.
///
/// **An entry that is on and unreachable is the same class of quiet as a stanza that was
/// forgotten**, which is the mistake the surface report exists to catch
/// (`docs/field-report-2026-08-23-b.md`, finding 3). The case that prompted it is
/// `token_revoke`: a deployment turns the entry on to take the outage out of revoking a
/// leaked credential, and the token that calls it can only be issued on the host, under
/// the lock, in a planned stop. An entry on with nobody able to reach it is that job left
/// half done, and the operator who finds out is mid-incident.
///
/// Not a refusal. Naming the entry before the identity exists is a legitimate order of
/// work, and this is the report that says the second half is still owed.
///
/// **The evaluator answers the question**, rather than this walking rules and matching
/// patterns itself: there is one place in this workspace that decides whether an identity
/// may do something, and a second implementation of that reasoning — even one that only
/// reports — is the thing ADR-9 forbids for path normalization, for the same reason.
fn unreachable_entries(policies: &PolicySet, surface: &crate::surface::Active) -> Vec<Unreachable> {
    REACHABILITY
        .iter()
        .filter(|(name, path, capability)| {
            surface.has(name) && !anyone_may(policies, path, *capability)
        })
        .map(|(name, path, capability)| Unreachable {
            entry: name,
            path,
            capability: *capability,
        })
        .collect()
}

/// One entry that is on, and the grant nobody in the policy file holds.
///
/// The grant is carried rather than only the entry name, because the report is read by
/// somebody who then has to write a rule: *no identity is authorized for `revoke` on
/// `sys/tokens`* names the edit, and *nobody can call this* does not.
pub struct Unreachable {
    /// The entry that is on.
    pub entry: &'static str,
    /// The path its capability is authorized against.
    pub path: &'static str,
    /// The capability no identity holds there.
    pub capability: Capability,
}

/// Whether any identity in this policy file is authorized for `capability` on `path`.
fn anyone_may(policies: &PolicySet, path: &str, capability: Capability) -> bool {
    let path = SecretPath::parse(path).expect("the reserved paths are valid by construction");
    policies.identities().any(|identity| {
        policies
            .evaluate(identity.name(), &path, capability)
            .is_allowed()
    })
}

/// Everything startup can learn from the configuration and the policy file alone.
///
/// **One function because both callers must check the same things.** [`Server::prepare`]
/// runs it before taking the lock so that an operator with a typo does not have to supply
/// a master key to find out; [`Server::check`] runs it *instead of* touching this host at
/// all. Written twice, the store-free half of the check would drift from the store-free
/// half of startup, and the drift would be invisible until a file passed the check and
/// refused to start.
fn from_files(config: &Config) -> Result<(PolicySet, crate::surface::Active), StartupError> {
    // The policy file first: it is the cheapest to check and the most likely to have a
    // typo in it, and getting it wrong is the failure with the worst consequences.
    let policy_text =
        std::fs::read_to_string(&config.policies).map_err(|source| ConfigError::Read {
            path: config.policies.display().to_string(),
            source,
        })?;
    let policies = PolicySet::from_toml(&policy_text)?;

    // The surface next: a pure check of the file against the binary, so an operator with
    // a stanza this build cannot honour finds out without a key, a store or a lock.
    let surface = crate::surface::resolve(&config.surface)?;

    Ok((policies, surface))
}

/// Whether this host's store is one the configuration could serve from.
///
/// Read-only throughout, and that is the whole design: nothing here migrates, locks or
/// records, so this is safe to run against a live service and cannot be the step that
/// spends the rollback a pre-upgrade backup was taken to keep ([`Server::check`]).
///
/// The seal is *used* rather than merely located — the key is read and the root key
/// unwrapped, then dropped — because "there is a key file" and "this key opens this
/// store" are different claims and only the second one is worth a check.
fn store_state(config: &Config) -> Result<StoreReady, StartupError> {
    // Asked before opening, so an absent store says so in the sentence the previous
    // version printed. Read-only cannot create the file, which is the point: the old
    // check left an empty `store.db` behind on a host that had none.
    if !config.storage.path.exists() {
        return Err(StartupError::Store(ciphr_store::StoreError::NotInitialized));
    }

    let store = SqliteStore::open_read_only(&config.storage.path)?;
    let schema_version = store.schema_version()?;
    let seal_state = store
        .seal_state()?
        .ok_or(StartupError::Store(ciphr_store::StoreError::NotInitialized))?;

    let seal = match &config.seal {
        SealConfig::StaticEnv { env } => ciphr_crypto::StaticSeal::from_env(env)?,
        SealConfig::StaticFile { path } => ciphr_crypto::StaticSeal::from_file(path)?,
    };
    // Dropped immediately, and zeroized on the way out. Checking that it unwraps is the
    // claim; holding it is not.
    drop(ciphr_crypto::Seal::unseal(
        &seal,
        &seal_state.wrapped_root_key,
    )?);

    let devices = open_devices(config)?
        .iter()
        .map(|device| device.name().to_owned())
        .collect();

    Ok(StoreReady {
        schema_version,
        seal_id: seal_state.seal_id,
        key_source: seal.source().kind().to_owned(),
        devices,
    })
}

/// Open every configured audit device.
///
/// A device that cannot be opened is a startup failure, not a warning. Starting with
/// one of two devices silently reduces the audit trail to a single copy, and nobody
/// finds out until they need the other one.
fn open_devices(config: &Config) -> Result<Vec<Box<dyn AuditDevice>>, StartupError> {
    let rotate_at = config.file_rotate_bytes()?;
    let mut devices: Vec<Box<dyn AuditDevice>> = Vec::with_capacity(config.audit.len());

    for device in &config.audit {
        match device {
            AuditConfig::Sqlite => {
                let device = SqliteAuditDevice::open(&config.storage.path)?;
                devices.push(Box::new(device));
            }
            AuditConfig::File { path, .. } => {
                // **The message names the requirement, not only the OS error.** It read
                // `cannot open <path>: Read-only file system (os error 30)`, whose first
                // reading is "the audit device is broken" when the fact is "this needs
                // the directory writable and it was mounted read-only". Read-only is the
                // safe instinct for a command whose name says *check*, so the person who
                // sees this is pre-flighting a host they have deliberately given as
                // little access as possible -- and the sentence they need is what the
                // device requires (`docs/field-report-2026-08-23-b.md`, finding 2). The
                // behaviour is unchanged and is the defensible half: the device is
                // checked by opening it the way it will be opened, and that is an append.
                let device = FileDevice::open(path, rotate_at).map_err(|error| {
                    StartupError::Audit(format!(
                        "cannot open {} for append: {error}\n  the file device appends \
                         every entry, so its directory has to be writable by the \
                         service user",
                        path.display()
                    ))
                })?;
                devices.push(Box::new(device));
            }
        }
    }

    // Unreachable through `Config`, which refuses an empty list at load time. Checked
    // again because the guarantee matters more than the redundancy costs.
    if devices.is_empty() {
        return Err(StartupError::Audit(
            "no audit device is configured".to_owned(),
        ));
    }

    Ok(devices)
}
