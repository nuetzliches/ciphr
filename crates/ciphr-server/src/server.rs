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
        // The policy file first: it is the cheapest to check and the most likely to
        // have a typo in it, and getting it wrong is the failure with the worst
        // consequences.
        let policy_text =
            std::fs::read_to_string(&config.policies).map_err(|source| ConfigError::Read {
                path: config.policies.display().to_string(),
                source,
            })?;
        let policies = PolicySet::from_toml(&policy_text)?;

        // The surface next, and before the store lock: it is a pure check of the file
        // against the binary, so an operator with a stanza this build cannot honour
        // finds out without supplying a master key or taking a lock. Same reason the
        // policy file goes first.
        let surface = crate::surface::resolve(&config.surface)?;

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
                let device = FileDevice::open(path, rotate_at).map_err(|error| {
                    StartupError::Audit(format!("cannot open {}: {error}", path.display()))
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
