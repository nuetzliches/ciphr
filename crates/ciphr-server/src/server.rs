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
        let state = AppState::new(store, sink, policies, root, seal_id, key_source);

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
            if tokio::signal::ctrl_c().await.is_ok() {
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
