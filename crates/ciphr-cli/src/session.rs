//! Opening the store, and the two rules about secrets on a terminal.
//!
//! The CLI works on the **local** store, not through the HTTP API. That is a
//! deliberate departure from the plan, which had the CLI go through the SDK: most of
//! what it does — initializing a store, issuing a token, verifying the audit chain,
//! exporting for migration — needs the master key and has no API endpoint, by design
//! (ADR-3). A CLI that spoke HTTP would need a second, privileged API to do its job,
//! which is the API this project deliberately does not have.
//!
//! Remote access is `curl`, or the SDK from an application. Both are documented.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use ciphr_audit::{Action, AuditSink, Chain, Entry, FileDevice, Principal};
use ciphr_crypto::{RootKey, Seal, StaticEnvSeal, TokenPepper};
use ciphr_store::{SqliteAuditDevice, SqliteStore, Store, StoreLock};

use crate::error::CliError;

/// An open store with its root key available.
pub(crate) struct Session {
    pub(crate) store: SqliteStore,
    pub(crate) root: RootKey,
    pub(crate) pepper: TokenPepper,
    pub(crate) database: PathBuf,
    /// Where audit entries this session writes will go.
    audit: Option<AuditSink>,
    /// Held for the lifetime of the session, released when it drops. Never read --
    /// its existence is the point.
    _lock: StoreLock,
}

impl Session {
    /// Open an initialized store and unseal it.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] if the database cannot be opened, has never been
    /// initialized, or cannot be unsealed with the master key in the environment.
    pub(crate) fn open(database: &Path, master_key_variable: &str) -> Result<Self, CliError> {
        // Before anything else. The audit chain is held in memory by whoever has the
        // store open, so a second writer -- another CLI invocation or a running
        // server -- would collide on a sequence number and leave the first process
        // refusing every request until it restarts. Taken here rather than only
        // around the write, because the CLI audits what it does including reads, so
        // every command that opens a session is a writer.
        let lock = StoreLock::acquire(database)?;
        let store = SqliteStore::open(database)?;
        let state = store
            .seal_state()?
            .ok_or_else(|| CliError::NotInitialized {
                path: database.display().to_string(),
            })?;

        let seal = StaticEnvSeal::from_env(master_key_variable)?;
        let root = seal.unseal(&state.wrapped_root_key)?;
        let pepper = TokenPepper::derive(&root);

        Ok(Self {
            store,
            root,
            pepper,
            database: database.to_path_buf(),
            audit: None,
            _lock: lock,
        })
    }

    /// Attach an audit sink, so that what this session does is recorded.
    ///
    /// The CLI audits its own actions for the same reason the server does: an
    /// operator reading a secret from the host is an access, and the trail that omits
    /// it is a trail that answers "who read this" incorrectly.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] if the audit device cannot be opened. Refusing here rather
    /// than continuing unaudited is the same fail-closed choice the server makes.
    pub(crate) fn with_audit(mut self, file: Option<&Path>) -> Result<Self, CliError> {
        let mut devices: Vec<Box<dyn ciphr_audit::AuditDevice>> =
            vec![Box::new(SqliteAuditDevice::open(&self.database)?)];
        if let Some(path) = file {
            devices.push(Box::new(FileDevice::open(path, None).map_err(|error| {
                CliError::Audit(format!("cannot open {}: {error}", path.display()))
            })?));
        }

        let chain = match self.store.audit_head()? {
            None => Chain::new(),
            Some((seq, hash)) => Chain::resume(seq, hash),
        };
        self.audit = Some(
            AuditSink::new(devices, chain).map_err(|error| CliError::Audit(error.to_string()))?,
        );
        Ok(self)
    }

    /// Record what this invocation did.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Audit`] if no device accepted the record. The command fails
    /// in that case, which for a read means the value is not printed — the same
    /// fail-closed rule as the server.
    pub(crate) fn record(&mut self, entry: &Entry) -> Result<(), CliError> {
        let Some(sink) = self.audit.as_mut() else {
            return Ok(());
        };
        sink.record(entry, now_millis())
            .map(|_| ())
            .map_err(|error| CliError::Audit(error.to_string()))
    }

    /// An audit entry attributed to the operator running the CLI.
    ///
    /// The principal is the local account name where it can be determined. It is not an
    /// identity from the policy file, and the entry does not pretend otherwise: a
    /// person on the host is not a machine identity, and conflating them would make the
    /// trail say something false.
    pub(crate) fn operator_entry(action: Action, allowed: bool, reason: Option<&str>) -> Entry {
        let name = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "operator".to_owned());

        let entry = match (allowed, reason) {
            (true, _) => Entry::allowed(action),
            (false, Some(reason)) => Entry::denied(action, reason),
            (false, None) => Entry::denied(action, "refused"),
        };
        entry.with_principal(Principal {
            name: format!("cli:{name}"),
            kind: Some("operator".to_owned()),
            token_id: None,
        })
    }
}

/// Milliseconds since the Unix epoch, UTC.
pub(crate) fn now_millis() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// Read a secret value from standard input.
///
/// **Values are never taken from an argument.** An argument ends up in shell history
/// and in `/proc/<pid>/cmdline`, where every other process on the host can read it for
/// as long as the command runs.
///
/// Nor is there an interactive prompt: disabling terminal echo needs another
/// dependency, and prompting *with* echo would write the secret into the scrollback of
/// whoever typed it. Piping is the one route that leaves no copy behind.
///
/// # Errors
///
/// Returns [`CliError::NeedsStdin`] if standard input is a terminal, with instructions.
pub(crate) fn read_value_from_stdin() -> Result<Vec<u8>, CliError> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::NeedsStdin);
    }

    let mut value = Vec::new();
    std::io::stdin().read_to_end(&mut value)?;

    // A trailing newline is almost always the shell's, not part of the secret. Exactly
    // one is stripped, so a value that genuinely ends in a newline can still be stored
    // by supplying two.
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    Ok(value)
}

/// Whether it is safe to print a secret, and refuse if not asked to.
///
/// Piped output is how a secret ends up in a log file, a CI transcript, or a shell
/// history through `$(...)`. That is often exactly what the caller wants, so it is
/// allowed — but only when said explicitly with `--force`.
///
/// # Errors
///
/// Returns [`CliError::WouldPipeSecret`] if standard output is not a terminal and
/// `force` is false.
pub(crate) fn guard_secret_output(force: bool) -> Result<(), CliError> {
    if force || std::io::stdout().is_terminal() {
        return Ok(());
    }
    Err(CliError::WouldPipeSecret)
}

#[cfg(test)]
mod tests {
    use super::Session;
    use ciphr_audit::Action;

    #[test]
    fn an_operator_entry_does_not_claim_to_be_a_machine_identity() {
        let entry = Session::operator_entry(Action::Read, true, None);
        let principal = entry.principal.expect("a principal");

        assert!(
            principal.name.starts_with("cli:"),
            "the trail must show this came from the host, got {}",
            principal.name
        );
        assert_eq!(principal.kind.as_deref(), Some("operator"));
        // No token was used, and the entry says so rather than inventing one.
        assert!(principal.token_id.is_none());
    }

    #[test]
    fn a_refusal_carries_its_reason() {
        let entry = Session::operator_entry(Action::Read, false, Some("not-found"));
        assert!(!entry.allowed);
        assert_eq!(entry.deny_reason.as_deref(), Some("not-found"));
    }
}
