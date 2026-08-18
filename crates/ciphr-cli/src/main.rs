#![forbid(unsafe_code)]

//! `ciphr` — the command-line interface.
//!
//! Works on the local store, with the master key from the environment. Most of what it
//! does has no API endpoint by design (ADR-3): initializing a store, issuing a token,
//! shredding a version, verifying the audit chain, and exporting for migration all need
//! the master key, and exposing them over HTTP would mean building the privileged API
//! this project deliberately does not have.
//!
//! Two rules run through every command:
//!
//! - **A value is never an argument.** Arguments end up in shell history and in
//!   `/proc/<pid>/cmdline`. Values come from standard input.
//! - **A secret is not written to a pipe without being asked.** Piped output is how a
//!   secret reaches a log or a CI transcript; `--force` says that is intended.

mod error;
mod formats;
mod session;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use ciphr_audit::{Action, StoredRecord, verify_from_genesis};
use ciphr_core::{Plaintext, Rotation, SecretPath, SecretVersion};
use ciphr_crypto::{RootKey, RootKeyId, Seal, StaticEnvSeal, Token};
use ciphr_policy::PolicySet;
use ciphr_store::{AuditFilter, SealState, SqliteStore, Store};
use clap::{Args, Parser, Subcommand};

use error::{CliError, parse_duration_millis};
use formats::{ExportFormat, Exported, parse_dotenv, render_actions_env};
use session::{Session, guard_secret_output, now_millis, read_value_from_stdin};

/// A secret manager for machine identities.
#[derive(Debug, Parser)]
#[command(name = "ciphr", version, about, long_about = None)]
struct Cli {
    /// Path to the store.
    #[arg(long, short, global = true, default_value = "ciphr.db")]
    database: PathBuf,

    /// Environment variable holding the 64-character hexadecimal master key.
    #[arg(long, global = true, default_value = "CIPHR_MASTER_KEY")]
    master_key_env: String,

    /// Policy file, for commands that need to know which identities exist.
    #[arg(long, global = true, default_value = "policies.toml")]
    policies: PathBuf,

    /// Also append this session's audit entries to a JSON Lines file.
    #[arg(long, global = true)]
    audit_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a store: generate a root key and seal it.
    Init,

    /// Write a new version of a secret. The value comes from standard input.
    Put {
        /// Where to store it.
        path: String,
        /// How safe this secret is to rotate.
        #[arg(long)]
        rotation: Option<String>,
    },

    /// Read a secret.
    Get {
        /// Which secret.
        path: String,
        /// Which version. The current one if omitted.
        #[arg(long)]
        version: Option<u32>,
        /// Write the value even though output is not a terminal.
        #[arg(long)]
        force: bool,
    },

    /// List paths under a prefix.
    List {
        /// The prefix. Everything if omitted.
        prefix: Option<String>,
    },

    /// Show the version history of a secret.
    Versions {
        /// Which secret.
        path: String,
    },

    /// Soft-delete a version. Reversible with `undelete`.
    Delete {
        /// Which secret.
        path: String,
        /// Which version. The current one if omitted.
        #[arg(long)]
        version: Option<u32>,
    },

    /// Restore a soft-deleted version.
    Undelete {
        /// Which secret.
        path: String,
        /// Which version.
        #[arg(long)]
        version: u32,
    },

    /// Destroy a version irreversibly by deleting its wrapped key.
    Destroy {
        /// Which secret.
        path: String,
        /// Which version.
        #[arg(long)]
        version: u32,
        /// Required. There is no undo, in this store or in any backup taken afterwards.
        #[arg(long)]
        yes: bool,
    },

    /// Set how safe a secret is to rotate.
    Rotation {
        /// Which secret.
        path: String,
        /// One of: rotatable, seed-only, breaks-data, volume-bound, invalidates-sessions.
        class: String,
    },

    /// Export several secrets in one of the consumable formats.
    Export(ExportArgs),

    /// Import a `.env` file.
    Import(ImportArgs),

    /// Tokens.
    #[command(subcommand)]
    Token(TokenCommand),

    /// The audit trail.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Re-wrap the root key under a new master key.
    RotateMasterKey {
        /// Environment variable holding the new master key.
        #[arg(long)]
        new_key_env: String,
    },

    /// Write every secret out in plaintext, for migrating away from ciphr.
    Dump {
        /// Only `portable` exists, and it is the format another system can read.
        #[arg(long, default_value = "portable")]
        format: String,
        /// Required, because this writes every secret in plaintext.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Export everything under this prefix.
    #[arg(long, conflicts_with = "path")]
    prefix: Option<String>,
    /// Export these paths. May be repeated.
    #[arg(long)]
    path: Vec<String>,
    /// dotenv, actions-env, or json.
    #[arg(long, default_value = "dotenv")]
    format: String,
    /// Write values even though output is not a terminal.
    #[arg(long)]
    force: bool,
    /// For `actions-env`: append the assignments to the file named by `$GITHUB_ENV`.
    #[arg(long)]
    github_env: bool,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// The `.env` file to read.
    #[arg(long)]
    from_dotenv: PathBuf,
    /// Prefix each variable with this path.
    #[arg(long)]
    prefix: String,
    /// Show what would be written, and write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Rotation class for every imported secret.
    #[arg(long)]
    rotation: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Issue a token for an identity from the policy file.
    Issue {
        /// The identity name.
        identity: String,
        /// How long it is valid, such as 90d. No expiry if omitted.
        #[arg(long)]
        ttl: Option<String>,
        /// Print the token even though output is not a terminal.
        #[arg(long)]
        force: bool,
    },
    /// List tokens, without their verifiers.
    List {
        /// Only this identity's tokens.
        #[arg(long)]
        identity: Option<String>,
    },
    /// Revoke one token by its identifier.
    Revoke {
        /// The eight-character identifier.
        token_id: String,
    },
    /// Revoke every token of an identity.
    RevokeAll {
        /// The identity name.
        identity: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Show the most recent entries.
    Tail {
        /// How many.
        #[arg(long, short = 'n', default_value = "20")]
        count: u32,
    },
    /// Verify the hash chain from the beginning.
    Verify,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ciphr: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The global options, separated from the command so that a command can be matched by
/// value while the options stay borrowable.
struct Context {
    database: PathBuf,
    master_key_env: String,
    policies: PathBuf,
    audit_file: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<(), CliError> {
    let Cli {
        database,
        master_key_env,
        policies,
        audit_file,
        command,
    } = cli;
    let cli = Context {
        database,
        master_key_env,
        policies,
        audit_file,
    };

    match command {
        Command::Init => init(&cli.database, &cli.master_key_env),

        Command::Put { path, rotation } => {
            let path = SecretPath::parse(&path)?;
            let value = read_value_from_stdin()?;
            let rotation = rotation.as_deref().map(Rotation::parse).transpose()?;

            let mut session = open(&cli)?;
            // Audited before the write, so a failure to record leaves the store
            // unchanged — the same ordering the server uses.
            session.record(&Session::operator_entry(Action::Write, true, None).with_path(&path))?;

            let plaintext = Plaintext::from(value);
            let root = &session.root;
            let version = session.store.put(&path, "cli", &mut |version| {
                ciphr_crypto::encrypt(root, &path, version, &plaintext)
            })?;
            if let Some(class) = rotation {
                session.store.set_rotation(&path, class)?;
            }

            println!("{path} version {version}");
            Ok(())
        }

        Command::Get {
            path,
            version,
            force,
        } => {
            let path = SecretPath::parse(&path)?;
            guard_secret_output(force)?;

            let mut session = open(&cli)?;
            let wanted = version.and_then(SecretVersion::new);

            let stored = match session.store.get(&path, wanted) {
                Ok(stored) => stored,
                Err(error) => {
                    session.record(
                        &Session::operator_entry(Action::Read, false, Some("not-found"))
                            .with_path(&path),
                    )?;
                    return Err(error.into());
                }
            };

            let plaintext =
                ciphr_crypto::decrypt(&session.root, &stored.path, stored.version, &stored.value)?;

            // Recorded before anything is printed. If the trail is unavailable the value
            // is not shown, which is the same fail-closed rule the server follows.
            session.record(
                &Session::operator_entry(Action::Read, true, None)
                    .with_path(&stored.path)
                    .with_version(stored.version),
            )?;

            let mut out = std::io::stdout();
            out.write_all(plaintext.expose())?;
            out.write_all(b"\n")?;
            Ok(())
        }

        Command::List { prefix } => {
            let prefix = prefix.as_deref().map(SecretPath::parse).transpose()?;
            let mut session = open(&cli)?;

            // Audited like every other access. The trail should say the same thing
            // whether a listing came through the API or from the host: a channel that
            // records less is a channel someone will use for that reason.
            let mut entry = Session::operator_entry(Action::List, true, None);
            if let Some(prefix) = prefix.as_ref() {
                entry = entry.with_path(prefix);
            }
            session.record(&entry)?;

            for path in session.store.list(prefix.as_ref())? {
                println!("{path}");
            }
            Ok(())
        }

        Command::Versions { path } => {
            let path = SecretPath::parse(&path)?;
            let mut session = open(&cli)?;
            session.record(&Session::operator_entry(Action::List, true, None).with_path(&path))?;

            for summary in session.store.versions(&path)? {
                let state = if summary.destroyed_at.is_some() {
                    "destroyed"
                } else if summary.deleted_at.is_some() {
                    "deleted"
                } else {
                    "present"
                };
                println!(
                    "{:>4}  {}  {:<9}  {}",
                    summary.version,
                    ciphr_audit::time::rfc3339_millis(summary.created_at),
                    state,
                    summary.created_by
                );
            }
            Ok(())
        }

        Command::Delete { path, version } => {
            let path = SecretPath::parse(&path)?;
            let mut session = open(&cli)?;
            let version = match version.and_then(SecretVersion::new) {
                Some(version) => version,
                None => session
                    .store
                    .metadata(&path)?
                    .current_version
                    .ok_or(CliError::Store(ciphr_store::StoreError::NotFound {
                        path: path.as_str().to_owned(),
                    }))?,
            };

            session.record(
                &Session::operator_entry(Action::Delete, true, None)
                    .with_path(&path)
                    .with_version(version),
            )?;
            session.store.delete(&path, version)?;
            println!("{path} version {version} deleted");
            Ok(())
        }

        Command::Undelete { path, version } => {
            let path = SecretPath::parse(&path)?;
            let version = SecretVersion::new(version).ok_or(CliError::Duration {
                found: "version 0".to_owned(),
            })?;

            let mut session = open(&cli)?;
            session.record(
                &Session::operator_entry(Action::Undelete, true, None)
                    .with_path(&path)
                    .with_version(version),
            )?;
            session.store.undelete(&path, version)?;
            println!("{path} version {version} restored");
            Ok(())
        }

        Command::Destroy { path, version, yes } => {
            let path = SecretPath::parse(&path)?;
            let version = SecretVersion::new(version).ok_or(CliError::Duration {
                found: "version 0".to_owned(),
            })?;

            if !yes {
                return Err(CliError::Audit(
                    "destroying a version is irreversible, including in every backup taken \
                     afterwards; pass --yes if that is what you mean"
                        .to_owned(),
                ));
            }

            let mut session = open(&cli)?;
            session.record(
                &Session::operator_entry(Action::Destroy, true, None)
                    .with_path(&path)
                    .with_version(version),
            )?;
            session.store.destroy(&path, version)?;
            println!("{path} version {version} destroyed; the value cannot be recovered");
            Ok(())
        }

        Command::Rotation { path, class } => {
            let path = SecretPath::parse(&path)?;
            let class = Rotation::parse(&class)?;
            let mut session = open(&cli)?;
            session.store.set_rotation(&path, class)?;

            println!("{path} is {class}");
            if class.needs_care() {
                println!();
                println!("{}", class.advice());
            }
            Ok(())
        }

        Command::Export(args) => export(&cli, &args),
        Command::Import(args) => import(&cli, &args),
        Command::Token(command) => token(&cli, command),
        Command::Audit(command) => audit(&cli, &command),
        Command::RotateMasterKey { new_key_env } => rotate_master_key(&cli, &new_key_env),
        Command::Dump { format, force } => dump(&cli, &format, force),
    }
}

/// Open the store, unseal it, and attach the audit devices.
fn open(cli: &Context) -> Result<Session, CliError> {
    Session::open(&cli.database, &cli.master_key_env)?.with_audit(cli.audit_file.as_deref())
}

/// `ciphr init` — generate a root key and seal it.
fn init(database: &std::path::Path, master_key_variable: &str) -> Result<(), CliError> {
    let mut store = SqliteStore::open(database)?;
    if store.seal_state()?.is_some() {
        return Err(CliError::AlreadyInitialized {
            path: database.display().to_string(),
        });
    }

    let seal = StaticEnvSeal::from_env(master_key_variable)?;
    let root = RootKey::generate()?;
    let root_id = RootKeyId::generate()?;

    store.initialize(&SealState {
        seal_id: seal.id().to_owned(),
        wrapped_root_key: seal.rewrap(&root, root_id)?,
    })?;

    // The first audit entry of a store is its own creation, which is what makes the
    // chain start at something rather than at nothing.
    let mut session = Session::open(database, master_key_variable)?.with_audit(None)?;
    session.record(&Session::operator_entry(Action::Init, true, None))?;

    println!("initialized {}", database.display());
    println!("root key {root_id}, sealed with {}", seal.id());
    println!();
    println!("Keep a break-glass copy of the master key outside this host, and not in the");
    println!("same backup as the database: together they are a complete secret store.");
    Ok(())
}

/// `ciphr export`.
fn export(cli: &Context, args: &ExportArgs) -> Result<(), CliError> {
    let format = match args.format.as_str() {
        "dotenv" => ExportFormat::Dotenv,
        "actions-env" => ExportFormat::ActionsEnv,
        "json" => ExportFormat::Json,
        other => {
            return Err(CliError::Duration {
                found: format!("format '{other}'; use dotenv, actions-env or json"),
            });
        }
    };

    // `actions-env` writes assignments into a file the runner reads, so it is allowed to
    // produce output on a pipe: that is its whole purpose. Everything else needs
    // --force.
    if format != ExportFormat::ActionsEnv {
        guard_secret_output(args.force)?;
    }

    let mut session = open(cli)?;

    let paths: Vec<SecretPath> = if let Some(prefix) = args.prefix.as_deref() {
        let prefix = SecretPath::parse(prefix)?;
        session.store.list(Some(&prefix))?
    } else {
        args.path
            .iter()
            .map(|raw| SecretPath::parse(raw))
            .collect::<Result<_, _>>()?
    };

    if paths.is_empty() {
        return Err(CliError::Duration {
            found: "nothing to export; pass --prefix or --path".to_owned(),
        });
    }

    let mut secrets = Vec::with_capacity(paths.len());
    for path in paths {
        let stored = session.store.get(&path, None)?;
        let plaintext =
            ciphr_crypto::decrypt(&session.root, &stored.path, stored.version, &stored.value)?;
        let value = String::from_utf8(plaintext.expose().to_vec()).map_err(|_| {
            CliError::Audit(format!("{path} is not valid UTF-8 and cannot be exported"))
        })?;

        // One entry per secret, exactly as the API does for a bulk read.
        session.record(
            &Session::operator_entry(Action::Read, true, None)
                .with_path(&stored.path)
                .with_version(stored.version),
        )?;

        secrets.push(Exported {
            path: stored.path,
            value,
        });
    }

    if format == ExportFormat::ActionsEnv {
        let (masks, assignments) = render_actions_env(&secrets);
        // Masks first, always: a mask registered after a value has been printed masks
        // nothing that already went out.
        print!("{masks}");

        if args.github_env {
            let Ok(target) = std::env::var("GITHUB_ENV") else {
                return Err(CliError::Audit(
                    "--github-env was given but GITHUB_ENV is not set".to_owned(),
                ));
            };
            let mut file = std::fs::OpenOptions::new().append(true).open(target)?;
            file.write_all(assignments.as_bytes())?;
        } else {
            print!("{assignments}");
        }
    } else {
        print!("{}", format.render(&secrets));
    }

    Ok(())
}

/// `ciphr import --from-dotenv`.
fn import(cli: &Context, args: &ImportArgs) -> Result<(), CliError> {
    let prefix = SecretPath::parse(&args.prefix)?;
    let rotation = args.rotation.as_deref().map(Rotation::parse).transpose()?;
    let text = std::fs::read_to_string(&args.from_dotenv)?;
    let entries =
        parse_dotenv(&text).map_err(|(line, reason)| CliError::DotEnv { line, reason })?;

    let targets: Vec<(SecretPath, String)> = entries
        .into_iter()
        .map(|entry| {
            let path = SecretPath::parse(&format!("{prefix}/{}", entry.key))?;
            Ok((path, entry.value))
        })
        .collect::<Result<_, CliError>>()?;

    if args.dry_run {
        // Deliberately shows paths and never values: a dry run is something people run
        // to check their work, often with a colleague looking at the screen.
        println!("would write {} secrets:", targets.len());
        for (path, value) in &targets {
            println!("  {path}  ({} bytes)", value.len());
        }
        return Ok(());
    }

    let mut session = open(cli)?;
    for (path, value) in targets {
        session.record(&Session::operator_entry(Action::Write, true, None).with_path(&path))?;

        let plaintext = Plaintext::from(value.into_bytes());
        let root = &session.root;
        session.store.put(&path, "cli:import", &mut |version| {
            ciphr_crypto::encrypt(root, &path, version, &plaintext)
        })?;
        if let Some(class) = rotation {
            session.store.set_rotation(&path, class)?;
        }
        println!("{path}");
    }
    Ok(())
}

/// `ciphr token …`.
fn token(cli: &Context, command: TokenCommand) -> Result<(), CliError> {
    match command {
        TokenCommand::Issue {
            identity,
            ttl,
            force,
        } => {
            // The identity must exist in the policy file. Issuing a token for a name
            // nobody granted anything would produce a credential that authenticates and
            // can do nothing, which is a confusing thing to hand someone.
            let policies = PolicySet::from_toml(&std::fs::read_to_string(&cli.policies)?)?;
            if policies.identity(&identity).is_none() {
                return Err(CliError::UnknownIdentity { name: identity });
            }

            guard_secret_output(force)?;

            let expires_at = ttl
                .as_deref()
                .map(parse_duration_millis)
                .transpose()?
                .map(|millis| now_millis() + millis);

            let mut session = open(cli)?;
            let token = Token::generate()?;
            // The session already derived the pepper when it unsealed; deriving a second
            // one would be one more place for the label to be spelled differently.
            let pepper = std::mem::replace(
                &mut session.pepper,
                ciphr_crypto::TokenPepper::derive(&session.root),
            );
            session
                .store
                .issue_token(&identity, &token, &pepper, "cli", expires_at)?;

            // Printed once, here, and never recoverable afterwards: what the database
            // holds is a verifier, not the token.
            println!("{}", token.expose_text().as_str());
            eprintln!();
            eprintln!("Identity {identity}, token id {}.", token.id());
            match expires_at {
                Some(at) => eprintln!("Expires {}.", ciphr_audit::time::rfc3339_millis(at)),
                None => eprintln!("No expiry. Consider --ttl for anything held by CI."),
            }
            eprintln!("This is the only time the token is shown.");
            Ok(())
        }

        TokenCommand::List { identity } => {
            let session = open(cli)?;
            for record in session.store.tokens(identity.as_deref())? {
                let state = if record.revoked_at.is_some() {
                    "revoked"
                } else if record.expires_at.is_some_and(|at| at <= now_millis()) {
                    "expired"
                } else {
                    "valid"
                };
                println!(
                    "{}  {:<20}  {:<8}  issued {}  {}",
                    record.token_id,
                    record.identity,
                    state,
                    ciphr_audit::time::rfc3339_millis(record.created_at),
                    record.last_used_at.map_or_else(
                        || "never used".to_owned(),
                        |at| format!("last used {}", ciphr_audit::time::rfc3339_millis(at))
                    )
                );
            }
            Ok(())
        }

        TokenCommand::Revoke { token_id } => {
            let mut session = open(cli)?;
            session.store.revoke_token(&token_id)?;
            println!("{token_id} revoked");
            Ok(())
        }

        TokenCommand::RevokeAll { identity } => {
            let mut session = open(cli)?;
            let count = session.store.revoke_identity_tokens(&identity)?;
            println!("{count} token(s) of {identity} revoked");
            Ok(())
        }
    }
}

/// `ciphr audit …`.
fn audit(cli: &Context, command: &AuditCommand) -> Result<(), CliError> {
    let session = open(cli)?;

    match command {
        AuditCommand::Tail { count } => {
            let mut rows = session.store.audit_query(&AuditFilter {
                limit: u32::MAX,
                ..AuditFilter::default()
            })?;
            let start = rows.len().saturating_sub(*count as usize);
            rows.drain(..start);

            for row in rows {
                let record: serde_json::Value = serde_json::from_str(&row.payload)
                    .map_err(|error| CliError::Audit(format!("unreadable record: {error}")))?;
                let entry = &record["entry"];
                println!(
                    "{:>6}  {}  {:<24}  {:<8}  {:<7}  {}",
                    row.seq,
                    record["ts"].as_str().unwrap_or("?"),
                    entry["principal"]["name"].as_str().unwrap_or("-"),
                    entry["action"].as_str().unwrap_or("?"),
                    if entry["allowed"] == true {
                        "allow"
                    } else {
                        "deny"
                    },
                    entry["path"].as_str().unwrap_or("-"),
                );
            }
            Ok(())
        }

        AuditCommand::Verify => {
            let rows = session.store.audit_all()?;
            let verified = verify_from_genesis(rows.iter().map(|row| StoredRecord {
                seq: row.seq,
                payload: &row.payload,
                hash: Some(row.hash),
            }))?;

            println!("{} entries verify", verified.records);
            println!(
                "head {} at sequence {}",
                ciphr_core::hex::encode(&verified.head_hash),
                verified.head_seq
            );
            println!();
            println!("A verified chain shows no entry was removed, edited, or reordered. It does");
            println!("not show that nobody rewrote the whole chain forward, which needs the head");
            println!("hash recorded somewhere outside this store.");
            Ok(())
        }
    }
}

/// `ciphr rotate-master-key`.
fn rotate_master_key(cli: &Context, new_key_variable: &str) -> Result<(), CliError> {
    let mut session = open(cli)?;
    let state = session
        .store
        .seal_state()?
        .ok_or_else(|| CliError::NotInitialized {
            path: cli.database.display().to_string(),
        })?;

    let new_seal = StaticEnvSeal::from_env(new_key_variable)?;
    let rewrapped = new_seal.rewrap(&session.root, state.wrapped_root_key.id)?;

    session.record(&Session::operator_entry(
        Action::RotateMasterKey,
        true,
        None,
    ))?;
    session.store.replace_seal(&SealState {
        seal_id: new_seal.id().to_owned(),
        wrapped_root_key: rewrapped,
    })?;

    println!("the root key is now sealed with the key in {new_key_variable}");
    println!();
    println!("Nothing was re-encrypted: one record changed. Keep the old key until a");
    println!("restart with the new one has been confirmed.");
    Ok(())
}

/// `ciphr dump --format portable` — the exit path.
fn dump(cli: &Context, format: &str, force: bool) -> Result<(), CliError> {
    if format != "portable" {
        return Err(CliError::Duration {
            found: format!("format '{format}'; only 'portable' exists"),
        });
    }
    guard_secret_output(force)?;

    let mut session = open(cli)?;
    let paths = session.store.list(None)?;

    let mut secrets = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = session.store.metadata(&path)?;
        let stored = session.store.get(&path, None)?;
        let plaintext =
            ciphr_crypto::decrypt(&session.root, &stored.path, stored.version, &stored.value)?;
        let value = String::from_utf8(plaintext.expose().to_vec())
            .map_err(|_| CliError::Audit(format!("{path} is not valid UTF-8")))?;

        session.record(
            &Session::operator_entry(Action::Read, true, None)
                .with_path(&stored.path)
                .with_version(stored.version),
        )?;

        secrets.push(serde_json::json!({
            "path": stored.path.as_str(),
            "version": stored.version.get(),
            "rotation": metadata.rotation.as_str(),
            "created_at": stored.created_at,
            "created_by": stored.created_by,
            "value": value,
        }));
    }

    // A neutral, self-describing document. This is the insurance against the scenario
    // in the plan: if this project ever struggles at the crypto or authorization layer,
    // moving to OpenBao must not fail because of a proprietary file format.
    let document = serde_json::json!({
        "format": "ciphr.portable.v1",
        "exported_at": ciphr_audit::time::rfc3339_millis(now_millis()),
        "note": "Every value below is plaintext. Treat this file as the secret store itself.",
        "secrets": secrets,
    });

    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Audit(format!("could not produce JSON: {error}"))
    }
}
