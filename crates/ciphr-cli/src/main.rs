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

use ciphr_audit::{Action, Anchor, StoredRecord, verify_from, verify_with_anchor};
use ciphr_core::{Plaintext, Rotation, SecretPath, SecretVersion};
use ciphr_crypto::{RootKey, RootKeyId, Seal, StaticSeal, Token};
use ciphr_policy::PolicySet;
use ciphr_store::{AuditFilter, SealState, SqliteAuditDevice, SqliteStore, Store};
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

    /// File holding the master key, such as a secret mounted at /run/secrets.
    ///
    /// Preferred over the variable where the deployment allows it: the key then stays out
    /// of the container configuration and out of /proc/<pid>/environ.
    #[arg(long, global = true, conflicts_with = "master_key_env")]
    master_key_file: Option<PathBuf>,

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
        /// Only paths in this rotation class.
        ///
        /// `--rotation unclassified` is the one that answers "what has nobody
        /// looked at yet?", which is the question the class exists for.
        #[arg(long)]
        rotation: Option<String>,
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

    /// Show or set how safe a secret is to rotate.
    Rotation {
        /// Which secret.
        path: String,
        /// One of: unclassified, rotatable, seed-only, breaks-data, volume-bound,
        /// invalidates-sessions. Omit it to read the current class instead.
        class: Option<String>,
    },

    /// Export several secrets in one of the consumable formats.
    Export(ExportArgs),

    /// Import a `.env` file.
    Import(ImportArgs),

    /// Tokens.
    #[command(subcommand)]
    Token(TokenCommand),

    /// Bait, and the trips it has produced (ADR-15).
    #[command(subcommand)]
    Honeypot(HoneypotCommand),

    /// What optional surface this binary can offer (ADR-20).
    #[command(subcommand)]
    Surface(SurfaceCommand),

    /// The audit trail.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Re-wrap the root key under a new master key.
    RotateMasterKey {
        /// Environment variable holding the new master key.
        #[arg(long, required_unless_present = "new_key_file")]
        new_key_env: Option<String>,
        /// File holding the new master key.
        #[arg(long, conflicts_with = "new_key_env")]
        new_key_file: Option<PathBuf>,
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
    #[arg(long, required_unless_present = "stdin", conflicts_with = "stdin")]
    from_dotenv: Option<PathBuf>,
    /// Read the same format from standard input instead of a file.
    ///
    /// For a corpus that has no `.env` on disk and should not acquire one: the
    /// values can be piped in from wherever they actually live. It parses
    /// exactly what `--from-dotenv` parses.
    #[arg(long)]
    stdin: bool,
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

/// `ciphr surface …` — what this binary can offer beyond the core (ADR-20).
///
/// There is deliberately no `enable`. For a *build* entry, enabling means choosing a
/// binary compiled with the feature and writing a `[[surface]]` stanza into the server's
/// configuration — and a command that edited that file would be writing to something a
/// deployment may well mount read-only, in a repository that keeps it under version
/// control. The switch is a deployment change, and this shows what the choice costs.
#[derive(Debug, Subcommand)]
enum SurfaceCommand {
    /// Show what a server configuration turned on, and what each entry costs.
    Show {
        /// Path to the server's configuration file, the one with the `[[surface]]`
        /// stanzas in it.
        config: String,
    },
}

/// `ciphr honeypot …` — bait, and the trips it has produced (ADR-15).
///
/// On the host and nowhere else. There is no route that marks bait and none that clears
/// a trip, for the reason ADR-3 gives policies and ADR-15 gives its own clearing: a
/// guard reachable through the door it guards is not a guard.
#[derive(Debug, Subcommand)]
enum HoneypotCommand {
    /// Mark an existing secret as bait.
    ///
    /// The path must already hold a real-looking value. A tier on an empty path is bait
    /// that answers 404 to whoever takes it.
    ///
    /// **Where it goes matters more than that it exists.** Bait belongs outside every
    /// prefix any consumer fetches -- `ciphr-run --prefix`, `client.environment(prefix)`
    /// and anything built on `POST /v1/export` read the *value* of every path under a
    /// prefix, so bait under one trips on every service start. Under a
    /// `infra/<host>/<service>/<KEY>` scheme that means a `<service>` level nobody
    /// deploys, and never beside the real secrets of a real service.
    Add {
        /// The path to mark.
        path: String,
    },
    /// Remove the mark, leaving the secret in place.
    Remove {
        /// The path to unmark.
        path: String,
    },
    /// Show every piece of bait and whether it has been taken.
    ///
    /// The only place bait is visible. It never appears in `list`, in `versions`, or on
    /// any value path: an operator has to be able to tell bait from a real secret, and a
    /// caller must not.
    List,
    /// Clear every open trip, so the bait can fire again.
    ///
    /// Sets a cleared timestamp rather than deleting anything: what an investigation
    /// wants is exactly the part a delete would remove. Never on a timer and never
    /// through the API -- a tripwire that resets quietly has, in effect, not fired.
    Clear,
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
        /// Plant bait instead of a credential (ADR-15).
        ///
        /// The token is generated, stored and printed exactly as a real one, and
        /// authenticates nothing. Plant it where a credential should not be but often
        /// is -- an old `.env` on a host, a job log, a wiki page. Presenting it proves
        /// somebody read something they should not have.
        ///
        /// The identity is still required and still has to exist: it is what names
        /// *which* bait was taken in the audit trail. Nothing is granted by it.
        #[arg(long)]
        honeypot: bool,
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
    Verify {
        /// Also check the chain against the newest anchor in this file.
        ///
        /// Without it, verification proves that no entry was removed, edited, or
        /// reordered. With it, it also proves the chain was not rewritten forward up
        /// to the anchored sequence — which is the part no amount of reading the store
        /// can establish.
        #[arg(long, value_name = "FILE")]
        anchor: Option<PathBuf>,
    },
    /// Record the current head of the chain, for keeping outside this store.
    ///
    /// Writes one JSON line to standard output, and appends it to `--out` if given.
    /// The point of an anchor is that the copy lives somewhere the writer of this
    /// store does not control, so the file belongs on another host or in a backup —
    /// next to the database it buys nothing.
    ///
    /// Reads without taking the store lock and without the master key, so it can run
    /// while the server does. It records no audit entry of its own: an entry would
    /// move the head it just wrote down, and it would need the write lock, which the
    /// running server holds.
    Anchor {
        /// Append the anchor to this file, creating it if necessary.
        ///
        /// If the file already holds anchors, the newest one is checked against the
        /// chain first, and nothing is appended if it does not hold. An anchor written
        /// over a contradiction would give a rewrite a fresh alibi.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Bound the queryable trail: remove the oldest entries, keeping the newest.
    ///
    /// The trail grows for as long as the store exists, and because auditing is
    /// fail-closed a full volume stops the service serving secrets. This is the command
    /// that bounds it — and the reason it is a command rather than something the service
    /// does on a schedule is that a cut has to be anchored outside the store, and the
    /// service is the thing an anchor exists to be independent of.
    ///
    /// Three things happen, in this order, and each one gates the next:
    ///
    /// 1. The chain is verified, including against the anchors already in `--anchor`.
    /// 2. Every record about to be removed is looked for in `--archive`, by hash.
    /// 3. The anchor at the cut is appended and synced, the records are removed, and a
    ///    fresh anchor over what remains is appended.
    ///
    /// A refusal at any point leaves the trail exactly as it was.
    Cut {
        /// How many of the newest entries stay queryable.
        ///
        /// A count rather than an age. The bound this answers is the size of the
        /// queryable device, and a time-based rule pointed at a hash chain removes a
        /// varying number of records for reasons unrelated to how large the table is.
        /// Age-based retention belongs on the archive, where the host's log tooling
        /// already does it.
        #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(u64).range(1..))]
        keep: u64,

        /// The anchor file, as for `audit anchor --out`. Required.
        ///
        /// Removing the oldest records leaves a chain that no longer starts at sequence
        /// one, so what remains can only be verified from the point the cut ended at.
        /// Without that point recorded outside this store, the remainder rests on the
        /// store's own claim about what it removed — which is exactly what a deletion
        /// dressed up as retention would write.
        #[arg(long, value_name = "FILE")]
        anchor: PathBuf,

        /// The file device's audit file, where the removed records must already be.
        ///
        /// Its rotated siblings are read as well. Every record the cut would remove has
        /// to appear there byte for byte, or the cut is refused: the queryable copy may
        /// be bounded, the evidence may not be thrown away.
        #[arg(long, value_name = "FILE", required_unless_present = "assume_archived")]
        archive: Option<PathBuf>,

        /// Cut without checking that the removed records are archived anywhere.
        ///
        /// For a deployment whose audit lines are shipped off the host as they are
        /// written, or whose rotated files are compressed and therefore unreadable here.
        /// It replaces a check with an assumption, and says so on every run.
        #[arg(long, conflicts_with = "archive")]
        assume_archived: bool,

        /// Report what would be removed, and remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
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
    master_key_file: Option<PathBuf>,
    policies: PathBuf,
    audit_file: Option<PathBuf>,
}

impl Context {
    /// Build the seal from whichever source was configured.
    ///
    /// Resolved in one place so that every command reads the key the same way, and so
    /// that adding a third source later is one change rather than one per command.
    ///
    /// clap rejects both flags together, so there is no precedence rule to get wrong:
    /// a deployment cannot end up using the source nobody thought was active.
    fn seal(&self) -> Result<StaticSeal, CliError> {
        match &self.master_key_file {
            Some(path) => Ok(StaticSeal::from_file(path)?),
            None => Ok(StaticSeal::from_env(&self.master_key_env)?),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<(), CliError> {
    let Cli {
        database,
        master_key_env,
        master_key_file,
        policies,
        audit_file,
        command,
    } = cli;
    let cli = Context {
        database,
        master_key_env,
        master_key_file,
        policies,
        audit_file,
    };

    match command {
        Command::Init => init(&cli),

        Command::Put { path, rotation } => {
            let path = SecretPath::parse(&path)?;
            // Refused before the value is read and before anything is recorded, the
            // same way a malformed path is. The store refuses it too, and that is
            // where the rule lives; checking here keeps the trail from carrying an
            // allowed write that storage was always going to turn down.
            ciphr_store::reject_reserved(&path)?;
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
                classify(&mut session, &path, class)?;
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

        Command::List { prefix, rotation } => {
            let prefix = prefix.as_deref().map(SecretPath::parse).transpose()?;
            let wanted = rotation.as_deref().map(Rotation::parse).transpose()?;
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
                // The filter reads metadata the listing already authorized, and
                // metadata is not a value: no decryption happens here and the
                // master key is not involved.
                if let Some(wanted) = wanted
                    && session.store.metadata(&path)?.rotation != wanted
                {
                    continue;
                }
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
            ciphr_store::reject_reserved(&path)?;
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
            let mut session = open(&cli)?;

            let class = match class {
                // Reading a class is a metadata listing, like `versions`.
                None => {
                    session.record(
                        &Session::operator_entry(Action::List, true, None).with_path(&path),
                    )?;
                    session.store.metadata(&path)?.rotation
                }
                // Changing one gets its own action. A reclassification produces no
                // version, so folding it into `write` would hide it among the
                // value writes -- and a downgrade to `rotatable` is the step that
                // comes immediately before a rotation that destroys data.
                Some(class) => {
                    let class = Rotation::parse(&class)?;
                    classify(&mut session, &path, class)?;
                    class
                }
            };

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
        Command::Honeypot(command) => honeypot(&cli, command),
        Command::Surface(command) => surface(&command),
        Command::Audit(command) => audit(&cli, &command),
        Command::RotateMasterKey {
            new_key_env,
            new_key_file,
        } => rotate_master_key(&cli, new_key_env.as_deref(), new_key_file.as_deref()),
        Command::Dump { format, force } => dump(&cli, &format, force),
    }
}

/// Open the store, unseal it, and attach the audit devices.
fn open(cli: &Context) -> Result<Session, CliError> {
    Session::open(&cli.database, &cli.seal()?)?.with_audit(cli.audit_file.as_deref())
}

/// `ciphr init` — generate a root key and seal it.
fn init(cli: &Context) -> Result<(), CliError> {
    let database = cli.database.as_path();
    let mut store = SqliteStore::open(database)?;
    if store.seal_state()?.is_some() {
        return Err(CliError::AlreadyInitialized {
            path: database.display().to_string(),
        });
    }

    let seal = cli.seal()?;
    let root = RootKey::generate()?;
    let root_id = RootKeyId::generate()?;

    store.initialize(&SealState {
        seal_id: seal.id().to_owned(),
        wrapped_root_key: seal.rewrap(&root, root_id)?,
    })?;

    // The first audit entry of a store is its own creation, which is what makes the
    // chain start at something rather than at nothing.
    //
    // It has to reach the file device too, and passing `None` here meant it never did:
    // every store's `audit.jsonl` began at sequence 2, whose `prev_hash` names a record
    // the file does not contain. The archived copy was therefore not verifiable from its
    // own beginning -- which is the only thing an archived hash chain is for. Measured on
    // a deployed store before it was noticed in the code, and unfixable there afterwards,
    // because a chain is precisely what cannot be amended.
    let mut session = Session::open(database, &seal)?.with_audit(cli.audit_file.as_deref())?;
    session.record(&Session::operator_entry(Action::Init, true, None))?;

    println!("initialized {}", database.display());
    println!(
        "root key {root_id}, sealed with {} from {}",
        seal.id(),
        seal.source()
    );
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
        // Names are assigned before anything is printed, so an export refused for a
        // collision has emitted neither a mask nor an assignment.
        let (masks, assignments) = render_actions_env(&secrets)?;
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
        print!("{}", format.render(&secrets)?);
    }

    Ok(())
}

/// Set a rotation class, and record that somebody did.
///
/// One function because this drifted once already, in the direction that matters: the
/// standalone `ciphr rotation` recorded the change while `put --rotation` and
/// `import --rotation` made the same change silently, and the documentation described
/// the audited behaviour for all three. A secret classified `breaks-data` could then be
/// downgraded to `rotatable` by a `put`, leaving a `write` entry and nothing that says
/// the classification moved -- immediately before the rotation that destroys the data.
///
/// Recorded before the change, like every other mutation here: a failure to record
/// leaves the store as it was.
fn classify(session: &mut Session, path: &SecretPath, class: Rotation) -> Result<(), CliError> {
    session.record(&Session::operator_entry(Action::Classify, true, None).with_path(path))?;
    session.store.set_rotation(path, class)?;
    Ok(())
}

/// `ciphr import --from-dotenv`.
fn import(cli: &Context, args: &ImportArgs) -> Result<(), CliError> {
    let prefix = SecretPath::parse(&args.prefix)?;
    let rotation = args.rotation.as_deref().map(Rotation::parse).transpose()?;
    // One parser for both sources: a second one is a second set of quoting rules
    // to get wrong, and the two would drift in exactly the way that puts a stray
    // quote character inside a stored secret.
    let text = if let Some(path) = &args.from_dotenv {
        std::fs::read_to_string(path)?
    } else {
        // Refused at a terminal, like every other standard-input read here. Without
        // this the command waits with no prompt and no output, and whatever the
        // operator types before Ctrl-D is parsed as a `.env` file.
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(CliError::NeedsStdin);
        }
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        text
    };
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
            classify(&mut session, &path, class)?;
        }
        println!("{path}");
    }
    Ok(())
}

/// `ciphr token issue`.
///
/// Its own function because it is the longest of the token commands and the only
/// one that both creates a credential and prints it -- keeping it inline pushed
/// `token` past the length this workspace lints for, and the lint was right.
fn issue_token(
    cli: &Context,
    identity: String,
    ttl: Option<&str>,
    force: bool,
    honeypot: bool,
) -> Result<(), CliError> {
    // The identity must exist in the policy file. Issuing a token for a name
    // nobody granted anything would produce a credential that authenticates and
    // can do nothing, which is a confusing thing to hand someone.
    let policies = PolicySet::from_toml(&std::fs::read_to_string(&cli.policies)?)?;
    if policies.identity(&identity).is_none() {
        return Err(CliError::UnknownIdentity { name: identity });
    }

    guard_secret_output(force)?;

    let expires_at = ttl
        .map(parse_duration_millis)
        .transpose()?
        .map(|millis| now_millis() + millis);

    let kind = policies
        .identity(&identity)
        .map(|found| found.kind().as_str().to_owned());

    let mut session = open(cli)?;
    let token = Token::generate()?;
    // The session already derived the pepper when it unsealed; deriving a second
    // one would be one more place for the label to be spelled differently.
    let pepper = std::mem::replace(
        &mut session.pepper,
        ciphr_crypto::TokenPepper::derive(&session.root),
    );
    // Recorded before the row exists, like every other mutation here. The
    // subject is the identity and the token's non-secret id -- the same id
    // every later access made with this credential will carry, which is what
    // lets a reader join the two.
    session.record(
        &Session::operator_entry(Action::IssueToken, true, None).with_subject(
            ciphr_audit::Principal {
                name: identity.clone(),
                kind,
                token_id: Some(token.id().as_text().clone()),
            },
        ),
    )?;
    session.store.issue_token(
        &identity,
        &token,
        &pepper,
        "cli",
        expires_at,
        if honeypot {
            ciphr_store::TokenPurpose::Honeypot
        } else {
            ciphr_store::TokenPurpose::Credential
        },
    )?;

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
    if honeypot {
        eprintln!();
        eprintln!("This is bait. It authenticates nothing, and presenting it is recorded");
        eprintln!("as honeypot-triggered. Plant it where a credential should not be but");
        eprintln!("often is -- and not where a consumer might pick it up by mistake.");
        eprintln!();
        eprintln!("Detection needs the service built with --features honeypot_alert and a");
        eprintln!("[[surface]] stanza naming it. Without both, taking this bait is recorded");
        eprintln!("as an ordinary rejected credential and nothing pages.");
    }
    Ok(())
}

/// `ciphr surface …`.
///
/// Takes no store and no policy file: what a binary contains is a property of the
/// binary, and asking a database about it would be asking the wrong thing.
fn surface(command: &SurfaceCommand) -> Result<(), CliError> {
    let SurfaceCommand::Show { config } = command;

    let text = std::fs::read_to_string(config)?;
    let stanzas = parse_surface_stanzas(config, &text)?;

    // **This reads a file, not a binary, and the difference is the whole caveat.** For a
    // build entry, a stanza is one half of being switched on and the compiled feature is
    // the other; the server refuses to start when the two disagree, but nothing here can
    // see the server's build. So this says what the deployment *asked for*, and points at
    // the endpoint that says what it got.
    if stanzas.is_empty() {
        eprintln!("{config} turns nothing on. That is the ordinary configuration.");
        return Ok(());
    }

    for (entry, accepted, reason) in &stanzas {
        println!("{entry}");
        println!("    accepted  {accepted}");
        println!("    reason    {reason}");
        match cost_of(entry) {
            Some(cost) => {
                println!("    without it:");
                for line in wrap_cost(cost) {
                    println!("        {line}");
                }
            }
            // A name this CLI does not know: either the configuration is for a newer
            // service, or it is a typo the server will refuse at startup. Saying so is
            // more useful than printing nothing.
            None => println!("    without it: unknown to this CLI build"),
        }
        println!();
    }

    eprintln!("A build entry needs the feature compiled in as well as a stanza, and the");
    eprintln!("service refuses to start when the two disagree. Ask that service's");
    eprintln!("/v1/health for the entries it actually contains.");
    Ok(())
}

/// The `[[surface]]` stanzas of a server configuration.
///
/// Parsed loosely on purpose: the strict typed load lives in `ciphr-server`, and
/// duplicating it here would mean a second definition of the same schema that can drift
/// from the one that decides whether the service starts. This reads three strings and
/// leaves every judgement to the server.
fn parse_surface_stanzas(
    path: &str,
    text: &str,
) -> Result<Vec<(String, String, String)>, CliError> {
    let document = toml::from_str::<toml::Value>(text).map_err(|error| CliError::Config {
        path: path.to_owned(),
        reason: error.to_string(),
    })?;
    let Some(entries) = document.get("surface").and_then(toml::Value::as_array) else {
        return Ok(Vec::new());
    };

    let field = |value: &toml::Value, name: &str| {
        value
            .get(name)
            .and_then(toml::Value::as_str)
            .unwrap_or("(missing)")
            .to_owned()
    };
    Ok(entries
        .iter()
        .map(|value| {
            (
                field(value, "entry"),
                field(value, "accepted"),
                field(value, "reason"),
            )
        })
        .collect())
}

/// What an entry's absence costs, from the record that owns it.
///
/// Duplicated from `ciphr-server`'s entry list rather than imported: the CLI does not
/// depend on the server crate and should not start, because that crate pulls in axum,
/// rustls and a tokio runtime and none of those belong in a host tool. The duplication
/// can drift, and what bounds it is that the list is one row long -- if it grows, that is
/// the moment to move the list into `ciphr-core` as data rather than to copy it twice.
fn cost_of(entry: &str) -> Option<&'static str> {
    match entry {
        "honeypot_alert" => Some(
            "No detection of bait. A deployment that plants none pays nothing for the              absence, and gets the strongest form of ADR-15's indistinguishability claim:              code that is not compiled in has no timing to get wrong.",
        ),
        _ => None,
    }
}

/// Break a cost sentence into terminal-width lines.
fn wrap_cost(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > 72 {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// `ciphr honeypot …`.
fn honeypot(cli: &Context, command: HoneypotCommand) -> Result<(), CliError> {
    match command {
        HoneypotCommand::Add { path } => set_bait(cli, &path, true),
        HoneypotCommand::Remove { path } => set_bait(cli, &path, false),
        HoneypotCommand::List => {
            let session = open(cli)?;
            let bait = session.store.honeypots()?;
            if bait.is_empty() {
                eprintln!("No bait planted.");
                return Ok(());
            }
            for entry in bait {
                let what = match (&entry.path, &entry.token_id) {
                    (Some(path), _) => format!("secret {path}"),
                    (None, Some(id)) => format!(
                        "token  {id} for {}",
                        entry.identity.as_deref().unwrap_or("?")
                    ),
                    (None, None) => "?".to_owned(),
                };
                let state = if entry.tripped { "TAKEN" } else { "quiet" };
                println!("{state:<6} {:<6} {what}", entry.tier.as_str());
            }
            Ok(())
        }
        HoneypotCommand::Clear => {
            let mut session = open(cli)?;
            // Recorded before the change, like every other mutation here. A cleared
            // tripwire is an operational decision and the trail is where it belongs --
            // clearing without a record is how an incident becomes a blip in a graph
            // nobody kept.
            session.record(&Session::operator_entry(
                Action::HoneypotCleared,
                true,
                None,
            ))?;
            let cleared = session.store.clear_trips()?;
            match cleared {
                0 => eprintln!("Nothing was tripped."),
                1 => eprintln!("One trip cleared. The bait can fire again."),
                many => eprintln!("{many} trips cleared. The bait can fire again."),
            }
            Ok(())
        }
    }
}

/// Mark a secret as bait, or remove the mark.
fn set_bait(cli: &Context, path: &str, bait: bool) -> Result<(), CliError> {
    let parsed = SecretPath::parse(path)?;
    let mut session = open(cli)?;

    // The secret has to exist first, and the message says why rather than reporting a
    // bare "not found": a tier on an empty path is the one mistake that produces bait
    // nobody can take.
    if session.store.metadata(&parsed).is_err() {
        return Err(CliError::BaitNeedsASecret {
            path: path.to_owned(),
        });
    }

    session.record(
        &Session::operator_entry(Action::HoneypotMarked, true, None)
            .with_path(&parsed)
            .with_detail(if bait { "marked" } else { "unmarked" }),
    )?;
    session.store.set_honeypot(
        &parsed,
        if bait {
            Some(ciphr_store::HoneypotTier::Alert)
        } else {
            None
        },
    )?;

    if bait {
        eprintln!("{path} is bait, tier alert.");
        eprintln!();
        eprintln!("It must sit outside every prefix a consumer fetches. A prefix fetch reads");
        eprintln!("the value of every path under it, so bait under one trips on every service");
        eprintln!("start -- see `ciphr honeypot add --help`.");
        eprintln!();
        eprintln!("Detection needs the service built with --features honeypot_alert and a");
        eprintln!("[[surface]] stanza naming it.");
    } else {
        eprintln!("{path} is no longer bait. The secret itself is unchanged.");
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
            honeypot,
        } => issue_token(cli, identity, ttl.as_deref(), force, honeypot),
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
            // Looked up first so that a revocation of a token that does not exist
            // is refused without recording one that never happened. The store
            // refuses it too; recording afterwards would put the claim in the trail
            // before the refusal.
            let identity = session
                .store
                .tokens(None)?
                .into_iter()
                .find(|record| record.token_id == token_id)
                .map(|record| record.identity);
            let Some(identity) = identity else {
                return Err(CliError::Store(ciphr_store::StoreError::TokenNotFound {
                    token_id: token_id.clone(),
                }));
            };
            session.record(
                &Session::operator_entry(Action::RevokeToken, true, None).with_subject(
                    ciphr_audit::Principal {
                        name: identity,
                        kind: None,
                        token_id: Some(token_id.clone()),
                    },
                ),
            )?;
            session.store.revoke_token(&token_id)?;
            println!("{token_id} revoked");
            Ok(())
        }

        TokenCommand::RevokeAll { identity } => {
            let mut session = open(cli)?;

            // One entry per token rather than one for the batch. The question asked
            // afterwards is "when did *this* credential stop working", and a single
            // entry carrying a count cannot answer it. Only the tokens this call
            // will actually revoke: an already-revoked one is not revoked again, and
            // recording it would put an event in the trail that did not happen.
            let revoking: Vec<String> = session
                .store
                .tokens(Some(&identity))?
                .into_iter()
                .filter(|record| record.revoked_at.is_none())
                .map(|record| record.token_id)
                .collect();

            for token_id in &revoking {
                session.record(
                    &Session::operator_entry(Action::RevokeToken, true, None).with_subject(
                        ciphr_audit::Principal {
                            name: identity.clone(),
                            kind: None,
                            token_id: Some(token_id.clone()),
                        },
                    ),
                )?;
            }

            let count = session.store.revoke_identity_tokens(&identity)?;
            debug_assert_eq!(count, revoking.len(), "the lock makes these agree");
            println!("{count} token(s) of {identity} revoked");
            Ok(())
        }
    }
}

/// `ciphr audit …`.
fn audit(cli: &Context, command: &AuditCommand) -> Result<(), CliError> {
    // Verifying and anchoring read the trail and write nothing, so they neither unseal
    // the store nor take its lock. That is what lets them run against a live service,
    // which is when a check is worth having. `tail` still goes through a session,
    // because it is the browsing command and shares the session's output guards.
    match command {
        AuditCommand::Verify { anchor } => return verify_chain(cli, anchor.as_deref()),
        AuditCommand::Anchor { out } => return take_anchor(cli, out.as_deref()),
        AuditCommand::Cut {
            keep,
            anchor,
            archive,
            assume_archived,
            dry_run,
        } => {
            return cut_trail(
                cli,
                *keep,
                anchor,
                archive.as_deref(),
                *assume_archived,
                *dry_run,
            );
        }
        AuditCommand::Tail { .. } => {}
    }

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
                // The last column is whatever the action was about: a path for the
                // secret actions, and for the token actions the identity and the
                // token's id. Without it `issue-token allow -` says that a
                // credential was created and refuses to say for whom, which is the
                // one thing somebody reading this line needs.
                let about = match entry["path"].as_str() {
                    Some(path) => path.to_owned(),
                    None => match entry["subject"]["name"].as_str() {
                        Some(name) => match entry["subject"]["token_id"].as_str() {
                            Some(token_id) => format!("{name} ({token_id})"),
                            None => name.to_owned(),
                        },
                        None => "-".to_owned(),
                    },
                };
                println!(
                    "{:>6}  {}  {:<24}  {:<13}  {:<7}  {}",
                    row.seq,
                    record["ts"].as_str().unwrap_or("?"),
                    entry["principal"]["name"].as_str().unwrap_or("-"),
                    entry["action"].as_str().unwrap_or("?"),
                    if entry["allowed"] == true {
                        "allow"
                    } else {
                        "deny"
                    },
                    about,
                );
            }
            Ok(())
        }

        AuditCommand::Verify { .. } | AuditCommand::Anchor { .. } | AuditCommand::Cut { .. } => {
            // Handled above, before the session was opened.
            Ok(())
        }
    }
}

/// The stored chain, as verification wants it.
///
/// The stored hash is passed along as well as the payload: a stored hash that
/// disagrees with its own record is evidence in itself, and dropping it here would
/// discard that.
fn stored_records(rows: &[ciphr_store::AuditRow]) -> Vec<StoredRecord<'_>> {
    rows.iter()
        .map(|row| StoredRecord {
            seq: row.seq,
            payload: &row.payload,
            hash: Some(row.hash),
        })
        .collect()
}

/// `ciphr audit verify [--anchor FILE]`.
fn verify_chain(cli: &Context, anchor_file: Option<&std::path::Path>) -> Result<(), CliError> {
    let store = SqliteStore::open_read_only(&cli.database)?;
    let rows = store.audit_all()?;
    let records = stored_records(&rows);
    let cut = store.audit_cut_latest()?;
    let start = store.audit_start()?;

    let anchor = match anchor_file {
        None => None,
        Some(path) => Some(read_anchor(path)?),
    };

    // The anchor taken at the cut, if this file holds it. It is a different check from
    // the newest anchor: this one pins the store's claim about what it removed, and the
    // newest one pins a record that is still here.
    let at_cut = match (&cut, anchor_file) {
        (Some(cut), Some(path)) => anchor_at(path, cut.seq)?,
        _ => None,
    };

    let verified = match &anchor {
        None => verify_from(start, records.iter().copied())?,
        Some(anchor) => verify_with_anchor(anchor, start, &records)?,
    };
    if let Some(at_cut) = &at_cut {
        verify_with_anchor(at_cut, start, &records)?;
    }

    println!("{} entries verify", verified.records);
    println!(
        "head {} at sequence {}",
        ciphr_core::hex::encode(&verified.head_hash),
        verified.head_seq
    );
    if let Some(cut) = &cut {
        println!(
            "the trail begins at sequence {} — cut on {}, {} entries removed",
            start.first_seq(),
            ciphr_audit::time::rfc3339_millis(cut.cut_at),
            cut.removed
        );
    }
    println!();

    match &anchor {
        None => {
            println!("A verified chain shows no entry was removed, edited, or reordered. It does");
            println!("not show that nobody rewrote the whole chain forward, which needs the head");
            println!("hash recorded somewhere outside this store: see `ciphr audit anchor`.");
        }
        Some(anchor) => {
            println!(
                "The chain also agrees with the anchor taken at {} for sequence {}, so it was",
                anchor.taken_at, anchor.seq
            );
            println!(
                "not rewritten up to that record. Records after sequence {} rest on the chain",
                anchor.seq
            );
            println!("alone until the next anchor is taken.");
        }
    }

    if let Some(cut) = &cut {
        println!();
        if let Some(at_cut) = &at_cut {
            println!(
                "The recorded cut agrees with the anchor taken at {} for the same sequence, so",
                at_cut.taken_at
            );
            println!("the point this trail is verified from comes from outside the store as well.");
        } else {
            println!("Nothing here checks the recorded cut itself. It is a row in the store,");
            println!("written by whatever can write the store, and everything above rests on it");
            println!(
                "being the truth about sequence {}. The anchor the cut appended is what",
                cut.seq
            );
            println!("settles that — pass the file it went to as --anchor.");
            if let Some(path) = &cut.anchor {
                println!("The cut recorded that file as {path}.");
            }
        }
    }
    Ok(())
}

/// `ciphr audit anchor [--out FILE]`.
fn take_anchor(cli: &Context, out: Option<&std::path::Path>) -> Result<(), CliError> {
    let store = SqliteStore::open_read_only(&cli.database)?;
    let rows = store.audit_all()?;
    let records = stored_records(&rows);
    let start = store.audit_start()?;

    // An anchor appended over a chain that contradicts the previous one would hand a
    // rewrite a fresh alibi, so the existing evidence is checked before more is added.
    let previous = match out {
        None => None,
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => Anchor::latest(&text)
                .map_err(|error| CliError::Audit(format!("{}: {error}", path.display())))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(CliError::Io(error)),
        },
    };

    let verified = match &previous {
        None => verify_from(start, records.iter().copied())?,
        Some(anchor) => verify_with_anchor(anchor, start, &records)?,
    };

    if verified.head_seq == 0 {
        return Err(CliError::Audit(
            "the chain is empty, so there is no head to anchor".to_owned(),
        ));
    }

    let anchor = Anchor::over(&verified, now_millis());
    let line = anchor.encode();

    if let Some(path) = out {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(CliError::Io)?;
        writeln!(file, "{line}").map_err(CliError::Io)?;
        // Anchors are evidence about writes that already happened. Losing the newest
        // one to a power failure would leave the trail unanchored without anyone
        // noticing, so the write is pushed to the device before the command reports
        // success.
        file.sync_all().map_err(CliError::Io)?;
    }

    // The record goes to standard output alone, so that a scheduled job can pipe it
    // somewhere without filtering prose out of it. Everything a person needs goes to
    // standard error.
    println!("{line}");

    eprintln!(
        "anchored sequence {} over {} verified entries",
        anchor.seq, verified.records
    );
    match out {
        Some(path) => eprintln!("appended to {}", path.display()),
        None => eprintln!(
            "not written to a file: pass --out, and keep it where this store's writer cannot reach"
        ),
    }
    if let Some(previous) = &previous {
        eprintln!(
            "the previous anchor, sequence {} from {}, still holds",
            previous.seq, previous.taken_at
        );
    }
    Ok(())
}

/// The newest anchor in a file, or an error saying the file has none.
fn read_anchor(path: &std::path::Path) -> Result<Anchor, CliError> {
    let text = std::fs::read_to_string(path).map_err(CliError::Io)?;
    Anchor::latest(&text)
        .map_err(|error| CliError::Audit(format!("{}: {error}", path.display())))?
        .ok_or_else(|| {
            CliError::Audit(format!(
                "{} holds no anchor record; run `ciphr audit anchor --out` first",
                path.display()
            ))
        })
}

/// The anchor in a file for one sequence number, if it holds one.
///
/// Unlike [`read_anchor`], an unreadable line is skipped rather than fatal: this is a
/// search through a file that may hold anchors from several formats and several years,
/// and the answer wanted is "is the one for this sequence here".
fn anchor_at(path: &std::path::Path, seq: u64) -> Result<Option<Anchor>, CliError> {
    let text = std::fs::read_to_string(path).map_err(CliError::Io)?;
    Ok(text
        .lines()
        .filter_map(|line| Anchor::parse(line).ok())
        .find(|anchor| anchor.seq == seq))
}

/// Append one anchor to a file, creating it if necessary, and get it onto the disk.
fn append_anchor(path: &std::path::Path, anchor: &Anchor) -> Result<String, CliError> {
    let line = anchor.encode();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(CliError::Io)?;
    writeln!(file, "{line}").map_err(CliError::Io)?;
    // The anchor at a cut is the only thing that makes the remainder verifiable, and it
    // is written before the records go. A buffered write would mean the delete could be
    // durable while the anchor was not.
    file.sync_all().map_err(CliError::Io)?;
    Ok(line)
}

/// A refusal to cut, in the words the store uses for its own refusals.
///
/// Whether the reason was found here or in the store, an operator needs to read the same
/// sentence: the log was not cut, and why. [`CliError::Audit`] is the wrong vocabulary
/// for it — that one means a record could not be written.
fn cut_refused(detail: String) -> CliError {
    CliError::Store(ciphr_store::StoreError::CutRefused { detail })
}

/// Establish that the records a cut would remove exist outside the queryable device.
///
/// The queryable copy may be bounded; the evidence may not be thrown away. Either the
/// archive is read and every record is found in it, or the caller has said in so many
/// words that it is trusting something this command cannot see.
fn require_archived(
    archive: Option<&std::path::Path>,
    assume_archived: bool,
    removing: &[StoredRecord<'_>],
) -> Result<(), CliError> {
    let count = removing.len();

    let Some(path) = archive else {
        assert!(assume_archived, "clap requires one of the two");
        eprintln!(
            "--assume-archived: nothing here checked that the {count} entries about to be removed"
        );
        eprintln!("exist anywhere else. If they do not, this destroys them permanently.");
        return Ok(());
    };

    let files = ciphr_audit::rotation_set(path).map_err(CliError::Io)?;
    let coverage =
        ciphr_audit::coverage_of(&files, removing.iter().copied()).map_err(CliError::Io)?;

    if !coverage.is_complete() {
        let missing = coverage.missing();
        let shown: Vec<String> = missing.iter().take(5).map(u64::to_string).collect();
        return Err(cut_refused(format!(
            "{} of the {count} entries to be removed are not in the archive at {} ({} file(s), \
             {} lines read); the first missing sequence numbers are {}. Cutting would destroy \
             them. Point --archive at the file device's file, decompress rotated files it \
             cannot read, or pass --assume-archived if the lines are shipped off this host as \
             they are written.",
            missing.len(),
            path.display(),
            coverage.files_read(),
            coverage.lines_read(),
            shown.join(", ")
        )));
    }

    eprintln!(
        "archive: all {count} entries found in {} file(s) at {}",
        coverage.files_read(),
        path.display()
    );
    Ok(())
}

/// `ciphr audit cut --keep N --anchor FILE (--archive FILE | --assume-archived)`.
fn cut_trail(
    cli: &Context,
    keep: u64,
    anchor_file: &std::path::Path,
    archive: Option<&std::path::Path>,
    assume_archived: bool,
    dry_run: bool,
) -> Result<(), CliError> {
    // Read through a read-only connection, as verifying does: it checks the schema, it
    // takes no store lock, and it cannot migrate a database the running service is using.
    let store = SqliteStore::open_read_only(&cli.database)?;

    // Asked first, because it is the one refusal that would otherwise arrive after the
    // anchor was written — and an anchor in the file for a cut that never happened is a
    // line somebody has to explain later. Cutting asks again inside its transaction.
    store.require_audit_cut_support()?;

    let rows = store.audit_all()?;
    let records = stored_records(&rows);
    let start = store.audit_start()?;

    // Whatever the anchor file already says has to hold before anything is removed. An
    // anchor appended over a chain that contradicts the previous one would give a rewrite
    // a fresh alibi, and a cut made on top of that would take the evidence with it.
    let previous = match std::fs::read_to_string(anchor_file) {
        Ok(text) => Anchor::latest(&text)
            .map_err(|error| CliError::Audit(format!("{}: {error}", anchor_file.display())))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CliError::Io(error)),
    };
    match &previous {
        None => verify_from(start, records.iter().copied())?,
        Some(anchor) => verify_with_anchor(anchor, start, &records)?,
    };

    let keep_index = usize::try_from(keep).unwrap_or(usize::MAX);
    if rows.len() <= keep_index {
        // Not an error. A scheduled cut that failed on a trail shorter than its bound
        // would be a scheduled cut somebody switches off.
        eprintln!("{} entries, keeping {keep}: nothing to remove", rows.len());
        return Ok(());
    }

    // Everything up to and including this record goes. The anchor is taken over exactly
    // that prefix, so the anchored sequence is the cut and the first survivor chains to
    // the anchored hash.
    let removing = rows.len() - keep_index;
    let prefix = &records[..removing];
    let verified = verify_from(start, prefix.iter().copied())?;
    let cut_seq = verified.head_seq;
    let anchor = Anchor::over(&verified, now_millis());

    require_archived(archive, assume_archived, prefix)?;

    if dry_run {
        eprintln!(
            "would remove {removing} entries up to sequence {cut_seq}, keeping {keep} \
             (sequences {} to {})",
            cut_seq + 1,
            records.last().map_or(cut_seq, |record| record.seq)
        );
        eprintln!("would append the anchor below to {}", anchor_file.display());
        println!("{}", anchor.encode());
        return Ok(());
    }

    // The anchor first, and synced, because it is what makes the remainder verifiable. A
    // crash after this and before the delete leaves an anchor over a record still in the
    // table, which verifies; the other order leaves records nothing can attest to.
    let line = append_anchor(anchor_file, &anchor)?;

    let mut device = SqliteAuditDevice::open(&cli.database)?;
    let cut = device.cut(
        cut_seq,
        verified.head_hash,
        now_millis(),
        anchor_file.to_str(),
    )?;

    // What survived was verified above, before anything was removed, so this anchors a
    // chain that was checked rather than one that is merely present. The cut is when the
    // trail changed shape, which makes it the moment a head anchor is most worth having —
    // and appending it here keeps the newest line in the file the one that covers most.
    let remainder = verify_from(cut.as_start(), records[removing..].iter().copied())?;
    let head = Anchor::over(&remainder, now_millis());
    let head_line = append_anchor(anchor_file, &head)?;

    // The records go to standard output alone, so a scheduled job can pipe them
    // somewhere. Everything a person needs goes to standard error.
    println!("{line}");
    println!("{head_line}");

    eprintln!(
        "removed {} entries through sequence {}; {} remain, from sequence {}",
        cut.removed,
        cut.seq,
        remainder.records,
        cut.seq + 1
    );
    eprintln!(
        "appended the anchor at the cut and an anchor over the remainder to {}",
        anchor_file.display()
    );
    eprintln!(
        "this cut is not itself an audit entry: writing one needs the lock the running \
         service holds, and it would move the head just anchored. The store's record of it \
         is the audit_cut row, and the anchor above is the copy of that outside the store."
    );
    if anchor_file.parent() == std::path::Path::new(&cli.database).parent() {
        eprintln!(
            "the anchor file sits beside the store. Whoever can rewrite the trail can \
             rewrite it too, which is the one thing an anchor is for: keep it on another \
             host, in a backup, or on an append-only share."
        );
    }
    Ok(())
}

/// `ciphr rotate-master-key`.
fn rotate_master_key(
    cli: &Context,
    new_key_variable: Option<&str>,
    new_key_file: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let mut session = open(cli)?;
    let state = session
        .store
        .seal_state()?
        .ok_or_else(|| CliError::NotInitialized {
            path: cli.database.display().to_string(),
        })?;

    // clap guarantees exactly one of the two, so there is no precedence to get wrong.
    let new_seal = match (new_key_variable, new_key_file) {
        (_, Some(path)) => StaticSeal::from_file(path)?,
        (Some(variable), None) => StaticSeal::from_env(variable)?,
        (None, None) => {
            return Err(CliError::Audit(
                "pass --new-key-env or --new-key-file".to_owned(),
            ));
        }
    };
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

    println!(
        "the root key is now sealed with the key from {}",
        new_seal.source()
    );
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
