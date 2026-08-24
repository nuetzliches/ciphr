#![forbid(unsafe_code)]

//! Fetch secrets, then become the given command.
//!
//! This is route B from plan section 13, as a generic wrapper instead of one derived image
//! per third-party service (ADR-14):
//!
//! ```text
//! ciphr-run --url https://ciphr.internal:4400 \
//!           --token-file /run/secrets/ciphr-token \
//!           --ca /etc/ciphr/ca.crt \
//!           --prefix infra/host/service \
//!           -- /original/entrypoint --flags
//! ```
//!
//! A container definition mounts this one binary, overrides `entrypoint:`, and the image
//! itself is untouched. Nothing is written to disk, nothing is baked into the container
//! configuration, and the value exists only in `/proc/<pid>/environ` of the service —
//! which is where it has to be for an image that reads environment variables at all.
//!
//! # The order of operations is the security property
//!
//! Every check that can refuse runs **before** the one irreversible step:
//!
//! 1. Can this platform replace a process at all? If not, refuse — before reading
//!    anything. A refusal after the fetch would leave audit entries for reads that served
//!    nothing.
//! 2. Is there a command to execute?
//! 3. Is the token file present, and not readable by everyone on the host?
//! 4. Fetch. The service decides; a `403` here is a refusal, not a warning.
//! 5. Do the secrets produce usable variable names, with no collision (ADR-18)? The SDK
//!    settles this before it spends the reads.
//! 6. Only now, `exec`.
//!
//! **If any of those fails, nothing is executed.** A wrapper that started the service
//! without its secrets would produce a process in some degraded state instead of a visible
//! failure, and fail-closed is the property this project is built on. The exit code says
//! which half failed: see [`error`].

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciphr_core::SecretPath;
use ciphr_sdk::{Client, Environment};
use clap::Parser;

mod error;
mod exec;

use error::RunError;
use exec::Plan;

/// Everything this needs, and all of it from the command line.
///
/// **No environment variables are read.** Not for the URL, not for the certificate
/// authority, and above all not for the token: this process `exec`s into a program that
/// inherits its environment, so anything read from there is something handed to the
/// service as well. Everything here already lives in the container definition, which is
/// where the `entrypoint:` override lives too.
#[derive(Debug, Parser)]
#[command(
    name = "ciphr-run",
    about = "Fetch secrets and replace this process with a command.",
    long_about = "Fetches secrets from ciphr and execs the given command with them in its \
                  environment, so that no plaintext is written to disk or baked into the \
                  container configuration. If anything fails, the command is not started."
)]
struct Cli {
    /// The ciphr instance, as an https URL.
    #[arg(long)]
    url: String,

    /// File holding the token for this host's identity.
    ///
    /// A file rather than a variable, and there is no flag that takes the value: an
    /// argument ends up in the container configuration and in /proc, which is what this
    /// program exists to avoid.
    #[arg(long)]
    token_file: PathBuf,

    /// The certificate authority to trust, as a PEM file.
    ///
    /// Required. This client trusts exactly this authority and no public root (ADR-17).
    #[arg(long, value_name = "PEM")]
    ca: PathBuf,

    /// Take every secret under this prefix. Needs the `list` and `read` capabilities.
    #[arg(long, required_unless_present = "path", conflicts_with = "path")]
    prefix: Option<String>,

    /// Take exactly this secret. Repeatable. Needs only `read`.
    ///
    /// The stricter arrangement, and the better-audited one: the request says what it
    /// wants instead of asking what exists.
    #[arg(long, value_name = "PATH")]
    path: Vec<String>,

    /// Seconds the fetch may take in total.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    timeout: u64,

    /// Report the variable names that were delivered, on standard error.
    ///
    /// Names only. There is no verbosity level that prints a value.
    #[arg(long)]
    report: bool,

    /// The command to become, after `--`.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Irrefutable, and that is the statement: `run` returns `Result<Infallible, _>`, so
    // there is no success branch to write. On success this process no longer exists.
    let Err(error) = run(&cli);

    eprintln!("ciphr-run: {error}");
    ExitCode::from(error.code())
}

/// Do the work.
///
/// The return type is deliberate: `Result<Infallible, _>` says in the signature that
/// there is no success path to return through. On success the process image has been
/// replaced and this stack frame does not exist any more.
fn run(cli: &Cli) -> Result<core::convert::Infallible, RunError> {
    // First, because a refusal here must not follow a fetch.
    if !exec::is_supported() {
        return Err(RunError::NoExec);
    }
    if cli.command.is_empty() {
        return Err(RunError::NoCommand);
    }

    let token = read_token(&cli.token_file)?;
    let authority = std::fs::read(&cli.ca).map_err(|error| RunError::AuthorityFile {
        path: cli.ca.display().to_string(),
        reason: error.kind().to_string(),
    })?;

    let client = Client::builder(&cli.url, token.trim(), &authority)
        .timeout(core::time::Duration::from_secs(cli.timeout))
        .build()?;

    let environment = fetch(&client, cli)?;

    // A name that decides how the child starts is refused before anything starts.
    // With `--prefix` the set of names is whatever the store holds, so an identity
    // with `write` there would otherwise choose `LD_PRELOAD` or `NODE_OPTIONS` for
    // this service (F4 of the review of 2026-08-24).
    //
    // **After the fetch rather than before it**, and that is a real cost: the
    // values have been read and the trail carries those reads. The names of a
    // prefix are known only once it has been listed, and the listing happens
    // inside the SDK call. Nothing is *executed*, which is the property that
    // matters here -- the wrapper exits 125 and the service does not start.
    for name in environment.names() {
        if let Some(reason) = ciphr_core::process_control_reason(name.as_str()) {
            return Err(RunError::ProcessControlName {
                name: name.as_str().to_owned(),
                reason,
            });
        }
    }

    let plan = Plan::new(&cli.command, environment.into_entries())?;

    if cli.report {
        let names: Vec<&str> = plan.names().map(ciphr_core::EnvVarName::as_str).collect();
        eprintln!(
            "ciphr-run: delivering {} to {}",
            names.join(", "),
            plan.program()
        );
    }

    Err(plan.exec())
}

/// The secrets to hand over, by whichever of the two routes was asked for.
///
/// The distinction is a capability one, not a convenience one: a prefix has to be listed
/// before it can be read, so `--prefix` needs `list` as well, while `--path` needs only
/// `read`. An identity that holds the narrower set has to name what it wants.
///
/// # Errors
///
/// Whatever the service or the naming rule says, unchanged. In particular a prefix that
/// yields nothing is a refusal rather than an empty environment — see
/// `SdkError::NothingUnderPrefix`, which is what stops a service booting with no secrets
/// because its token lacks a capability.
fn fetch(client: &Client, cli: &Cli) -> Result<Environment, RunError> {
    if let Some(prefix) = &cli.prefix {
        return Ok(client.environment(&SecretPath::parse(prefix)?)?);
    }

    let paths: Vec<SecretPath> = cli
        .path
        .iter()
        .map(|path| SecretPath::parse(path))
        .collect::<Result<_, _>>()?;

    Ok(client.environment_of(&paths)?)
}

/// Read the token, refusing a file anyone on the host can read or replace.
///
/// The permission check mirrors the one on the master key file in `ciphr-crypto`, and now
/// shares its rule ([`ciphr_core::WorldAccess`]) rather than restating it: a
/// world-accessible credential is unambiguously wrong, so it stops the process instead of
/// producing a warning nobody reads. Group bits are left alone — a root-owned file read by
/// a service group is a legitimate arrangement, and refusing it would push deployments
/// towards running as root.
///
/// Replaceable matters as much as readable here. This file is the only thing standing
/// between the wrapper and a token of someone else's choosing.
///
/// **One descriptor, inspected and read** ([`ciphr_core::open_credential`], F10). The
/// check used to resolve the path, then the read resolved it again — and this file is
/// mounted into images this project does not own, which is exactly where the directory
/// around a credential is least under anyone's control.
fn read_token(path: &Path) -> Result<String, RunError> {
    let mut credential =
        ciphr_core::open_credential(path).map_err(|error| RunError::TokenFile {
            path: path.display().to_string(),
            reason: error.reason(),
        })?;

    if let Some(access) = credential.world {
        return Err(RunError::TokenFileWorldAccessible {
            path: path.display().to_string(),
            // Present whenever `world` is: the verdict is derived from it.
            mode: credential.mode.unwrap_or_default(),
            access,
        });
    }

    let mut token = String::new();
    std::io::Read::read_to_string(&mut credential.file, &mut token).map_err(|error| {
        RunError::TokenFile {
            path: path.display().to_string(),
            reason: error.kind().to_string(),
        }
    })?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn the_command_after_the_separator_is_taken_whole() {
        let cli = Cli::parse_from([
            "ciphr-run",
            "--url",
            "https://ciphr.internal:4400",
            "--token-file",
            "/run/secrets/token",
            "--ca",
            "/etc/ciphr/ca.crt",
            "--prefix",
            "infra/host/service",
            "--",
            "/original/entrypoint",
            "--config",
            "/etc/app.conf",
        ]);

        assert_eq!(cli.prefix.as_deref(), Some("infra/host/service"));
        // The child's own flags are not this program's flags, and `--config` in
        // particular must not be read as one.
        assert_eq!(
            cli.command,
            ["/original/entrypoint", "--config", "/etc/app.conf"]
        );
        assert_eq!(cli.timeout, 10);
        assert!(!cli.report);
    }

    #[test]
    fn a_flag_the_child_shares_with_this_program_stays_the_childs() {
        // `--prefix` after `--` belongs to the child. If this ever regresses, a service
        // starts with the wrong arguments, which is a confusing failure to diagnose.
        let cli = Cli::parse_from([
            "ciphr-run",
            "--url",
            "https://h:4400",
            "--token-file",
            "/t",
            "--ca",
            "/ca",
            "--path",
            "infra/a/DB_PASSWORD",
            "--",
            "/entrypoint",
            "--prefix",
            "not-ours",
        ]);

        assert_eq!(cli.path, ["infra/a/DB_PASSWORD"]);
        assert_eq!(cli.prefix, None);
        assert_eq!(cli.command, ["/entrypoint", "--prefix", "not-ours"]);
    }

    #[test]
    fn several_paths_are_accepted_and_a_prefix_excludes_them() {
        let cli = Cli::parse_from([
            "ciphr-run",
            "--url",
            "https://h:4400",
            "--token-file",
            "/t",
            "--ca",
            "/ca",
            "--path",
            "infra/a/ONE",
            "--path",
            "infra/a/TWO",
            "--",
            "/entrypoint",
        ]);
        assert_eq!(cli.path, ["infra/a/ONE", "infra/a/TWO"]);

        // The two are mutually exclusive: "everything here" and "exactly these" need
        // different capabilities, and a request that meant both would be a request whose
        // authorization nobody can state.
        let both = Cli::try_parse_from([
            "ciphr-run",
            "--url",
            "https://h:4400",
            "--token-file",
            "/t",
            "--ca",
            "/ca",
            "--prefix",
            "infra/a",
            "--path",
            "infra/a/ONE",
            "--",
            "/entrypoint",
        ]);
        assert!(both.is_err(), "--prefix and --path must not combine");
    }

    #[test]
    fn one_of_prefix_or_path_is_required() {
        // Neither given: there is nothing to fetch, and a wrapper that execs anyway is a
        // service starting without its secrets.
        let neither = Cli::try_parse_from([
            "ciphr-run",
            "--url",
            "https://h:4400",
            "--token-file",
            "/t",
            "--ca",
            "/ca",
            "--",
            "/entrypoint",
        ]);
        assert!(neither.is_err());
    }

    #[test]
    fn the_separator_and_a_command_are_both_required() {
        // No command at all.
        assert!(
            Cli::try_parse_from([
                "ciphr-run",
                "--url",
                "https://h:4400",
                "--token-file",
                "/t",
                "--ca",
                "/ca",
                "--prefix",
                "infra/a",
            ])
            .is_err()
        );

        // A separator with nothing after it.
        assert!(
            Cli::try_parse_from([
                "ciphr-run",
                "--url",
                "https://h:4400",
                "--token-file",
                "/t",
                "--ca",
                "/ca",
                "--prefix",
                "infra/a",
                "--",
            ])
            .is_err()
        );
    }

    #[test]
    fn there_is_no_flag_that_takes_the_token_itself() {
        // The rule from plan section 11, applied here: a value is never an argument. If
        // someone adds `--token`, this fails and the reason is in the message.
        let attempt = Cli::try_parse_from([
            "ciphr-run",
            "--url",
            "https://h:4400",
            "--token",
            "ciphr_pat_whatever",
            "--ca",
            "/ca",
            "--prefix",
            "infra/a",
            "--",
            "/entrypoint",
        ]);
        assert!(
            attempt.is_err(),
            "a token must come from a file, never from an argument"
        );
    }
}
