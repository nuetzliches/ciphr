#![forbid(unsafe_code)]

//! Fetch secrets on a CI runner, and hand them over with the masking the forge does not do.
//!
//! This is the consumption half of plan section 14 as a program rather than as a page of
//! shell ([ADR-25](../../../docs/adr/0025-the-ci-side-fetch-is-its-own-binary.md)):
//!
//! ```text
//! ciphr-ci --url https://ciphr.internal:4400 \
//!          --token-file "$RUNNER_TEMP/ciphr-token" \
//!          --ca /etc/ciphr/ca.crt \
//!          --path ci/widget/DB_PASSWORD \
//!          --format actions-env --github-env
//! ```
//!
//! # Why this exists at all
//!
//! **No forge masks a value fetched at runtime.** Only its own native secrets are masked,
//! so a job that reaches the API with `curl` and reads the value with `jq` has a secret in
//! its log the moment anybody adds `set -x`. The masking rules that answer that — masks
//! before anything else, one per line, a heredoc delimiter the value cannot reproduce —
//! are the kind of thing that is written once and reviewed once, which is why they live in
//! `ciphr-export` and are shared with `ciphr export` on a host rather than reimplemented
//! in a composite action's shell.
//!
//! # What separates it from `ciphr-run`
//!
//! The wrapper (ADR-14) fetches and then *becomes* a service; this fetches and then
//! *terminates*, having written into the job's environment file. That difference is why
//! they are two binaries and not one flag:
//!
//! - `ciphr-run` reads no environment variable, because it `exec`s into a program that
//!   inherits its environment. This one reads `$GITHUB_ENV`, and may: it hands its
//!   environment to nothing.
//! - `ciphr-run`'s exit codes are the `docker run` convention, because a restart policy
//!   reads them. This one exits `0` or `1`, because a workflow step is what reads it.
//! - `ciphr-run` is bind-mounted into images this project does not own, so its dependency
//!   list is a security boundary. This one is downloaded onto a runner.
//!
//! # The order of operations
//!
//! Every check that can refuse runs **before** the fetch, and the whole set is rendered
//! before anything is written:
//!
//! 1. Is the format one that exists, and does the invocation match it?
//! 2. Would this put values somewhere nobody asked for them?
//! 3. Is the token file present, and not readable or replaceable by everyone?
//! 4. Which paths — named, or listed under the prefix?
//! 5. Do those paths produce usable variable names (ADR-18)? Settled before a single
//!    value is read, so a layout that cannot work costs no audit entries.
//! 6. Fetch, render, and only then write.
//!
//! **A non-zero exit therefore means no assignment was written**, and a job that
//! continues past a failed step does not continue with half an environment.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciphr_core::{EnvVarName, SecretPath};
use ciphr_export::{ExportFormat, Exported};
use ciphr_sdk::Client;
use clap::Parser;

mod deliver;
mod error;

use error::CiError;

/// Everything this needs, and all of it from the command line except one variable.
///
/// **There is no flag that takes the token itself.** An argument lands in the job log of
/// any runner that echoes its command lines, in `/proc/<pid>/cmdline` while the process
/// runs, and in the shell history of whoever tried it locally. The token comes from a
/// file, exactly as it does for `ciphr-run`.
///
/// The one thing read from the environment is `$GITHUB_ENV`, and only with `--github-env`:
/// it is set by the runner, it names a file rather than carrying a value, and this process
/// hands its environment to nothing.
#[derive(Debug, Parser)]
#[command(
    name = "ciphr-ci",
    about = "Fetch secrets into a CI job, masked.",
    long_about = "Fetches secrets from ciphr and renders them for a CI job: dotenv, JSON, \
                  or an Actions environment file with `::add-mask::` emitted for every \
                  value before anything else. If anything fails, nothing is written."
)]
struct Cli {
    /// The ciphr instance, as an https URL.
    #[arg(long)]
    url: String,

    /// File holding the token for this job's identity.
    ///
    /// Refused if anyone on the runner can read or replace it — the same rule the master
    /// key and `ciphr-run`'s token file are held to.
    #[arg(long)]
    token_file: PathBuf,

    /// The certificate authority to trust, as a PEM file.
    ///
    /// Required, and required by design: there is no way to make this client trust the
    /// public CA set (ADR-17, ADR-19). Distribute it as a non-secret CI variable.
    #[arg(long, value_name = "PEM")]
    ca: PathBuf,

    /// Take every secret under this prefix. Needs the `list` and `read` capabilities.
    #[arg(long, required_unless_present = "path", conflicts_with = "path")]
    prefix: Option<String>,

    /// Take exactly this secret. Repeatable. Needs only `read`.
    ///
    /// Prefer this where the set is known when the workflow is written: a listing that
    /// shrinks does so silently, and somebody else's new secret can collide with a name
    /// this job depends on.
    #[arg(long, value_name = "PATH")]
    path: Vec<String>,

    /// dotenv, actions-env, or json.
    #[arg(long, default_value = "actions-env")]
    format: String,

    /// For `actions-env`: append the assignments to the file named by `$GITHUB_ENV`.
    #[arg(long)]
    github_env: bool,

    /// Seconds the fetch may take in total.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    timeout: u64,

    /// Write values to standard output even though it is not a terminal.
    #[arg(long)]
    force: bool,

    /// Report the variable names that were delivered, on standard error.
    #[arg(long)]
    report: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ciphr-ci: {error}");
            ExitCode::from(CiError::code())
        }
    }
}

/// Do the work, in the order the module documentation gives.
fn run(cli: &Cli) -> Result<(), CiError> {
    let format = ExportFormat::parse(&cli.format)?;
    let environment_file = environment_file(cli, format)?;

    // A value on a pipe nobody asked for is how a secret reaches a log, a transcript, or
    // a shell variable through `$(…)`. `actions-env` is exempt because its values go into
    // a file the runner reads, and because whatever it does put on standard output is
    // preceded by the mask that redacts it.
    if format.writes_values_to_stdout() && !cli.force && !std::io::stdout().is_terminal() {
        return Err(CiError::WouldPipeSecret);
    }

    let token = read_token(&cli.token_file)?;
    let authority = std::fs::read(&cli.ca).map_err(|error| CiError::AuthorityFile {
        path: cli.ca.display().to_string(),
        reason: error.kind().to_string(),
    })?;

    let client = Client::builder(&cli.url, token.trim(), &authority)
        .timeout(core::time::Duration::from_secs(cli.timeout))
        .build()?;

    let paths = paths(&client, cli)?;

    // Names before values. A set that cannot become an environment is refused here, which
    // costs the deployment nothing — no reads, and so no audit entries for secrets that
    // were never delivered. The JSON format is keyed by path and has no names to assign.
    if format != ExportFormat::Json {
        let names = EnvVarName::assign(&paths)?;

        // And a name that decides how a *later step* starts is refused with them
        // (F4 of the review of 2026-08-24). This is sharper here than in the
        // wrapper: `$GITHUB_ENV` sets variables for every step that follows, not
        // for one program — which is the shape of CVE-2020-15228, the reason
        // GitHub Actions stopped letting a workflow set variables through a log
        // directive. JSON is exempt because it is keyed by path and becomes
        // nobody's environment on its own.
        //
        // Before the fetch, so a set that will be refused costs no reads and no
        // audit entries.
        for name in &names {
            if let Some(reason) = ciphr_core::process_control_reason(name.as_str()) {
                return Err(CiError::ProcessControlName {
                    name: name.as_str().to_owned(),
                    reason,
                });
            }
        }
    }

    let secrets = client.read_all(&paths)?;
    let exported = as_text(secrets)?;

    if cli.report {
        report(format, &exported);
    }

    deliver::deliver(
        format,
        &exported,
        environment_file.as_deref(),
        &mut std::io::stdout().lock(),
    )
}

/// The file the assignments go into, if the invocation asked for one.
///
/// Resolved before anything is fetched: `--github-env` outside a runner is a workflow
/// that would otherwise read its secrets, print them, and deliver nothing.
fn environment_file(cli: &Cli, format: ExportFormat) -> Result<Option<PathBuf>, CiError> {
    if !cli.github_env {
        return Ok(None);
    }
    if format != ExportFormat::ActionsEnv {
        return Err(CiError::GithubEnvWithoutActions);
    }

    std::env::var("GITHUB_ENV")
        .map(|value| Some(PathBuf::from(value)))
        .map_err(|_| CiError::GithubEnvUnset)
}

/// Which paths to fetch: the ones named, or the ones the prefix lists.
///
/// The distinction is a capability one rather than a convenience one — a prefix has to be
/// listed before it can be read, so `--prefix` needs `list` as well.
fn paths(client: &Client, cli: &Cli) -> Result<Vec<SecretPath>, CiError> {
    let Some(prefix) = &cli.prefix else {
        return cli
            .path
            .iter()
            .map(|path| SecretPath::parse(path).map_err(CiError::from))
            .collect();
    };

    let prefix = SecretPath::parse(prefix)?;
    let listed = client.list(&prefix)?;
    if listed.is_empty() {
        // Two causes, one shape on the wire, and neither of them is a job that should
        // continue: `GET /v1/list` authorizes every path it returns, so "you may list
        // nothing here" and "there is nothing here" are the same empty array.
        return Err(CiError::NothingUnderPrefix {
            prefix: prefix.as_str().to_owned(),
        });
    }
    Ok(listed)
}

/// The values as text, for a renderer that writes text.
///
/// `openapi.yaml` says values are UTF-8 and a binary secret is encoded by whoever stored
/// it, so the failure below is a service breaking its own contract. It names the path
/// rather than the bytes.
fn as_text(secrets: Vec<ciphr_sdk::Secret>) -> Result<Vec<Exported>, CiError> {
    let mut exported = Vec::with_capacity(secrets.len());
    for secret in secrets {
        let Ok(value) = String::from_utf8(secret.value.expose().to_vec()) else {
            return Err(CiError::NotText {
                path: secret.path.as_str().to_owned(),
            });
        };
        exported.push(Exported {
            path: secret.path,
            value,
        });
    }
    Ok(exported)
}

/// Say what was delivered, on standard error, without saying what it was.
///
/// Names for the environment-shaped formats, because a name is what the next step
/// reads; paths for JSON, which is keyed by path and has no names. Never a value, and
/// there is no verbosity level that would add one.
fn report(format: ExportFormat, exported: &[Exported]) {
    let subjects: Vec<String> = if format == ExportFormat::Json {
        exported
            .iter()
            .map(|secret| secret.path.as_str().to_owned())
            .collect()
    } else {
        // Assigned once more rather than threaded through: the rule is a pure function of
        // the paths (ADR-18), and it has already succeeded for this set by the time this
        // runs.
        match EnvVarName::assign(exported.iter().map(|secret| &secret.path)) {
            Ok(names) => names.iter().map(|name| name.as_str().to_owned()).collect(),
            Err(_) => return,
        }
    };

    eprintln!("ciphr-ci: delivering {}", subjects.join(", "));
}

/// Read the token, refusing a file anyone on the runner can read or replace.
///
/// The same rule and the same implementation as `ciphr-run`'s
/// ([`ciphr_core::open_credential`]): one descriptor is opened, and both the permission
/// bits and the content come from it, so a file swapped in after the check is not the file
/// that was read.
///
/// **A runner's working directory is the wrong place for this file.** Whoever can create
/// entries in the directory a token lives in can put their own token there at mode `0600`
/// and pass every rule here; on a shared runner that directory is often writable by the
/// job that runs next. `$RUNNER_TEMP` is per-job and is the right place.
fn read_token(path: &Path) -> Result<String, CiError> {
    let mut credential = ciphr_core::open_credential(path).map_err(|error| CiError::TokenFile {
        path: path.display().to_string(),
        reason: error.reason(),
    })?;

    if let Some(access) = credential.world {
        return Err(CiError::TokenFileWorldAccessible {
            path: path.display().to_string(),
            // Present whenever `world` is: the verdict is derived from it.
            mode: credential.mode.unwrap_or_default(),
            access,
        });
    }

    let mut token = String::new();
    credential
        .file
        .read_to_string(&mut token)
        .map_err(|error| CiError::TokenFile {
            path: path.display().to_string(),
            reason: error.kind().to_string(),
        })?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    /// The flags a workflow step writes, and what they default to.
    fn parse(extra: &[&str]) -> Cli {
        let mut argv = vec![
            "ciphr-ci",
            "--url",
            "https://ciphr.internal:4400",
            "--token-file",
            "/runner/temp/token",
            "--ca",
            "/etc/ciphr/ca.crt",
        ];
        argv.extend_from_slice(extra);
        Cli::parse_from(argv)
    }

    #[test]
    fn the_default_format_is_the_one_that_masks() {
        // The default matters more here than defaults usually do: a job that omits
        // `--format` is a job whose author did not think about masking, and the safe
        // shape is the one that does it for them.
        let cli = parse(&["--path", "ci/widget/DB_PASSWORD"]);
        assert_eq!(cli.format, "actions-env");
        assert_eq!(cli.timeout, 10);
        assert!(!cli.github_env);
        assert!(!cli.force);
        assert!(!cli.report);
    }

    #[test]
    fn several_paths_are_accepted_and_a_prefix_excludes_them() {
        let cli = parse(&["--path", "ci/widget/ONE", "--path", "ci/widget/TWO"]);
        assert_eq!(cli.path, ["ci/widget/ONE", "ci/widget/TWO"]);
        assert_eq!(cli.prefix, None);

        // "Everything here" and "exactly these" need different capabilities, so a
        // request meaning both is a request whose authorization nobody can state.
        assert!(
            Cli::try_parse_from([
                "ciphr-ci",
                "--url",
                "https://h:4400",
                "--token-file",
                "/t",
                "--ca",
                "/ca",
                "--prefix",
                "ci/widget",
                "--path",
                "ci/widget/ONE",
            ])
            .is_err(),
            "--prefix and --path must not combine"
        );
    }

    #[test]
    fn one_of_prefix_or_path_is_required() {
        assert!(
            Cli::try_parse_from([
                "ciphr-ci",
                "--url",
                "https://h:4400",
                "--token-file",
                "/t",
                "--ca",
                "/ca",
            ])
            .is_err(),
            "there would be nothing to fetch"
        );
    }

    #[test]
    fn there_is_no_flag_that_takes_the_token_itself() {
        // The rule from plan section 11, applied here: a value is never an argument. On a
        // runner this is sharper than on a host -- an argument reaches the job log of any
        // runner that echoes command lines, and that log outlives the job.
        assert!(
            Cli::try_parse_from([
                "ciphr-ci",
                "--url",
                "https://h:4400",
                "--token",
                "ciphr_pat_whatever",
                "--ca",
                "/ca",
                "--prefix",
                "ci/widget",
            ])
            .is_err(),
            "a token must come from a file, never from an argument"
        );
    }

    #[test]
    fn the_certificate_authority_is_not_optional() {
        // There is no fallback to the platform's trust store to fall back *to* (ADR-17),
        // so this is refused at the command line rather than at the handshake.
        assert!(
            Cli::try_parse_from([
                "ciphr-ci",
                "--url",
                "https://h:4400",
                "--token-file",
                "/t",
                "--prefix",
                "ci/widget",
            ])
            .is_err()
        );
    }
}
