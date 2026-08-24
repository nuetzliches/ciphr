//! Where the two halves of a rendered export go.
//!
//! Separated from the fetch so that this file can be tested without a service: what it
//! decides is which sink receives which half, and that decision is the one a workflow
//! author is exposed to. The rendering itself — the masking order, the delimiter — is
//! `ciphr-export`, shared with `ciphr export` on a host (ADR-25).
//!
//! # The order, once more
//!
//! Masks first, on standard output, where the runner reads workflow commands. Then the
//! assignments, into the file named by `$GITHUB_ENV`. A mask registered after a value has
//! been printed masks nothing that already went out, and the same holds one level up: a
//! failure between the two halves has to leave the *values* unwritten rather than the
//! masks unregistered, which is why the whole set is rendered before anything is emitted.

use std::io::Write;
use std::path::Path;

use ciphr_export::{ExportFormat, Exported, render_actions_env};

use crate::error::CiError;

/// Render the set and write it where the format says.
///
/// `github_env` is the file the runner reads back, and `Some` only where `--github-env`
/// was given and the variable was set. Without it the assignments follow the masks on
/// standard output, which is what a job wanting to read them itself gets.
///
/// # Errors
///
/// [`CiError::Render`] if the set has no usable names or no usable delimiter — before
/// anything is written. [`CiError::Output`] and [`CiError::EnvironmentFile`] for a sink
/// that could not be written.
pub(crate) fn deliver(
    format: ExportFormat,
    secrets: &[Exported],
    github_env: Option<&Path>,
    out: &mut dyn Write,
) -> Result<(), CiError> {
    if format != ExportFormat::ActionsEnv {
        let rendered = format.render(secrets)?;
        return write_out(out, rendered.as_bytes());
    }

    // Both halves before either is written: a refusal for a colliding name must not
    // arrive after half the masks have gone out.
    let (masks, assignments) = render_actions_env(secrets)?;

    write_out(out, masks.as_bytes())?;
    // Flushed here rather than at the end: the masks have to be *in the runner's hands*
    // before the values reach a file it will read back.
    out.flush().map_err(|error| CiError::Output {
        reason: error.kind().to_string(),
    })?;

    match github_env {
        Some(path) => append(path, assignments.as_bytes()),
        None => write_out(out, assignments.as_bytes()),
    }
}

/// Write to the process's own output, naming the failure rather than panicking on it.
fn write_out(out: &mut dyn Write, bytes: &[u8]) -> Result<(), CiError> {
    out.write_all(bytes).map_err(|error| CiError::Output {
        reason: error.kind().to_string(),
    })
}

/// Append to the runner's environment file.
///
/// Appending rather than truncating, because that file is shared: earlier steps have
/// written to it and later ones will. A write that replaced it would delete a variable
/// this program never saw.
fn append(path: &Path, bytes: &[u8]) -> Result<(), CiError> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| CiError::EnvironmentFile {
            path: path.display().to_string(),
            reason: error.kind().to_string(),
        })?;

    file.write_all(bytes)
        .map_err(|error| CiError::EnvironmentFile {
            path: path.display().to_string(),
            reason: error.kind().to_string(),
        })
}

#[cfg(test)]
mod tests {
    use ciphr_core::SecretPath;
    use ciphr_export::{ExportFormat, Exported};

    use super::deliver;
    use crate::error::CiError;

    fn exported(path: &str, value: &str) -> Exported {
        Exported {
            path: SecretPath::parse(path).expect("a valid path"),
            value: value.to_owned(),
        }
    }

    #[test]
    fn the_actions_format_puts_masks_on_output_and_values_in_the_file() {
        // The split that makes this format worth having: standard output carries no
        // value at all, so a job log with the step's output in it has nothing to redact.
        let directory = tempfile::tempdir().expect("temp dir");
        let environment = directory.path().join("env");
        std::fs::write(&environment, b"PRE_EXISTING=1\n").expect("seed the file");

        let secrets = [exported("ci/widget/DB_PASSWORD", "s3cret")];
        let mut out = Vec::new();
        deliver(
            ExportFormat::ActionsEnv,
            &secrets,
            Some(&environment),
            &mut out,
        )
        .expect("delivered");

        let printed = String::from_utf8(out).expect("utf-8");
        assert_eq!(printed, "::add-mask::s3cret\n");
        assert!(
            !printed.contains("DB_PASSWORD="),
            "no assignment belongs on standard output when a file was named"
        );

        let written = std::fs::read_to_string(&environment).expect("read back");
        // Appended: the step before this one keeps its variable.
        assert_eq!(written, "PRE_EXISTING=1\nDB_PASSWORD=s3cret\n");
    }

    #[test]
    fn without_a_file_the_assignments_follow_the_masks_in_order() {
        let secrets = [exported("ci/widget/TOKEN", "s3cret")];
        let mut out = Vec::new();
        deliver(ExportFormat::ActionsEnv, &secrets, None, &mut out).expect("delivered");

        let printed = String::from_utf8(out).expect("utf-8");
        let mask_at = printed.find("::add-mask::").expect("a mask");
        let assign_at = printed.find("TOKEN=").expect("an assignment");
        assert!(mask_at < assign_at, "masks must come first: {printed:?}");
    }

    #[test]
    fn a_set_that_cannot_be_named_writes_nothing_at_all() {
        // Two paths whose last segments collide. The refusal has to happen before the
        // first mask, because a mask for a value that is then not assigned is noise --
        // and worse, a *partial* delivery would leave the job with half its environment.
        let directory = tempfile::tempdir().expect("temp dir");
        let environment = directory.path().join("env");
        std::fs::write(&environment, b"").expect("seed the file");

        let secrets = [
            exported("ci/widget/db/PASSWORD", "right"),
            exported("ci/widget/cache/PASSWORD", "wrong"),
        ];
        let mut out = Vec::new();
        let refused = deliver(
            ExportFormat::ActionsEnv,
            &secrets,
            Some(&environment),
            &mut out,
        )
        .expect_err("a colliding set must be refused");

        assert!(matches!(refused, CiError::Render(_)), "{refused}");
        assert!(out.is_empty(), "nothing may be printed");
        assert_eq!(
            std::fs::read_to_string(&environment).expect("read back"),
            "",
            "and nothing may be written"
        );
    }

    #[test]
    fn dotenv_and_json_write_only_to_the_given_sink() {
        // Neither format has a second half, and neither may touch the environment file:
        // a job asking for `.env` is redirecting standard output somewhere it chose.
        let secrets = [exported("ci/widget/TOKEN", "s3cret")];

        let mut dotenv = Vec::new();
        deliver(ExportFormat::Dotenv, &secrets, None, &mut dotenv).expect("delivered");
        assert_eq!(
            String::from_utf8(dotenv).expect("utf-8"),
            "TOKEN='s3cret'\n"
        );

        let mut json = Vec::new();
        deliver(ExportFormat::Json, &secrets, None, &mut json).expect("delivered");
        let parsed: serde_json::Value = serde_json::from_slice(&json).expect("valid JSON");
        assert_eq!(parsed["ci/widget/TOKEN"], "s3cret");
    }

    #[test]
    fn an_environment_file_that_is_not_there_names_itself() {
        let secrets = [exported("ci/widget/TOKEN", "s3cret")];
        let mut out = Vec::new();
        let refused = deliver(
            ExportFormat::ActionsEnv,
            &secrets,
            Some(std::path::Path::new("./no/such/file")),
            &mut out,
        )
        .expect_err("a missing environment file must be refused");

        let message = refused.to_string();
        assert!(message.contains("no/such/file"), "{message}");
        // The masks went out before the failure, and the message says the values did not.
        assert!(message.contains("no assignment was written"), "{message}");
    }
}
