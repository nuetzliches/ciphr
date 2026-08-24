#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Rendering a set of secrets into the forms a process can consume.
//!
//! Three formats, one rule for the variable name, and one place where a stored value
//! crosses from data into command. Two binaries render: `ciphr export` on a host with the
//! store, and `ciphr-ci` on a runner with a token (ADR-25). They share this crate rather
//! than a shape, because the interesting half below is the masking discipline and a
//! second copy of it is how the two start to disagree.
//!
//! # The masking trap
//!
//! **No forge masks a value fetched at runtime.** Only its own native secrets are
//! masked. A bare `curl | jq` therefore writes secrets into the job log the moment
//! anyone adds `set -x` or a debug echo — and that log is usually readable by more
//! people than the secret store is.
//!
//! Masking is consequently part of the product rather than of the documentation: the
//! `actions-env` format emits `::add-mask::` for every value *before* writing anything
//! else. The order matters. A mask registered after a value has been printed masks
//! nothing that already went out.
//!
//! Multi-line values get one `::add-mask::` per line, because the runners match
//! literal strings and a value containing a newline is never matched as a whole.
//!
//! # What this crate does not do
//!
//! It does not decide where the two halves of an Actions export go, and it does not
//! write them. [`render_actions_env`] hands back the masks and the assignments
//! separately because they belong on different sinks — the masks on standard output,
//! where a runner reads workflow commands, and the assignments in the file named by
//! `$GITHUB_ENV`. Which file that is, and whether standard output is a place a value may
//! go at all, is a question about the invocation and is answered by the binary.

use ciphr_core::{EnvNameError, EnvVarName, SecretPath};

/// A path and its value, ready to be written out.
///
/// No `Debug`: it holds a value. The path alone is safe to print, and every error in
/// this crate carries the name or the path rather than this type.
pub struct Exported {
    /// Where it came from.
    pub path: SecretPath,
    /// The value.
    pub value: String,
}

/// Why a set of secrets could not be rendered.
///
/// Both variants are properties of the *set* rather than of the transport: no retry
/// changes either, and neither carries a value.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike `SdkError`. Both consumers are in this
/// workspace and both translate this into their own error type, so a third variant should
/// stop their compilation and make somebody write the sentence a person reads — not fall
/// into a catch-all arm that prints something vaguer than what happened.
#[derive(Debug)]
pub enum ExportError {
    /// The set has no usable variable names: two paths want the same one, or one of
    /// them is not a name a shell can read (ADR-18).
    EnvName(EnvNameError),
    /// A multi-line value could not be given a heredoc delimiter it cannot close
    /// itself.
    Delimiter {
        /// The variable the delimiter was for. A name, never the value.
        name: String,
        /// What went wrong, in words.
        reason: String,
    },
}

impl core::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EnvName(error) => write!(formatter, "{error}"),
            Self::Delimiter { name, reason } => write!(
                formatter,
                "cannot write {name} into an environment file: {reason}"
            ),
        }
    }
}

impl core::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::EnvName(error) => Some(error),
            Self::Delimiter { .. } => None,
        }
    }
}

impl From<EnvNameError> for ExportError {
    fn from(error: EnvNameError) -> Self {
        Self::EnvName(error)
    }
}

/// The variable names for a whole export, or the reason it has none.
///
/// The rule itself is in [`ciphr_core::EnvVarName`], not here: `ciphr export`, `ciphr-ci`,
/// `ciphr-run` and the SDK derive the same name from the same path, and a second copy of
/// the rule is how those four start to disagree (ADR-18).
fn assign_names(secrets: &[Exported]) -> Result<Vec<EnvVarName>, EnvNameError> {
    EnvVarName::assign(secrets.iter().map(|secret| &secret.path))
}

/// Which shape an export takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// `KEY=value`, quoted, for a `.env` file.
    Dotenv,
    /// `::add-mask::` lines followed by `KEY=value` for `$GITHUB_ENV`.
    ActionsEnv,
    /// A JSON object of path to value.
    Json,
}

impl ExportFormat {
    /// Parse the format name a command line carries.
    ///
    /// One parser, so that `ciphr export --format` and `ciphr-ci --format` accept the
    /// same three words and refuse the same fourth one with the same sentence.
    ///
    /// # Errors
    ///
    /// The name of the format that does not exist, ready to be quoted in a message.
    pub fn parse(name: &str) -> Result<Self, UnknownFormat> {
        match name {
            "dotenv" => Ok(Self::Dotenv),
            "actions-env" => Ok(Self::ActionsEnv),
            "json" => Ok(Self::Json),
            other => Err(UnknownFormat {
                found: other.to_owned(),
            }),
        }
    }

    /// Whether this format writes a value where a shell could capture it.
    ///
    /// [`ExportFormat::ActionsEnv`] writes its assignments into a file a runner reads
    /// and puts only mask commands on standard output, which is the one case where
    /// output on a pipe is the purpose rather than the accident. The other two are a
    /// value on standard output, and a value on standard output needs to be asked for.
    #[must_use]
    pub fn writes_values_to_stdout(self) -> bool {
        match self {
            Self::Dotenv | Self::Json => true,
            Self::ActionsEnv => false,
        }
    }

    /// Render the export.
    ///
    /// For [`ExportFormat::ActionsEnv`] the result is meant to be *printed*, so the
    /// runner sees the mask commands, and the `KEY=value` half appended to the file
    /// named by `$GITHUB_ENV`. [`render_actions_env`] returns the two parts separately
    /// for that reason.
    ///
    /// # Errors
    ///
    /// The two environment-shaped formats fail if a path has no usable variable name or
    /// if two of them want the same one. [`ExportFormat::Json`] is keyed by the full path
    /// and therefore cannot fail — which is the honest difference between the formats
    /// rather than an inconsistency in this signature.
    pub fn render(self, secrets: &[Exported]) -> Result<String, ExportError> {
        match self {
            Self::Dotenv => Ok(render_dotenv(secrets)?),
            Self::ActionsEnv => {
                let (masks, assignments) = render_actions_env(secrets)?;
                Ok(format!("{masks}{assignments}"))
            }
            Self::Json => Ok(render_json(secrets)),
        }
    }
}

/// A `--format` nobody implements.
#[derive(Debug)]
pub struct UnknownFormat {
    /// What was asked for.
    pub found: String,
}

impl core::fmt::Display for UnknownFormat {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "format '{}'; use dotenv, actions-env or json",
            self.found
        )
    }
}

impl core::error::Error for UnknownFormat {}

/// `KEY='value'` lines.
///
/// Single quotes with embedded single quotes escaped, which is the one form that needs
/// no further reasoning about what the shell will do to `$`, backticks, or backslashes
/// inside the value.
///
/// # Errors
///
/// [`ExportError::EnvName`] if the set has no usable names. Nothing is rendered in that
/// case: a partial `.env` file is a service that starts with half its configuration.
pub fn render_dotenv(secrets: &[Exported]) -> Result<String, ExportError> {
    let names = assign_names(secrets)?;

    let mut out = String::new();
    for (secret, name) in secrets.iter().zip(&names) {
        out.push_str(name.as_str());
        out.push('=');
        out.push_str(&shell_single_quote(&secret.value));
        out.push('\n');
    }
    Ok(out)
}

/// How many random bytes a heredoc delimiter carries: 128 bits, hex-encoded.
///
/// The size is not about colliding with the word `EOF` — including the variable name
/// already handled that. It is about a writer who knows this format. Finding F2 of
/// `docs/review-2026-08-21-current-tree.md`: the delimiter was derived from the name, so a
/// value containing that exact line closed its own assignment, and every line after it was
/// read by the runner as further environment-file commands. An identity allowed to write
/// one exported secret could therefore define environment variables for later steps of
/// every workflow that reads it.
///
/// 128 bits is chosen so that guessing is not a strategy, which is what makes the
/// verification below a formality rather than a retry loop anybody has to reason about.
const DELIMITER_BYTES: usize = 16;

/// How many candidates to draw before giving up.
///
/// A loop that can only end in success hides an entropy failure. Four attempts and then a
/// named error, so a machine with no randomness produces a refusal rather than a delimiter
/// somebody could have predicted.
const DELIMITER_ATTEMPTS: usize = 4;

/// A heredoc delimiter for one value: random, and then checked against that value.
///
/// Both halves, because neither is the property on its own. Randomness is what makes the
/// delimiter unguessable to whoever wrote the value; the check is what keeps the guarantee
/// from depending on the entropy source being everything it claims. GitHub's own
/// documentation for `$GITHUB_ENV` asks for the same pair, and this is the one place in
/// this project where a stored value crosses from data into command.
///
/// **Compared line by line and not with `contains`.** A delimiter closes a heredoc only
/// when it stands alone on a line, so a substring test would refuse values that are
/// perfectly safe — and a refusal here is an export that does not happen.
fn heredoc_delimiter(name: &str, value: &str) -> Result<String, ExportError> {
    for _ in 0..DELIMITER_ATTEMPTS {
        let mut bytes = [0u8; DELIMITER_BYTES];
        if getrandom::fill(&mut bytes).is_err() {
            return Err(ExportError::Delimiter {
                name: name.to_owned(),
                reason: "the operating system provided no entropy".to_owned(),
            });
        }

        let candidate = format!("ciphr_{name}_{}", ciphr_core::hex::encode(&bytes));
        if !value.lines().any(|line| line == candidate) {
            return Ok(candidate);
        }
    }

    // Reachable only for a value that already contains four unpredictable 128-bit strings
    // somebody would have had to write into it. It is an error rather than a fifth attempt
    // because at that point the assumption behind the whole function is wrong.
    Err(ExportError::Delimiter {
        name: name.to_owned(),
        reason: format!("{DELIMITER_ATTEMPTS} random delimiters all occur in the value"),
    })
}

/// The two halves of an Actions-style export: the mask commands, and the assignments.
///
/// Returned separately because they go to different places — the masks to standard
/// output, where the runner reads workflow commands, and the assignments to the file
/// named by `$GITHUB_ENV`.
///
/// # Errors
///
/// [`ExportError::EnvName`] if the set has no usable names — checked before a single
/// `::add-mask::` is produced, so a refused export has printed nothing at all. And
/// [`ExportError::Delimiter`] if a multi-line value cannot be given a delimiter it
/// could not close itself, which is the same discipline one line further out: the
/// refusal happens before anything is written.
// `format_push_string` fires on the two lines below. Building the heredoc block as one
// string is clearer than three `writeln!` calls, and this function is not on a hot path
// — it runs once per export.
#[allow(clippy::format_push_string)]
pub fn render_actions_env(secrets: &[Exported]) -> Result<(String, String), ExportError> {
    let names = assign_names(secrets)?;

    let mut masks = String::new();
    let mut assignments = String::new();

    for (secret, name) in secrets.iter().zip(&names) {
        // One mask per line: runners match literal strings, so a value containing a
        // newline is never matched as a whole.
        for line in secret.value.lines() {
            if line.is_empty() {
                // Masking an empty string would ask the runner to redact everything.
                continue;
            }
            masks.push_str("::add-mask::");
            masks.push_str(line);
            masks.push('\n');
        }

        let name = name.as_str();
        if secret.value.contains('\n') {
            // The heredoc form, which is the only way to put a multi-line value into
            // `$GITHUB_ENV`. The delimiter is 128 random bits verified against this
            // value, because a delimiter derived from the name is one the writer of
            // the value could reproduce -- and then close (finding F2).
            let delimiter = heredoc_delimiter(name, &secret.value)?;
            assignments.push_str(&format!(
                "{name}<<{delimiter}\n{}\n{delimiter}\n",
                secret.value
            ));
        } else {
            assignments.push_str(&format!("{name}={}\n", secret.value));
        }
    }

    Ok((masks, assignments))
}

/// A JSON object of path to value.
#[must_use]
pub fn render_json(secrets: &[Exported]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = secrets
        .iter()
        .map(|secret| {
            (
                secret.path.as_str().to_owned(),
                serde_json::Value::String(secret.value.clone()),
            )
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

/// Quote a value for a shell, using single quotes.
#[must_use]
pub fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for character in value.chars() {
        if character == '\'' {
            // Close the quote, emit an escaped quote, reopen: the standard trick, and
            // the only one that needs no assumptions about the shell.
            out.push_str("'\\''");
        } else {
            out.push(character);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        ExportError, ExportFormat, Exported, render_actions_env, render_dotenv, shell_single_quote,
    };
    use ciphr_core::{EnvNameError, SecretPath};

    fn exported(path: &str, value: &str) -> Exported {
        Exported {
            path: SecretPath::parse(path).expect("valid"),
            value: value.to_owned(),
        }
    }

    #[test]
    fn the_variable_name_is_the_last_path_segment() {
        // The rule itself is tested in `ciphr-core`; what this checks is that the export
        // calls it rather than carrying its own copy.
        let secrets = [exported("infra/service-a/DB_PASSWORD", "x")];
        assert_eq!(
            render_dotenv(&secrets).expect("a usable name"),
            "DB_PASSWORD='x'\n"
        );
        assert_eq!(
            render_dotenv(&[exported("SINGLE", "x")]).expect("a usable name"),
            "SINGLE='x'\n"
        );
    }

    #[test]
    fn an_export_whose_names_would_collide_is_refused_entirely() {
        // Two paths under one prefix that share a last segment. Rendered, the second
        // assignment would win and the service would receive the wrong secret with no
        // error anywhere — so nothing is rendered at all.
        let secrets = [
            exported("infra/a/db/PASSWORD", "right"),
            exported("infra/a/cache/PASSWORD", "wrong"),
        ];

        assert!(matches!(
            render_dotenv(&secrets),
            Err(ExportError::EnvName(EnvNameError::Collision { .. }))
        ));
        // And the masking format refuses before it prints a single mask, which is what
        // makes the refusal safe: a mask that went out for a value that was then not
        // assigned is noise, but a value printed before its mask is a leak.
        assert!(render_actions_env(&secrets).is_err());

        // JSON is keyed by the full path, so it has no collision to have.
        assert!(ExportFormat::Json.render(&secrets).is_ok());
    }

    #[test]
    fn a_path_whose_last_segment_is_no_variable_name_is_refused() {
        // `db-password` is a legal secret path and an illegal shell name. Before this
        // rule the export emitted `db-password='…'`, which no shell can source and this
        // project's own import rejects.
        let secrets = [exported("infra/a/db-password", "x")];
        assert!(matches!(
            render_dotenv(&secrets),
            Err(ExportError::EnvName(EnvNameError::NotAName { .. }))
        ));
        // Still exportable as JSON, which promises a path rather than a name.
        assert!(ExportFormat::Json.render(&secrets).is_ok());
    }

    #[test]
    fn dotenv_quoting_survives_the_shell() {
        let secrets = [exported("a/PASSWORD", "p4ss w'rd$`\\")];
        let rendered = render_dotenv(&secrets).expect("a usable name");
        assert_eq!(rendered, "PASSWORD='p4ss w'\\''rd$`\\'\n");

        // The property that matters: a single quote inside the value cannot end the
        // quoting.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn actions_env_masks_before_it_assigns() {
        // The order is the whole point: a mask registered after a value has been
        // printed masks nothing that already went out.
        let secrets = [exported("a/TOKEN", "s3cret")];
        let (masks, assignments) = render_actions_env(&secrets).expect("a usable name");

        assert_eq!(masks, "::add-mask::s3cret\n");
        assert_eq!(assignments, "TOKEN=s3cret\n");

        let combined = ExportFormat::ActionsEnv
            .render(&secrets)
            .expect("a usable name");
        let mask_at = combined.find("::add-mask::").expect("a mask");
        let assign_at = combined.find("TOKEN=").expect("an assignment");
        assert!(mask_at < assign_at, "masks must come first");
    }

    #[test]
    fn a_multi_line_value_is_masked_line_by_line_and_assigned_with_a_heredoc() {
        // Runners match literal strings, so a value with a newline is never masked as a
        // whole — and `KEY=value` cannot express it at all.
        let secrets = [exported("a/KEY", "-----BEGIN-----\nmiddle\n-----END-----")];
        let (masks, assignments) = render_actions_env(&secrets).expect("a usable name");

        assert_eq!(masks.lines().count(), 3);
        assert!(masks.contains("::add-mask::-----BEGIN-----"));
        assert!(masks.contains("::add-mask::middle"));

        // The delimiter is random, so what is asserted is its shape and its use: the block
        // opens with it, closes with it, and carries the value between them unchanged.
        let lines: Vec<&str> = assignments.lines().collect();
        let delimiter = lines
            .first()
            .expect("an opening line")
            .strip_prefix("KEY<<")
            .expect("the heredoc opens by naming its delimiter");
        assert!(delimiter.starts_with("ciphr_KEY_"), "got {delimiter:?}");
        assert_eq!(
            delimiter.len(),
            "ciphr_KEY_".len() + 32,
            "128 bits, hex-encoded"
        );
        assert_eq!(lines.last(), Some(&delimiter), "and closes with it");
        assert_eq!(lines[1..lines.len() - 1].join("\n"), secrets[0].value);
    }

    /// Finding F2: the value that used to close its own assignment.
    ///
    /// The delimiter was `ciphr_<NAME>_EOF` and nothing else, so a writer who knew the
    /// format could put that line into a value and have the runner read everything after
    /// it as further environment-file commands — which is influence over later steps of
    /// every workflow that reads the secret. The payload below is that attack.
    #[test]
    fn a_value_cannot_close_its_own_heredoc() {
        let payload = "harmless\nciphr_KEY_EOF\nINJECTED=owned\n::add-mask::whatever";
        let secrets = [exported("a/KEY", payload)];
        let (_, assignments) = render_actions_env(&secrets).expect("a usable name");

        let lines: Vec<&str> = assignments.lines().collect();
        let delimiter = lines[0]
            .strip_prefix("KEY<<")
            .expect("the heredoc opens by naming its delimiter");
        assert_ne!(
            delimiter, "ciphr_KEY_EOF",
            "the delimiter must not be the one the value already contains"
        );

        // The property is that the payload stays *inside* the block, not that it was
        // sanitized -- a value must go out as it was stored. So: exactly one line equals
        // the delimiter, and it is the last one.
        assert_eq!(
            lines.iter().filter(|line| **line == delimiter).count(),
            1,
            "nothing in the value may equal the delimiter"
        );
        assert_eq!(lines.last(), Some(&delimiter));

        let body = lines[1..lines.len() - 1].join("\n");
        assert_eq!(body, payload, "the value is written unchanged");
        assert!(
            body.contains("INJECTED=owned"),
            "and the injection attempt is data inside the block"
        );
    }

    #[test]
    fn two_exports_of_one_value_get_different_delimiters() {
        // The delimiter comes from the OS CSPRNG rather than from the variable name, which
        // is what makes it unguessable to whoever wrote the value. At 128 bits, a repeat
        // here means the randomness is not actually there.
        let secrets = [exported("a/KEY", "one\ntwo")];
        let first = render_actions_env(&secrets).expect("a usable name").1;
        let second = render_actions_env(&secrets).expect("a usable name").1;

        assert_ne!(first, second, "two renders must not share a delimiter");
    }

    #[test]
    fn an_empty_line_is_not_masked() {
        // `::add-mask::` with an empty string would ask the runner to redact
        // everything.
        let secrets = [exported("a/KEY", "first\n\nlast")];
        let (masks, _) = render_actions_env(&secrets).expect("a usable name");
        assert_eq!(masks.lines().count(), 2);
    }

    #[test]
    fn json_export_is_keyed_by_full_path() {
        let secrets = [exported("infra/a/ONE", "1"), exported("infra/b/TWO", "2")];
        let rendered = ExportFormat::Json
            .render(&secrets)
            .expect("json cannot fail");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");

        assert_eq!(parsed["infra/a/ONE"], "1");
        assert_eq!(parsed["infra/b/TWO"], "2");
    }

    #[test]
    fn the_three_format_names_are_the_same_three_everywhere() {
        // One parser, so that a workflow written against `ciphr-ci --format` and a host
        // script written against `ciphr export --format` accept the same words.
        assert_eq!(
            ExportFormat::parse("dotenv").expect("known"),
            ExportFormat::Dotenv
        );
        assert_eq!(
            ExportFormat::parse("actions-env").expect("known"),
            ExportFormat::ActionsEnv
        );
        assert_eq!(
            ExportFormat::parse("json").expect("known"),
            ExportFormat::Json
        );

        let refused = ExportFormat::parse("yaml").expect_err("no such format");
        // The message names the three that exist rather than only the one that does not.
        let message = refused.to_string();
        assert!(message.contains("dotenv"), "{message}");
        assert!(message.contains("actions-env"), "{message}");
        assert!(message.contains("json"), "{message}");
    }

    #[test]
    fn only_the_actions_format_puts_no_value_on_standard_output() {
        // What decides whether a binary needs `--force` before it writes: the Actions
        // format sends values to a file and masks to the terminal, the other two send
        // the values themselves.
        assert!(ExportFormat::Dotenv.writes_values_to_stdout());
        assert!(ExportFormat::Json.writes_values_to_stdout());
        assert!(!ExportFormat::ActionsEnv.writes_values_to_stdout());
    }
}
