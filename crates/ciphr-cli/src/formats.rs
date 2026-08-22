//! Export and import formats.
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

use ciphr_core::{EnvNameError, EnvVarName, SecretPath};

use crate::error::CliError;

/// A path and its value, ready to be written out.
pub(crate) struct Exported {
    /// Where it came from.
    pub(crate) path: SecretPath,
    /// The value.
    pub(crate) value: String,
}

/// The variable names for a whole export, or the reason it has none.
///
/// The rule itself is in [`ciphr_core::EnvVarName`], not here: `ciphr run` and the SDK
/// derive the same name from the same path, and a second copy of the rule is how those
/// three start to disagree (ADR-18).
fn assign_names(secrets: &[Exported]) -> Result<Vec<EnvVarName>, EnvNameError> {
    EnvVarName::assign(secrets.iter().map(|secret| &secret.path))
}

/// Which shape an export takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// `KEY=value`, quoted, for a `.env` file.
    Dotenv,
    /// `::add-mask::` lines followed by `KEY=value` for `$GITHUB_ENV`.
    ActionsEnv,
    /// A JSON object of path to value.
    Json,
}

impl ExportFormat {
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
    pub(crate) fn render(self, secrets: &[Exported]) -> Result<String, CliError> {
        match self {
            // `?` rather than a bare call: this one fails only on a name, and the
            // signature now carries the delimiter failure the Actions form can have.
            Self::Dotenv => Ok(render_dotenv(secrets)?),
            Self::ActionsEnv => {
                let (masks, assignments) = render_actions_env(secrets)?;
                Ok(format!("{masks}{assignments}"))
            }
            Self::Json => Ok(render_json(secrets)),
        }
    }
}

/// `KEY='value'` lines.
///
/// Single quotes with embedded single quotes escaped, which is the one form that needs
/// no further reasoning about what the shell will do to `$`, backticks, or backslashes
/// inside the value.
///
/// # Errors
///
/// [`EnvNameError`] if the set has no usable names. Nothing is rendered in that case: a
/// partial `.env` file is a service that starts with half its configuration.
pub(crate) fn render_dotenv(secrets: &[Exported]) -> Result<String, EnvNameError> {
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
fn heredoc_delimiter(name: &str, value: &str) -> Result<String, CliError> {
    for _ in 0..DELIMITER_ATTEMPTS {
        let mut bytes = [0u8; DELIMITER_BYTES];
        if getrandom::fill(&mut bytes).is_err() {
            return Err(CliError::ExportDelimiter {
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
    Err(CliError::ExportDelimiter {
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
/// [`CliError::EnvName`] if the set has no usable names — checked before a single
/// `::add-mask::` is produced, so a refused export has printed nothing at all. And
/// [`CliError::ExportDelimiter`] if a multi-line value cannot be given a delimiter it
/// could not close itself, which is the same discipline one line further out: the
/// refusal happens before anything is written.
// `format_push_string` fires on the two lines below. Building the heredoc block as one
// string is clearer than three `writeln!` calls, and this function is not on a hot path
// — it runs once per export.
#[allow(clippy::format_push_string)]
pub(crate) fn render_actions_env(secrets: &[Exported]) -> Result<(String, String), CliError> {
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
pub(crate) fn render_json(secrets: &[Exported]) -> String {
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
fn shell_single_quote(value: &str) -> String {
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

/// One line of a `.env` file, parsed.
///
/// `Debug` prints the key and the value. That is acceptable only because nothing in the
/// CLI formats this type — it exists to be consumed immediately — and because a test
/// needs it to report an unexpected success. Do not log one.
#[derive(Debug)]
pub(crate) struct DotEnvEntry {
    /// The variable name.
    pub(crate) key: String,
    /// The value, unquoted.
    pub(crate) value: String,
}

/// Parse a `.env` file.
///
/// Handles what such files actually contain: comments, blank lines, `export` prefixes,
/// and values in single or double quotes. It deliberately does **not** expand `$VAR`
/// references — an import that interpreted the value would store something other than
/// what the file says, and the point of the import is to move what is there.
///
/// # Errors
///
/// Returns the line number and reason for the first line it cannot read. An import that
/// skipped unreadable lines would silently move part of a corpus, and the missing half
/// would surface as a broken deploy much later.
pub(crate) fn parse_dotenv(text: &str) -> Result<Vec<DotEnvEntry>, (usize, String)> {
    let mut entries = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, value)) = line.split_once('=') else {
            return Err((number, format!("no '=' in {:?}", truncate(line))));
        };

        // The same rule the export applies, so that a corpus which leaves through
        // `export --format dotenv` comes back through this door unchanged (ADR-18). The
        // key is truncated for the message but validated whole: a name is refused for
        // what it is, not for the part of it that fits in an error.
        let key = key.trim();
        let name = EnvVarName::parse(key).map_err(|error| {
            let reason = match &error {
                EnvNameError::NotAName { reason, .. } => reason.to_string(),
                // Unreachable in practice: a collision needs a set, and this validates
                // one name. Spelled out rather than left to a wildcard so that a new
                // variant is a compile error here instead of a message that says nothing.
                collision @ EnvNameError::Collision { .. } => collision.to_string(),
            };
            (
                number,
                format!(
                    "{:?} is not a usable variable name: {reason}",
                    truncate(key)
                ),
            )
        })?;

        entries.push(DotEnvEntry {
            key: name.as_str().to_owned(),
            value: unquote(value.trim()),
        });
    }

    Ok(entries)
}

/// Remove one layer of matching quotes.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

/// Shorten a fragment for an error message.
///
/// Error messages about a `.env` file quote the offending text, and that file is full
/// of secrets — so only the part that identifies the problem is shown, and never more
/// than a few characters of it.
fn truncate(text: &str) -> String {
    const LIMIT: usize = 24;
    if text.chars().count() <= LIMIT {
        return text.to_owned();
    }
    let shortened: String = text.chars().take(LIMIT).collect();
    format!("{shortened}…")
}

#[cfg(test)]
mod tests {
    use super::{
        ExportFormat, Exported, parse_dotenv, render_actions_env, render_dotenv, shell_single_quote,
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
            Err(EnvNameError::Collision { .. })
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
        // program's own import rejects.
        let secrets = [exported("infra/a/db-password", "x")];
        assert!(matches!(
            render_dotenv(&secrets),
            Err(EnvNameError::NotAName { .. })
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
    fn dotenv_parsing_handles_what_such_files_actually_contain() {
        let text = r#"
# a comment

export QUOTED="with spaces"
SINGLE='single quoted'
PLAIN=plain
EMPTY=
WITH_EQUALS=a=b
  INDENTED = spaced
"#;
        let entries = parse_dotenv(text).expect("must parse");
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();

        assert_eq!(
            pairs,
            [
                ("QUOTED", "with spaces"),
                ("SINGLE", "single quoted"),
                ("PLAIN", "plain"),
                ("EMPTY", ""),
                ("WITH_EQUALS", "a=b"),
                ("INDENTED", "spaced"),
            ]
        );
    }

    #[test]
    fn dotenv_parsing_does_not_expand_references() {
        // Storing the expansion rather than the text would store something the file
        // does not say.
        let entries = parse_dotenv("A=$OTHER/suffix").expect("must parse");
        assert_eq!(entries[0].value, "$OTHER/suffix");
    }

    #[test]
    fn an_unreadable_line_stops_the_import_and_says_where() {
        let (line, reason) =
            parse_dotenv("GOOD=1\nthis is not an assignment\n").expect_err("must be refused");
        assert_eq!(line, 2);
        assert!(reason.contains("no '='"));

        let (line, _) = parse_dotenv("BAD-KEY=1").expect_err("must be refused");
        assert_eq!(line, 1);
    }

    #[test]
    fn error_messages_do_not_quote_a_whole_line() {
        // A `.env` file is full of secrets, so an error about a line it cannot read
        // must not reproduce the line. A long line with no `=` is the case that
        // triggers it: the message identifies the problem and shows only its start.
        let long = "x".repeat(200);
        let (line, reason) = parse_dotenv(&long).expect_err("a line with no '=' is refused");

        assert_eq!(line, 1);
        assert!(reason.len() < 60, "got {reason}");
        assert!(reason.contains('…'), "got {reason}");
    }

    #[test]
    fn a_long_variable_name_is_accepted_because_it_is_a_valid_one() {
        // Checked because the previous test used to assume the opposite: 100 characters
        // of `K` is a usable name, and a path segment may be up to 128 bytes.
        let entries = parse_dotenv(&format!("{}=x", "K".repeat(100))).expect("must parse");
        assert_eq!(entries[0].key.len(), 100);
    }
}
