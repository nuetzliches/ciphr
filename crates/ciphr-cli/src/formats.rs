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

use ciphr_core::SecretPath;

/// A path and its value, ready to be written out.
pub(crate) struct Exported {
    /// Where it came from.
    pub(crate) path: SecretPath,
    /// The value.
    pub(crate) value: String,
}

impl Exported {
    /// The environment variable name for this secret: the last path segment.
    ///
    /// `infra/service-a/DB_PASSWORD` becomes `DB_PASSWORD`. The convention is
    /// deliberate — a path's last segment is the name the consuming process already
    /// uses, so an export needs no mapping table for the common case.
    pub(crate) fn variable_name(&self) -> &str {
        self.path
            .segments()
            .next_back()
            .unwrap_or_else(|| self.path.as_str())
    }
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
    pub(crate) fn render(self, secrets: &[Exported]) -> String {
        match self {
            Self::Dotenv => render_dotenv(secrets),
            Self::ActionsEnv => {
                let (masks, assignments) = render_actions_env(secrets);
                format!("{masks}{assignments}")
            }
            Self::Json => render_json(secrets),
        }
    }
}

/// `KEY='value'` lines.
///
/// Single quotes with embedded single quotes escaped, which is the one form that needs
/// no further reasoning about what the shell will do to `$`, backticks, or backslashes
/// inside the value.
pub(crate) fn render_dotenv(secrets: &[Exported]) -> String {
    let mut out = String::new();
    for secret in secrets {
        out.push_str(secret.variable_name());
        out.push('=');
        out.push_str(&shell_single_quote(&secret.value));
        out.push('\n');
    }
    out
}

/// The two halves of an Actions-style export: the mask commands, and the assignments.
///
/// Returned separately because they go to different places — the masks to standard
/// output, where the runner reads workflow commands, and the assignments to the file
/// named by `$GITHUB_ENV`.
// `format_push_string` fires on the two lines below. Building the heredoc block as one
// string is clearer than three `writeln!` calls, and this function is not on a hot path
// — it runs once per export.
#[allow(clippy::format_push_string)]
pub(crate) fn render_actions_env(secrets: &[Exported]) -> (String, String) {
    let mut masks = String::new();
    let mut assignments = String::new();

    for secret in secrets {
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

        let name = secret.variable_name();
        if secret.value.contains('\n') {
            // The heredoc form, which is the only way to put a multi-line value into
            // `$GITHUB_ENV`. The delimiter includes the variable name so that a value
            // containing the word "EOF" cannot terminate its own block.
            let delimiter = format!("ciphr_{name}_EOF");
            assignments.push_str(&format!(
                "{name}<<{delimiter}\n{}\n{delimiter}\n",
                secret.value
            ));
        } else {
            assignments.push_str(&format!("{name}={}\n", secret.value));
        }
    }

    (masks, assignments)
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

        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err((
                number,
                format!("{:?} is not a usable variable name", truncate(key)),
            ));
        }

        entries.push(DotEnvEntry {
            key: key.to_owned(),
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
    use ciphr_core::SecretPath;

    fn exported(path: &str, value: &str) -> Exported {
        Exported {
            path: SecretPath::parse(path).expect("valid"),
            value: value.to_owned(),
        }
    }

    #[test]
    fn the_variable_name_is_the_last_path_segment() {
        assert_eq!(
            exported("infra/service-a/DB_PASSWORD", "x").variable_name(),
            "DB_PASSWORD"
        );
        assert_eq!(exported("SINGLE", "x").variable_name(), "SINGLE");
    }

    #[test]
    fn dotenv_quoting_survives_the_shell() {
        let secrets = [exported("a/PASSWORD", "p4ss w'rd$`\\")];
        let rendered = render_dotenv(&secrets);
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
        let (masks, assignments) = render_actions_env(&secrets);

        assert_eq!(masks, "::add-mask::s3cret\n");
        assert_eq!(assignments, "TOKEN=s3cret\n");

        let combined = ExportFormat::ActionsEnv.render(&secrets);
        let mask_at = combined.find("::add-mask::").expect("a mask");
        let assign_at = combined.find("TOKEN=").expect("an assignment");
        assert!(mask_at < assign_at, "masks must come first");
    }

    #[test]
    fn a_multi_line_value_is_masked_line_by_line_and_assigned_with_a_heredoc() {
        // Runners match literal strings, so a value with a newline is never masked as a
        // whole — and `KEY=value` cannot express it at all.
        let secrets = [exported("a/KEY", "-----BEGIN-----\nmiddle\n-----END-----")];
        let (masks, assignments) = render_actions_env(&secrets);

        assert_eq!(masks.lines().count(), 3);
        assert!(masks.contains("::add-mask::-----BEGIN-----"));
        assert!(masks.contains("::add-mask::middle"));

        assert!(assignments.starts_with("KEY<<ciphr_KEY_EOF\n"));
        assert!(assignments.ends_with("ciphr_KEY_EOF\n"));
    }

    #[test]
    fn an_empty_line_is_not_masked() {
        // `::add-mask::` with an empty string would ask the runner to redact
        // everything.
        let secrets = [exported("a/KEY", "first\n\nlast")];
        let (masks, _) = render_actions_env(&secrets);
        assert_eq!(masks.lines().count(), 2);
    }

    #[test]
    fn json_export_is_keyed_by_full_path() {
        let secrets = [exported("infra/a/ONE", "1"), exported("infra/b/TWO", "2")];
        let rendered = ExportFormat::Json.render(&secrets);
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
