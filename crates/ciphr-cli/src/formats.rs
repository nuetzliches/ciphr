//! Reading an existing `.env` corpus in.
//!
//! The other direction — rendering secrets out as dotenv, an Actions environment file,
//! or JSON — is in `ciphr-export`, which this crate depends on. It moved there when
//! `ciphr-ci` appeared (ADR-25): the masking discipline is the part of an export that
//! has to be identical in both binaries, and the way to keep two implementations
//! identical is not to have two.
//!
//! What stays here is the parser, because nothing else reads a `.env` file: `ciphr
//! import` runs on a host with the store, moving a corpus in once.

use ciphr_core::{EnvNameError, EnvVarName};

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
    use super::parse_dotenv;

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
