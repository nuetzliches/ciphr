//! A set of secrets under the names a process reads them by.
//!
//! This is route C from plan section 13 in one type: an application fetches its own
//! secrets at startup, so nothing is rendered to a file, nothing is baked into the
//! container configuration, and the audit entry names the *service* rather than the
//! runner that deployed it.
//!
//! # What this type deliberately does not do
//!
//! It does not set a single environment variable. Modifying the process environment is
//! `unsafe` in this edition — it is not thread-safe, and this crate forbids `unsafe_code`
//! — so the choice is made for us, and it happens to be the better one:
//!
//! - **Reading from here directly is strictly better than an environment variable.** A
//!   value that never reaches the environment never reaches `/proc/<pid>/environ`, which
//!   is the one exposure route C otherwise still has (plan section 13, A5 of the threat
//!   model).
//! - **A child process is the case where the environment is unavoidable**, and
//!   `Command::env` sets it for the child without touching this process. That is the same
//!   mechanism `ciphr run` uses (ADR-14), which is why this type is shaped to feed it.
//!
//! An `into_entries()` that hands over the values is provided for exactly that, and it
//! consumes the [`Environment`] — the mapping does not stay behind holding a second copy.

use ciphr_core::{EnvVarName, Plaintext};

use crate::error::SdkError;
use crate::types::Secret;

/// Secrets keyed by the variable name each of them is read under.
///
/// The names come from [`EnvVarName`], so they match what `ciphr export` writes and what
/// `ciphr run` will set for the same paths (ADR-18). A set that would produce a collision
/// never becomes one of these.
///
/// No `Debug`, no `Display`, no `Serialize`: it holds values.
pub struct Environment {
    entries: Vec<(EnvVarName, Plaintext)>,
}

impl Environment {
    /// Build one from what the service returned.
    ///
    /// # Errors
    ///
    /// [`SdkError::EnvName`] if the set has no usable names. The caller has normally
    /// checked that already, before spending the reads — this is the second check, on
    /// what actually came back, because the service returns the paths it served and those
    /// are what the names have to come from.
    pub(crate) fn assemble(secrets: Vec<Secret>) -> Result<Self, SdkError> {
        let paths: Vec<_> = secrets.iter().map(|secret| secret.path.clone()).collect();
        let names = EnvVarName::assign(&paths)?;

        Ok(Self {
            entries: names
                .into_iter()
                .zip(secrets.into_iter().map(|secret| secret.value))
                .collect(),
        })
    }

    /// The value for one variable name, if it is in here.
    ///
    /// Borrowed rather than cloned: every copy of a plaintext is a copy that has to be
    /// wiped, and this one does not need to exist.
    pub fn get(&self, name: &str) -> Option<&Plaintext> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.as_str() == name)
            .map(|(_, value)| value)
    }

    /// The names, in the order the service returned their paths.
    ///
    /// Safe to log. That is the point of having it: a service can record *which* secrets
    /// it received without recording any of them.
    pub fn names(&self) -> impl Iterator<Item = &EnvVarName> {
        self.entries.iter().map(|(name, _)| name)
    }

    /// How many secrets are in here.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it is empty.
    ///
    /// Never true for an [`Environment`] built by
    /// [`Client::environment`](crate::Client::environment), which refuses an empty prefix
    /// rather than returning one.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take the pairs out, for handing to a child process.
    ///
    /// Consumes the mapping so that the values exist in one place afterwards:
    ///
    /// ```no_run
    /// use std::process::Command;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let environment: ciphr_sdk::Environment = unimplemented!();
    /// let mut command = Command::new("/original/entrypoint");
    /// for (name, value) in environment.into_entries() {
    ///     // The one place a value becomes text again. `expose` is deliberately ugly to
    ///     // write, and every call site is meant to be greppable.
    ///     command.env(name.as_str(), String::from_utf8(value.expose().to_vec())?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_entries(self) -> Vec<(EnvVarName, Plaintext)> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use ciphr_core::{Plaintext, SecretPath, SecretVersion};

    use super::Environment;
    use crate::error::SdkError;
    use crate::types::Secret;

    fn secret(path: &str, value: &str) -> Secret {
        Secret {
            path: SecretPath::parse(path).expect("valid path"),
            version: SecretVersion::FIRST,
            value: Plaintext::new(value.as_bytes().to_vec()),
            created_at: 0,
            created_by: "test".to_owned(),
        }
    }

    #[test]
    fn names_come_from_the_shared_rule() {
        let environment = Environment::assemble(vec![
            secret("infra/a/DB_PASSWORD", "one"),
            secret("infra/a/API_TOKEN", "two"),
        ])
        .expect("usable names");

        let names: Vec<&str> = environment
            .names()
            .map(ciphr_core::EnvVarName::as_str)
            .collect();
        assert_eq!(names, ["DB_PASSWORD", "API_TOKEN"]);
        assert_eq!(environment.len(), 2);
        assert!(!environment.is_empty());
    }

    #[test]
    fn a_value_is_reachable_by_name_and_by_nothing_else() {
        let environment =
            Environment::assemble(vec![secret("infra/a/DB_PASSWORD", "hunter2")]).expect("usable");

        assert_eq!(
            environment.get("DB_PASSWORD").expect("present").expose(),
            b"hunter2"
        );
        // Not by path, and not by a name that is not in here.
        assert!(environment.get("infra/a/DB_PASSWORD").is_none());
        assert!(environment.get("OTHER").is_none());
    }

    #[test]
    fn a_colliding_response_is_refused_even_though_the_request_was_checked() {
        // The request-side check cannot cover this on its own: the service returns the
        // paths it served, and those are what the names come from.
        // `expect_err` is unavailable here, and that is the point: it would require
        // `Environment: Debug`, and this type holds values.
        let outcome = Environment::assemble(vec![
            secret("infra/a/db/PASSWORD", "right"),
            secret("infra/a/cache/PASSWORD", "wrong"),
        ]);

        match outcome {
            Err(SdkError::EnvName(_)) => {}
            Err(other) => panic!("expected a naming error, got {other}"),
            Ok(_) => panic!("a colliding response must be refused"),
        }
    }

    #[test]
    fn the_pairs_come_out_in_order_for_a_child_process() {
        let environment =
            Environment::assemble(vec![secret("infra/a/ONE", "1"), secret("infra/a/TWO", "2")])
                .expect("usable");

        let entries = environment.into_entries();
        let rendered: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose()))
            .collect();
        assert_eq!(
            rendered,
            [("ONE", b"1".as_slice()), ("TWO", b"2".as_slice())]
        );
    }
}
