//! What gets executed, and the one call that replaces this process with it.
//!
//! # Why `exec` and not a child process
//!
//! ADR-14 gives the reason: replacing this process means **no supervisor survives holding
//! the values**, and no shell ever sees them. A `spawn` would leave a parent alive whose
//! only job is to wait, holding a copy of every secret it just fetched for the lifetime
//! of the service. That parent would also collect the signals meant for the service, so
//! the weaker option is worse twice over.
//!
//! # What this does not need, and why that is worth saying
//!
//! ADR-14 describes the wrapper as one that "sets them in its own environment" and then
//! execs. That would need `std::env::set_var`, which is `unsafe` in this edition — it is
//! not thread-safe — and every crate here forbids `unsafe_code`.
//!
//! It turns out not to be needed at all. [`Command::env`] sets the environment of the
//! process image `exec` is about to install, without this process ever mutating its own.
//! The values therefore exist in exactly two places: the `Command`'s map, and the new
//! image. This process's own environment never contains a secret, so nothing can read one
//! out of `/proc/self/environ` in the window before the `exec`.
//!
//! The honest remainder: the `Command` map is not a zeroizing allocation, and it cannot
//! be — the kernel needs a plain byte layout to build the new environment from. The
//! window is the few microseconds between building it and `exec`, in a process that then
//! ceases to exist.

use std::process::Command;

use ciphr_core::{EnvVarName, Plaintext};

use crate::error::RunError;

/// A command, its arguments, and the variables to hand it.
///
/// No `Debug`: it holds values. [`Plan::names`] is the part that is safe to print, and it
/// exists so that a wrapper can say what it delivered without saying what it was.
pub(crate) struct Plan {
    program: String,
    arguments: Vec<String>,
    variables: Vec<(EnvVarName, Plaintext)>,
}

impl Plan {
    /// Split a command line into a program and its arguments, and attach the secrets.
    ///
    /// Takes the pairs rather than an [`Environment`](ciphr_sdk::Environment) so that this
    /// type knows nothing about where they came from — and so that it stays testable
    /// without a public constructor existing on the SDK's side for the tests' benefit.
    ///
    /// # Errors
    ///
    /// [`RunError::NoCommand`] if there is nothing after `--`. Reachable, because `--`
    /// with an empty tail parses.
    pub(crate) fn new(
        command: &[String],
        variables: Vec<(EnvVarName, Plaintext)>,
    ) -> Result<Self, RunError> {
        let (program, arguments) = command.split_first().ok_or(RunError::NoCommand)?;

        Ok(Self {
            program: program.clone(),
            arguments: arguments.to_vec(),
            variables,
        })
    }

    /// The program that will replace this process.
    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    /// The variable names being handed over.
    ///
    /// Safe to print, and the reason this exists: an operator needs to be able to see
    /// that four secrets arrived under the four expected names without any of them
    /// appearing anywhere.
    pub(crate) fn names(&self) -> impl Iterator<Item = &EnvVarName> {
        self.variables.iter().map(|(name, _)| name)
    }

    /// Build the command, with the fetched variables added to the inherited environment.
    ///
    /// Inherited rather than cleared: the service still needs `PATH`, `HOME`, and whatever
    /// else its image sets. Nothing is removed, because nothing needs to be — this program
    /// reads no environment variable, so it introduces no credential into the environment
    /// that could be inherited. The credential it does use is a file, and the honest
    /// consequence of that is recorded in ADR-14: the child can still read that file, so
    /// the token wants to be scoped to the prefix the child gets.
    fn command(self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.arguments);

        for (name, value) in self.variables {
            command.env(name.as_str(), as_os_value(&value));
        }

        command
    }

    /// Replace this process with the command.
    ///
    /// **Returns only on failure.** On success there is no "after": this process image is
    /// gone, and with it every copy of every value it held. That is why the return type is
    /// the error rather than a `Result` — a success has nothing to return to.
    #[cfg(unix)]
    pub(crate) fn exec(self) -> RunError {
        use std::os::unix::process::CommandExt;

        let program = self.program.clone();
        // `exec` returns only if it failed, so this is always an error.
        let error = self.command().exec();

        RunError::Exec {
            program,
            reason: error.kind().to_string(),
            not_found: error.kind() == std::io::ErrorKind::NotFound,
        }
    }

    /// The same, on a platform that has no `exec`.
    ///
    /// Unreachable in practice: [`is_supported`] is checked before anything is fetched, so
    /// this program refuses before it reads a secret rather than after. It exists so that
    /// the crate compiles on the development platform, and it refuses rather than falling
    /// back to a child process — see [`RunError::NoExec`].
    #[cfg(not(unix))]
    pub(crate) fn exec(self) -> RunError {
        // `self` is dropped here, which wipes every value it holds. On the platform that
        // matters, `exec` never gets that far, and the process image is what disappears.
        drop(self.command());
        RunError::NoExec
    }
}

/// Whether this platform can replace a process.
///
/// Checked before the token is read and before anything is fetched. A refusal after the
/// fetch would have written audit entries for reads that were then thrown away, which
/// makes the trail describe an access that never served anything.
pub(crate) const fn is_supported() -> bool {
    cfg!(unix)
}

/// A secret value as an OS string, without going through `String`.
///
/// On Unix an environment value is bytes, and this is the conversion that says so: no
/// UTF-8 validation, no second copy through a `String`. Elsewhere it goes through the
/// lossy conversion, which is only reached on the platform that refuses to exec anyway.
#[cfg(unix)]
fn as_os_value(value: &Plaintext) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;

    std::ffi::OsString::from_vec(value.expose().to_vec())
}

#[cfg(not(unix))]
fn as_os_value(value: &Plaintext) -> std::ffi::OsString {
    std::ffi::OsString::from(String::from_utf8_lossy(value.expose()).into_owned())
}

#[cfg(test)]
mod tests {
    use ciphr_core::{EnvVarName, Plaintext};

    use super::Plan;
    use crate::error::RunError;

    fn command(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    /// The arguments the built command will pass on.
    ///
    /// Read off the `Command` rather than from a getter on `Plan`: what matters is what
    /// the child receives, and a getter would be a second answer to the same question.
    fn arguments_of(plan: Plan) -> Vec<String> {
        plan.command()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn variables(pairs: &[(&str, &str)]) -> Vec<(EnvVarName, Plaintext)> {
        pairs
            .iter()
            .map(|(name, value)| {
                (
                    EnvVarName::parse(name).expect("a usable name"),
                    Plaintext::from(value.as_bytes()),
                )
            })
            .collect()
    }

    #[test]
    fn nothing_after_the_separator_is_refused() {
        // `--` with an empty tail parses, so this is reachable rather than theoretical.
        match Plan::new(&[], Vec::new()) {
            Err(RunError::NoCommand) => {}
            Err(other) => panic!("expected NoCommand, got {other}"),
            Ok(_) => panic!("an empty command must be refused"),
        }
    }

    #[test]
    fn the_first_word_is_the_program_and_the_rest_are_arguments() {
        let plan = Plan::new(
            &command(&["/original/entrypoint", "--flag", "value"]),
            Vec::new(),
        )
        .expect("a command");

        assert_eq!(plan.program(), "/original/entrypoint");
        assert_eq!(arguments_of(plan), ["--flag", "value"]);
    }

    #[test]
    fn a_program_with_no_arguments_is_not_a_special_case() {
        let plan = Plan::new(&command(&["/bin/true"]), Vec::new()).expect("a command");
        assert_eq!(plan.program(), "/bin/true");
        assert_eq!(plan.names().count(), 0);
        assert!(arguments_of(plan).is_empty());
    }

    #[test]
    fn an_argument_that_looks_like_a_flag_stays_an_argument() {
        // The realistic case: the original entrypoint takes `--config` and this program
        // must not try to interpret it. Splitting happens on position, never on shape.
        let plan = Plan::new(
            &command(&["/entrypoint", "--prefix", "--url", "--"]),
            Vec::new(),
        )
        .expect("a command");

        assert_eq!(arguments_of(plan), ["--prefix", "--url", "--"]);
    }

    #[test]
    fn the_names_are_reportable_and_the_values_are_not_in_reach() {
        let plan = Plan::new(
            &command(&["/bin/true"]),
            variables(&[("DB_PASSWORD", "hunter2"), ("API_TOKEN", "t0ken")]),
        )
        .expect("a command");

        let names: Vec<&str> = plan.names().map(EnvVarName::as_str).collect();
        assert_eq!(names, ["DB_PASSWORD", "API_TOKEN"]);

        // There is deliberately no accessor for the values: the only thing that reads
        // them is `command`, which is private, and after that the kernel. If a getter for
        // them ever appears here, that is the change to argue about.
    }

    #[test]
    fn the_variables_reach_the_command_and_the_inherited_environment_survives() {
        // What this checks is the part `exec` would consume: a `Command` carrying both
        // the fetched values and whatever the image already set. Checked through
        // `get_envs`, because the alternative is asserting it after a process has been
        // replaced, which leaves nothing to assert in.
        let plan = Plan::new(
            &command(&["/bin/sh", "-c", "true"]),
            variables(&[("DB_PASSWORD", "hunter2")]),
        )
        .expect("a command");

        let built = plan.command();
        let overrides: Vec<(String, Option<String>)> = built
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();

        assert_eq!(
            overrides,
            [("DB_PASSWORD".to_owned(), Some("hunter2".to_owned()))]
        );
        // Nothing is cleared and nothing is removed: the service still needs `PATH`.
        assert!(
            !overrides.iter().any(|(_, value)| value.is_none()),
            "a `None` here would mean a variable is being unset"
        );
        assert_eq!(built.get_program(), std::ffi::OsStr::new("/bin/sh"));
    }
}
