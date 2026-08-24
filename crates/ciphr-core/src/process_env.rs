//! Which variable names may be *injected into a process environment*.
//!
//! # This is not the naming rule, and the difference is the point
//!
//! [`crate::env_name`] answers one question: is this a name a shell can read
//! (ADR-18). It has exactly one answer and four consumers, and it stays that way.
//!
//! This module answers a different one: **may a name that somebody else chose
//! decide how a process starts?** It applies only where a fetched set becomes the
//! environment of a program — `ciphr-run` before `exec`, and `ciphr-ci` writing
//! into a runner's environment file. It deliberately does *not* apply to
//! `ciphr export`, which writes a `.env` file for a human to place: refusing a
//! name there would refuse a corpus somebody is migrating, and no process starts.
//!
//! # What the problem is
//!
//! The variable name of a secret is its last path segment. Where a consumer
//! fetches a **prefix**, the set of names is therefore whatever the store holds at
//! that moment — so an identity with `write` on that prefix chooses environment
//! variable names for the consuming service. Most names are data. A few are read
//! by the loader or by a language runtime *before* the program's own code runs:
//!
//! - `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` and the rest of `LD_*` —
//!   the dynamic loader, and `DYLD_*` for the same reason elsewhere.
//! - `NODE_OPTIONS`, which is the sharpest of them: `--inspect=0.0.0.0:9229`
//!   needs **no file in the image**, opens a debugger port, and whoever reaches it
//!   runs code as the service. This is the mechanism behind CVE-2020-15228, which
//!   is why GitHub Actions stopped letting a workflow set environment variables
//!   through a log directive.
//! - `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `BASH_ENV`,
//!   `JAVA_TOOL_OPTIONS` — a startup hook per ecosystem.
//! - `PATH` and `IFS`, which decide what a name resolves to and how a word splits.
//!
//! F4 of `docs/assurance/reviews/review-2026-08-24-full-repository.md`. The rest of the list needs a
//! writable path inside the image to be useful, so it is narrower than
//! `NODE_OPTIONS` — but "narrower" is not a defence, and `write` should not be a
//! way to reach `exec`.
//!
//! # What this is worth, and what it is not
//!
//! **A denylist is incomplete, and saying so is part of shipping it.** Every
//! runtime has an option variable, some are per-version, and this list cannot keep
//! up with images this project does not own. What it does is remove the names an
//! attacker reaches for first, and turn the general case into one that needs a
//! name nobody here listed.
//!
//! The property that actually bounds this is upstream of the list: **name the
//! paths.** With `--path`, the set is what the container definition says and a
//! newly written secret is not fetched at all. `--prefix` is the form where the
//! store decides, and both binaries document that.

/// Names whose value is read before the program's own code runs.
///
/// Exact matches. The prefix families are handled by [`process_control_reason`],
/// because `LD_` has too many members to list and the next one is not knowable.
const CONTROL_NAMES: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "IFS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "MALLOC_CONF",
    "NODE_OPTIONS",
    "NODE_REPL_EXTERNAL_MODULE",
    "PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "RUBYLIB",
    "RUBYOPT",
];

/// Name prefixes whose whole family is read by a loader.
const CONTROL_PREFIXES: &[&str] = &["LD_", "DYLD_"];

/// Whether this name decides how a process starts, and why.
///
/// `None` means the name is data as far as this rule is concerned — which is not a
/// promise that it is inert in every image, only that it is not one of the names
/// this project refuses to hand over.
///
/// # Examples
///
/// ```
/// use ciphr_core::process_env::process_control_reason;
///
/// assert!(process_control_reason("DB_PASSWORD").is_none());
/// assert!(process_control_reason("LD_PRELOAD").is_some());
/// assert!(process_control_reason("NODE_OPTIONS").is_some());
/// ```
#[must_use]
pub fn process_control_reason(name: &str) -> Option<&'static str> {
    if CONTROL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Some("the dynamic loader reads it before the program starts");
    }

    if CONTROL_NAMES.contains(&name) {
        return Some("a language runtime or the shell reads it before the program starts");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::process_control_reason;

    #[test]
    fn ordinary_secret_names_are_data() {
        for name in [
            "DB_PASSWORD",
            "API_TOKEN",
            "DEPLOY_KEY",
            "SMTP_PASSWORD",
            "LDAP_BIND_PASSWORD",
        ] {
            assert!(
                process_control_reason(name).is_none(),
                "{name} is an ordinary secret name"
            );
        }
    }

    /// `LDAP_BIND_PASSWORD` starts with `LD` and must not be caught by the `LD_`
    /// family. A refusal that fires on a real secret name teaches people to work
    /// around the rule.
    #[test]
    fn the_loader_family_matches_the_prefix_and_not_a_word_starting_with_it() {
        assert!(process_control_reason("LD_PRELOAD").is_some());
        assert!(process_control_reason("LD_LIBRARY_PATH").is_some());
        assert!(process_control_reason("LDAP_URL").is_none());
        assert!(process_control_reason("LDFLAGS").is_none());
    }

    #[test]
    fn the_names_that_need_no_file_in_the_image_are_covered() {
        // `NODE_OPTIONS=--inspect=0.0.0.0:9229` opens a debugger port and needs
        // nothing else, which is what makes it the sharpest of these.
        assert!(process_control_reason("NODE_OPTIONS").is_some());
        assert!(process_control_reason("PYTHONWARNINGS").is_some());
        assert!(process_control_reason("BASH_ENV").is_some());
    }

    #[test]
    fn path_and_ifs_count() {
        // Not startup hooks, but they decide what a name resolves to and how a
        // word splits -- which is the same outcome one step later.
        assert!(process_control_reason("PATH").is_some());
        assert!(process_control_reason("IFS").is_some());
    }

    #[test]
    fn the_reason_is_a_sentence_a_message_can_carry() {
        let reason = process_control_reason("LD_PRELOAD").expect("a loader variable");
        assert!(reason.contains("before the program starts"), "{reason}");
    }
}
