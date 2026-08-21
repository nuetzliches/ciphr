//! Optional surface: what this build offers beyond the core, and the record that says
//! why.
//!
//! [ADR-20](../../../docs/adr/0020-optional-surface.md) decides that optionality lives
//! in a named, deliberately small set of **entries**, never in the reviewed core. Each
//! entry adds attack surface, each is off until a deployment turns it on, and turning
//! one on is a recorded decision rather than a flag.
//!
//! # The record is the point
//!
//! Three fields, all required: whether the entry is on, the date the deployment
//! accepted the cost, and the reason. **The server refuses to start on an entry that
//! is on and cannot say since when and why** — the same refusal as starting without an
//! audit device, because a configuration that cannot answer the question is a
//! configuration error rather than an operating mode.
//!
//! The alternative was a `[features]` table of booleans, which records the state
//! without the trade. It answers "is this on" and never "who decided that, when, and
//! against what" — and six months later an unexplained flag reads as an accident,
//! whose safest-looking fix is to restore the default.
//!
//! # Two kinds, and why a build entry checks two things
//!
//! A **runtime** entry is composed at startup: off means the route is never registered
//! and the handler sits in no reachable path. A **build** entry is a Cargo feature,
//! absent from the default build, chosen where a deployment has to be able to prove the
//! code is *not there* rather than merely not called.
//!
//! For a runtime entry the configuration decides. For a build entry the *binary*
//! decides, and the configuration has to agree with it — so both directions are a
//! refusal:
//!
//! - Compiled in and not named in the configuration: the deployment is running surface
//!   it never recorded a decision about.
//! - Named in the configuration and not compiled in: worse, and the reason this check
//!   exists in both directions. The deployment believes it has bait recognition, has
//!   written down when and why, and has none. Nothing would ever say so — the entry
//!   would simply never fire, which is indistinguishable from bait nobody took.
//!
//! # What is visible where
//!
//! Plan section 10's rule: an unauthenticated endpoint may report **what the process
//! enforces** and never **what is stored**. Which entries are active is enforcement, so
//! `/v1/health` carries the names. The reason is prose an operator wrote about their own
//! environment, so it is authenticated only.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// How an entry is switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A Cargo feature, absent from the default build. Off means the code is not in
    /// the binary.
    Build,
    /// Composed at startup. Off means the route is never registered.
    ///
    /// No entry uses this yet: `viewer_api` and `bulk_export` are built and are not
    /// entries, which plan section 24 says they should become. The variant exists so
    /// that the change is a row in [`ENTRIES`] rather than an invention.
    #[allow(dead_code)]
    Runtime,
}

/// One thing a deployment may turn on.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// The name a configuration uses. Stable: it appears in a deployment's file.
    pub name: &'static str,
    /// How it is switched on.
    pub kind: Kind,
    /// What its absence costs, in one sentence.
    ///
    /// Part of the entry rather than of the documentation, because the cost is what a
    /// deployment is deciding about and `GET /v1/surface` is where it gets asked.
    pub cost: &'static str,
    /// Whether this build contains the code.
    ///
    /// Always `true` for a runtime entry: the code is compiled in and the question is
    /// whether it was composed.
    pub compiled_in: bool,
}

/// Every entry this version knows about.
///
/// A closed list, in one place, so that "what can a deployment turn on" is a question
/// with an answer rather than a search.
pub const ENTRIES: &[Entry] = &[Entry {
    name: "honeypot_alert",
    kind: Kind::Build,
    cost: "No detection of bait. A deployment that plants none pays nothing for the \
           absence, and gets the strongest form of ADR-15's indistinguishability claim: \
           code that is not compiled in has no timing to get wrong.",
    compiled_in: cfg!(feature = "honeypot_alert"),
}];

/// Look an entry up by the name a configuration used.
fn entry(name: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|entry| entry.name == name)
}

/// One `[[surface]]` stanza, as written in the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceConfig {
    /// Which entry. Must be one of [`ENTRIES`].
    pub entry: String,
    /// The date the deployment accepted the cost, as `YYYY-MM-DD`.
    pub accepted: String,
    /// Why this deployment wants it. Prose, and deployment-specific.
    pub reason: String,
}

/// An entry that is on, with the record that says since when and why.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveEntry {
    /// The entry name.
    pub name: &'static str,
    /// How it is switched on.
    pub kind: Kind,
    /// When the deployment accepted the cost.
    pub accepted: String,
    /// Why, in the operator's own words.
    pub reason: String,
    /// What its absence would cost.
    pub cost: &'static str,
}

/// The surface this process is actually running.
#[derive(Debug, Clone, Default)]
pub struct Active {
    entries: Vec<ActiveEntry>,
}

impl Active {
    /// The active entries, with their records.
    pub fn entries(&self) -> &[ActiveEntry] {
        &self.entries
    }

    /// Just the names, for `/v1/health`.
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|active| active.name).collect()
    }

    /// One line naming the active surface, for the startup audit entry.
    ///
    /// `none` rather than an empty string: a trail reader has to be able to tell "this
    /// deployment turned nothing on" from "this version did not record it".
    pub fn summary(&self) -> String {
        if self.entries.is_empty() {
            return "none".to_owned();
        }
        self.entries
            .iter()
            .map(|active| active.name)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Check a configuration's surface stanzas against what this binary contains.
///
/// # Errors
///
/// Returns a [`ConfigError`] variant per distinct mistake, because the fix differs:
/// an unknown name, a repeated one, a missing or malformed date, an empty reason, an
/// entry this build has and the configuration does not mention, or one the
/// configuration mentions and this build does not have.
pub fn resolve(configured: &[SurfaceConfig]) -> Result<Active, ConfigError> {
    let mut entries: Vec<ActiveEntry> = Vec::new();

    for stanza in configured {
        let Some(known) = entry(&stanza.entry) else {
            return Err(ConfigError::SurfaceUnknown {
                name: stanza.entry.clone(),
                known: ENTRIES
                    .iter()
                    .map(|entry| entry.name)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        };

        if entries.iter().any(|active| active.name == known.name) {
            return Err(ConfigError::SurfaceDuplicate {
                name: known.name.to_owned(),
            });
        }

        if !is_iso_date(&stanza.accepted) {
            return Err(ConfigError::SurfaceDate {
                name: known.name.to_owned(),
                found: stanza.accepted.clone(),
            });
        }

        if stanza.reason.trim().is_empty() {
            return Err(ConfigError::SurfaceReason {
                name: known.name.to_owned(),
            });
        }

        entries.push(ActiveEntry {
            name: known.name,
            kind: known.kind,
            accepted: stanza.accepted.clone(),
            reason: stanza.reason.clone(),
            cost: known.cost,
        });
    }

    // Agreement between the binary and the file, in a second pass rather than inside
    // the loop above. The order is not cosmetic: checked per stanza, the *first*
    // stanza of a malformed list would fail on "not built" and hide the duplicate or
    // the empty reason behind it — so the message would name the harder problem to fix
    // rather than the one the operator actually made.
    for known in ENTRIES {
        if known.kind != Kind::Build {
            continue;
        }
        let declared = entries.iter().any(|active| active.name == known.name);

        // Named, and this binary does not have it. The deployment has recorded a
        // decision about surface it is not running, and nothing else would ever say
        // so — the entry would simply never fire, which looks exactly like bait
        // nobody took.
        if declared && !known.compiled_in {
            return Err(ConfigError::SurfaceNotBuilt {
                name: known.name.to_owned(),
            });
        }

        // Compiled in, and nothing says since when or why. ADR-20 property 3.
        if known.compiled_in && !declared {
            return Err(ConfigError::SurfaceUndeclared {
                name: known.name.to_owned(),
            });
        }
    }

    Ok(Active { entries })
}

/// Whether a string is a plausible `YYYY-MM-DD`.
///
/// Shape rather than calendar: this project has no date library, and the claim being
/// checked is that the deployment *can say* when it accepted the cost. A 31st of
/// February in that field is a typo somebody will notice; an empty field or a `soon`
/// is the failure this catches. The same ISO form the documents and the audit trail
/// use, so a reader is not asked to hold two formats.
fn is_iso_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let ok = match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        };
        if !ok {
            return false;
        }
    }
    let month: u32 = text[5..7].parse().unwrap_or(0);
    let day: u32 = text[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::{SurfaceConfig, is_iso_date, resolve};
    use crate::error::ConfigError;

    fn stanza(entry: &str, accepted: &str, reason: &str) -> SurfaceConfig {
        SurfaceConfig {
            entry: entry.to_owned(),
            accepted: accepted.to_owned(),
            reason: reason.to_owned(),
        }
    }

    /// The default build has no build entry compiled in, so an empty list is the
    /// configuration that matches it.
    #[cfg(not(feature = "honeypot_alert"))]
    #[test]
    fn the_default_build_wants_an_empty_surface() {
        let active = resolve(&[]).expect("an empty surface");
        assert!(active.entries().is_empty());
        assert_eq!(active.summary(), "none");
    }

    /// The case that matters most, and the one a `[features]` boolean could not
    /// express: the deployment has written down a decision about code it does not have.
    #[cfg(not(feature = "honeypot_alert"))]
    #[test]
    fn naming_an_entry_this_build_lacks_is_refused() {
        let error = resolve(&[stanza(
            "honeypot_alert",
            "2026-08-21",
            "bait under an unfetched prefix",
        )])
        .expect_err("a build without the feature cannot honour this");
        assert!(matches!(error, ConfigError::SurfaceNotBuilt { .. }));
    }

    /// The other direction: the feature is in the binary and nothing says why.
    #[cfg(feature = "honeypot_alert")]
    #[test]
    fn a_compiled_in_entry_must_be_declared() {
        let error = resolve(&[]).expect_err("on, and cannot say since when or why");
        assert!(matches!(error, ConfigError::SurfaceUndeclared { .. }));
    }

    #[cfg(feature = "honeypot_alert")]
    #[test]
    fn a_declared_and_compiled_entry_is_active() {
        let active = resolve(&[stanza(
            "honeypot_alert",
            "2026-08-21",
            "bait under infra/_runner, which nothing fetches",
        )])
        .expect("declared and built");
        assert_eq!(active.names(), vec!["honeypot_alert"]);
        assert_eq!(active.summary(), "honeypot_alert");
        assert_eq!(active.entries()[0].kind, super::Kind::Build);
    }

    #[test]
    fn an_unknown_entry_names_what_is_known() {
        let error = resolve(&[stanza("honeypot_freeze", "2026-08-21", "why not")])
            .expect_err("not an entry");
        match error {
            ConfigError::SurfaceUnknown { known, .. } => assert!(known.contains("honeypot_alert")),
            other => panic!("wrong variant: {other}"),
        }
    }

    #[test]
    fn a_date_that_is_not_a_date_is_refused() {
        for written in [
            "",
            "soon",
            "2026-8-1",
            "21-08-2026",
            "2026-13-01",
            "2026-01-32",
        ] {
            assert!(!is_iso_date(written), "{written} should not pass");
        }
        assert!(is_iso_date("2026-08-21"));
    }

    /// A reason of spaces is the same failure as no reason, and is what somebody
    /// writes to get past a required field.
    #[test]
    fn a_blank_reason_is_refused() {
        let error =
            resolve(&[stanza("honeypot_alert", "2026-08-21", "   ")]).expect_err("no reason");
        assert!(matches!(error, ConfigError::SurfaceReason { .. }));
    }

    #[test]
    fn the_same_entry_twice_is_refused() {
        let error = resolve(&[
            stanza("honeypot_alert", "2026-08-21", "first"),
            stanza("honeypot_alert", "2026-08-22", "second"),
        ])
        .expect_err("two records for one entry");
        assert!(matches!(error, ConfigError::SurfaceDuplicate { .. }));
    }
}
