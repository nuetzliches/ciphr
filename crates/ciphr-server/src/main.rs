#![forbid(unsafe_code)]

//! Entry point of the ciphr server.
//!
//! Two arguments and no more: the configuration file, and `--check-config` to validate
//! it without starting. Everything else lives in the configuration file, because a
//! flag that changes behaviour is a difference between what the file says and what the
//! process does.

use std::process::ExitCode;

use ciphr_server::surface::{ActiveEntry, ENTRIES, Entry};
use ciphr_server::{ActiveSurface, Check, Config, Server};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next();

    let (config_path, check_only) = match first.as_deref() {
        Some("--check-config") => (arguments.next(), true),
        Some("--help" | "-h") | None => {
            usage();
            return ExitCode::from(2);
        }
        Some(path) => (Some(path.to_owned()), false),
    };

    let Some(config_path) = config_path else {
        usage();
        return ExitCode::from(2);
    };

    match run(&config_path, check_only) {
        Ok(Outcome::Fine) => ExitCode::SUCCESS,
        // The report has already said what is not ready, in its own labelled section
        // and on stdout. Printing the reason a second time here would put the same
        // sentence twice in one run.
        Ok(Outcome::NotReady) => ExitCode::FAILURE,
        Err(error) => {
            // The one place in the workspace that writes to stderr: a process that
            // cannot start has to say why, and there is no audit trail to say it to.
            eprintln!("ciphr-server: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Whether the process did what it was asked, when the failure is not an error.
///
/// `--check-config` on a healthy file and an unready store is not a command that failed:
/// it answered, completely, and part of the answer is *no*. It still exits non-zero,
/// because a pipeline branches on that — but the reason belongs in the report, not in a
/// second sentence on stderr.
enum Outcome {
    Fine,
    NotReady,
}

fn run(config_path: &str, check_only: bool) -> Result<Outcome, Box<dyn core::error::Error>> {
    let config = Config::load(config_path)?;

    if check_only {
        let check = Server::check(&config)?;
        let ready = check.store.is_ok();
        for line in check_report(config_path, &check) {
            println!("{line}");
        }
        return Ok(if ready {
            Outcome::Fine
        } else {
            Outcome::NotReady
        });
    }

    let server = Server::prepare(config)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.serve())?;
    Ok(Outcome::Fine)
}

/// The whole `--check-config` report: the half that travels with the files, then the
/// half that describes this host.
///
/// **The order is the finding.** `configuration and policies are usable` still leads,
/// byte for byte, because that sentence is what runbooks and the `0.5.0` upgrade note
/// quote — but everything down to and including the surface report is now printed
/// *before* the store is looked at, so a reviewer with the two files and no host gets
/// the one report that catches a forgotten stanza. What needs this host is the last
/// section and says which it is.
fn check_report(config_path: &str, check: &Check) -> Vec<String> {
    let mut lines = vec![
        "configuration and policies are usable".to_owned(),
        format!("  file      {config_path}"),
        format!(
            "  policies  {}, {}",
            counted(check.identities, "identity", "identities"),
            counted(check.rules, "rule", "rules")
        ),
    ];

    lines.extend(surface_report(&check.surface));

    // Its own labelled section, because it answers a different question from everything
    // above it: not *is this the file I meant* but *is this host ready to run it*. A
    // caller that only has the file reads the sections above and stops here.
    lines.push(String::new());
    match &check.store {
        Ok(store) => {
            lines.push(format!(
                "store: ready (schema {}, seal {}, key from {})",
                store.schema_version, store.seal_id, store.key_source
            ));
            lines.push(format!("  audit  {}", store.devices.join(", ")));
        }
        // The error's own text, unchanged: `store: the store is not initialized` is what
        // the previous version printed for this case, and it is still exactly right.
        Err(error) => {
            lines.push(format!("{error}"));
            lines.push(
                "  the sections above are about the file and hold without this host".to_owned(),
            );
        }
    }
    lines
}

/// A count with the right noun beside it.
///
/// `1 identities` reads as a bug in the thing printing it, which is a bad first impression
/// for a report whose whole job is to be trusted. `(s)` is the same problem written down.
fn counted(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

/// What this configuration turned on, and what it left off, as lines to print.
///
/// **The second half is the reason this exists.** An entry that is off is absent from the
/// router, so it is byte-identical on the wire to a path that never existed -- which is
/// what ADR-20 wants there. Nothing else then answers the question an operator has after
/// a `404`: *is this route missing because the build never had it, or because this file
/// did not name it?* `upgrade.md` recommends this command for the `0.5.0` upgrade
/// precisely because that release made four routes conditional -- and a *missing* stanza
/// is legal, so before this the command accepted the previous version's file without a
/// word about surface at all.
///
/// [`ENTRIES`] is the closed list that exists so "what can a deployment turn on" has an
/// answer rather than needing a search, and this is the interface that prints it.
///
/// Lines rather than direct printing, so the shape is testable without capturing stdout.
fn surface_report(active: &ActiveSurface) -> Vec<String> {
    // **The headline says how many of the total this binary could offer at all**, because
    // the bare count cannot. "2 of 3 entries on" reads as though a third were available to
    // switch on, and for a build entry this binary lacks it is not -- that needs a
    // different artefact. The off lines two rows down say so, but this is the line people
    // quote.
    let absent = ENTRIES.iter().filter(|entry| !entry.compiled_in).count();
    let headline = match absent {
        0 => format!(
            "surface: {} of {} entries on (ADR-20)",
            active.entries().len(),
            ENTRIES.len()
        ),
        absent => format!(
            "surface: {} of {} entries on, {absent} not in this binary (ADR-20)",
            active.entries().len(),
            ENTRIES.len()
        ),
    };
    let mut lines = vec![String::new(), headline];

    // The name, the kind and the date each entry was accepted -- not the reason, which the
    // operator has in the file open in front of them, and not the cost, which is the input
    // to a decision this deployment has already made.
    for entry in active.entries() {
        lines.push(active_line(entry));
    }

    for known in ENTRIES {
        if !active.has(known.name) {
            lines.extend(inactive_lines(known));
        }
    }
    lines
}

/// One entry this configuration named.
fn active_line(entry: &ActiveEntry) -> String {
    format!(
        "  on   {:<15} {:<8} accepted {}",
        entry.name,
        entry.kind.as_str(),
        entry.accepted
    )
}

/// One entry this configuration did not name, with what its absence costs.
///
/// The cost sentence belongs here rather than beside the active entries. It is what an
/// operator deciding *about* an entry wants to read, and before this it was only ever
/// printed for entries already decided in favour of.
///
/// A build entry that is off is also not in this binary, and says so: `resolve` refuses
/// to start a service whose binary has the feature and whose configuration does not
/// declare it, so by the time this runs the two cannot disagree.
fn inactive_lines(known: &Entry) -> Vec<String> {
    let state = if known.compiled_in {
        "not named by this configuration"
    } else {
        "not named by this configuration, and not in this binary"
    };
    let mut lines = vec![format!(
        "  off  {:<15} {:<8} {state}",
        known.name,
        known.kind.as_str()
    )];
    lines.extend(
        wrap(known.cost, 68)
            .into_iter()
            .map(|line| format!("       {line}")),
    );
    lines
}

/// Break a cost sentence into lines that fit a terminal.
///
/// Measured in characters rather than bytes. These sentences are prose, and prose acquires
/// an em dash eventually -- `len()` would then wrap early for a reason nobody reading the
/// output could see.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let width_of = |text: &str| text.chars().count();
    for word in text.split_whitespace() {
        if !line.is_empty() && width_of(&line) + 1 + width_of(word) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn usage() {
    println!("usage: ciphr-server <config.toml>");
    println!("       ciphr-server --check-config <config.toml>");
}

#[cfg(test)]
mod tests {
    use super::{check_report, surface_report};
    use ciphr_server::{ActiveSurface, Check, StartupError};

    /// The order the finding is about: everything that is a function of the file comes
    /// before the section that describes this host.
    ///
    /// A reviewer with the two files and no store reads down to the store line and stops
    /// — and by then the surface report has already told them whether a stanza was
    /// forgotten, which is the one thing a legal file can be wrong about.
    #[test]
    fn the_file_half_is_printed_before_the_host_half() {
        let report = check_report(
            "/etc/ciphr/ciphr.toml",
            &Check {
                identities: 4,
                rules: 7,
                surface: ActiveSurface::default(),
                store: Err(StartupError::Store(ciphr_store::StoreError::NotInitialized)),
            },
        );

        // The first line, byte for byte: runbooks and the `0.5.0` upgrade note quote it.
        assert_eq!(report[0], "configuration and policies are usable");

        let joined = report.join("\n");
        let surface = joined.find("surface:").expect("the surface report");
        let store = joined
            .find("the store is not initialized")
            .expect("the host half says why");
        assert!(
            surface < store,
            "the store gate must not come first: {joined}"
        );
        assert!(
            joined.contains("4 identities, 7 rules"),
            "the policy file is counted: {joined}"
        );
    }

    /// A ready store is reported as what it is, and never as a key.
    #[test]
    fn a_ready_store_names_the_key_source_and_not_the_key() {
        let report = check_report(
            "/etc/ciphr/ciphr.toml",
            &Check {
                identities: 1,
                rules: 1,
                surface: ActiveSurface::default(),
                store: Ok(ciphr_server::StoreReady {
                    schema_version: 6,
                    seal_id: "static".to_owned(),
                    key_source: "environment".to_owned(),
                    devices: vec!["sqlite:/var/lib/ciphr/store.db".to_owned()],
                }),
            },
        )
        .join("\n");

        assert!(report.contains("store: ready (schema 6"), "{report}");
        assert!(report.contains("environment"), "{report}");
        assert!(
            report.contains("sqlite:/var/lib/ciphr/store.db"),
            "the devices that opened: {report}"
        );
    }

    /// The finding this output exists for: an empty surface is the ordinary
    /// configuration, and it has to say what "nothing" was chosen from. Before this,
    /// `--check-config` accepted a file naming no entry without mentioning surface at
    /// all -- the exact case the `0.5.0` upgrade note recommends the command for.
    #[test]
    fn a_configuration_that_names_nothing_still_names_every_entry() {
        let report = surface_report(&ActiveSurface::default()).join("\n");

        for entry in ciphr_server::SURFACE_ENTRIES {
            assert!(
                report.contains(entry.name),
                "{} is missing from the report",
                entry.name
            );
        }
        let total = ciphr_server::SURFACE_ENTRIES.len();
        assert!(
            report.contains(&format!("0 of {total} entries on")),
            "{report}"
        );
        assert!(!report.contains("  on   "), "nothing is on: {report}");
    }

    /// An entry that is off carries the sentence an operator deciding about it wants,
    /// and one that is on carries the record instead.
    #[test]
    fn off_carries_the_cost_and_on_carries_the_record() {
        let active = ciphr_server::surface::only(&["viewer_api"]).expect("a known entry");
        let report = surface_report(&active).join("\n");

        assert!(report.contains("  on   viewer_api"), "{report}");
        assert!(report.contains("  off  bulk_export"), "{report}");
        assert!(
            report.contains("`ciphr-run` cannot fetch at all"),
            "the cost of the off entry: {report}"
        );
        assert!(
            !report.contains("The viewer stops working"),
            "the cost of a decided entry is not the operator's question: {report}"
        );
    }

    /// A build entry that is off is off in two ways, and the report separates them: a
    /// runtime entry could be turned on by editing the file, and this one could not.
    #[cfg(not(feature = "honeypot_alert"))]
    #[test]
    fn a_build_entry_that_is_absent_says_the_binary_lacks_it() {
        let report = surface_report(&ActiveSurface::default()).join("\n");

        assert!(
            report.contains(
                "honeypot_alert  build    not named by this configuration, and not in this binary"
            ),
            "{report}"
        );
        assert!(
            report.contains("bulk_export     runtime  not named by this configuration\n"),
            "a runtime entry says nothing about the binary: {report}"
        );
    }
}
