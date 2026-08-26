#![forbid(unsafe_code)]

//! Entry point of the ciphr server.
//!
//! Two arguments and no more: the configuration file, and `--check-config` to validate
//! it without starting. Everything else lives in the configuration file, because a
//! flag that changes behaviour is a difference between what the file says and what the
//! process does.

use std::process::ExitCode;

use ciphr_server::surface::{ActiveEntry, ENTRIES, Entry};
use ciphr_server::{ActiveSurface, Check, Config, Server, Unreachable};

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
        Ok(Outcome::HostNotReady) => ExitCode::from(HOST_NOT_READY),
        Err(error) => {
            // The one place in the workspace that writes to stderr: a process that
            // cannot start has to say why, and there is no audit trail to say it to.
            eprintln!("ciphr-server: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The exit code for a complete report about a host that is not ready.
///
/// **The same number and the same reasoning as `ciphr state`'s pre-flight code**, which
/// `0.8.0` gave its own status for exactly this shape: a command that answered in full,
/// where the part of the answer that is *no* is about something other than what the
/// caller asked. Here the caller asked whether the files are usable, and the store is a
/// property of the host.
///
/// **The release that made this worth a number is `0.9.0`.** It made a policy edit
/// mandatory (ADR-23) and pointed at review as the place to catch a file that still has
/// the old form — and a review host is precisely the host that deliberately has no
/// store. With both cases on `1`, the pipeline `upgrade.md` recommends could not tell
/// "this policy file is refused" from "this machine has no store", so the check it runs
/// was a check somebody remembers to read
/// (`docs/assurance/field-reports/field-report-2026-08-23-b.md`, finding 1).
///
/// The other codes are what they were, which is what keeps this readable as a contract:
/// `0` the files are usable and this host is ready, `1` the files are not usable, `2` a
/// usage error from [`usage`]. A caller can tell all four apart, and none of them needs
/// the report parsed to be understood.
const HOST_NOT_READY: u8 = 3;

/// Whether the process did what it was asked, when the failure is not an error.
///
/// `--check-config` on a healthy file and an unready store is not a command that failed:
/// it answered, completely, and part of the answer is *no*. It still exits non-zero,
/// because a pipeline branches on that — with [`HOST_NOT_READY`] rather than `1`, so
/// that the branch can be taken on the status alone. The reason belongs in the report,
/// not in a second sentence on stderr.
enum Outcome {
    Fine,
    HostNotReady,
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
            Outcome::HostNotReady
        });
    }

    let server = Server::prepare(config)?;

    // The one state this release describes as needing a human, said where a human is
    // looking. Finding 1 of the field report of 2026-08-25: a device quarantined at
    // startup reached `/v1/health` and nothing else -- not the trail, not either stream
    // -- and the moment it fires most often is the first start after an upgrade, which
    // is exactly when somebody is watching a deploy log and the monitoring rule for a
    // field added in that same release has not been written yet.
    //
    // Here rather than in the library, because a library that prints has no idea what it
    // is printing into; `ci/check-no-print.sh` holds that line and exempts this file.
    // The trail is still the artefact -- `record_quarantined` wrote it before this ran.
    // This only says the state exists.
    //
    // Both names: the label is what `/v1/health` shows, so a reader can match the two,
    // and the device's own name is what identifies the file they have to archive.
    for stopped in server.state().quarantined() {
        let label = server
            .state()
            .label_for(&stopped.device)
            .unwrap_or_else(|| stopped.device.clone());
        eprintln!(
            "{}",
            quarantine_warning(&label, &stopped.device, stopped.missed_from)
        );
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.serve())?;
    Ok(Outcome::Fine)
}

/// The startup line for a quarantined device, built rather than printed, so a test can
/// read it.
///
/// **It is separate from the `eprintln!` for one reason: this line's entire purpose is
/// that a human reads it in a deploy log.** The field report of 2026-08-25 (b) found the
/// first version carrying two runs of fourteen spaces into the output — a continuation
/// literal indented to match the surrounding code — which nothing detected because
/// nothing looked at the string. Everything else in this system is checked by what it
/// does; this line can only be checked by what it says.
fn quarantine_warning(label: &str, device: &str, missed_from: u64) -> String {
    // One fragment per line, each ending in the space that joins it to the next, so the
    // joins are visible -- a literal continued across lines puts the next line's
    // indentation into the string instead, which is the defect this replaces. The names
    // are passed rather than captured because a format string expanded from a macro
    // cannot capture them.
    format!(
        concat!(
            "ciphr-server: audit device {label} ({device}) is quarantined from seq ",
            "{missed_from}: it is missing records the chain has and will not be ",
            "written to again while this process runs. See ",
            "docs/operations/audit-trail.md."
        ),
        label = label,
        device = device,
        missed_from = missed_from
    )
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

    lines.extend(surface_report(&check.surface, &check.unreachable));

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

/// An entry that is on and that nobody in this policy file can call.
///
/// **Part of the file half, and nothing about the exit code.** Both inputs are the two
/// `.toml` files, so this answers in review; and naming an entry before the identity that
/// uses it exists is a legitimate order of work, which is why this is a note rather than a
/// refusal. What it prevents is that order of work being *forgotten*: an entry on with
/// nobody able to reach it is the same class of quiet as a stanza that was never named,
/// which is the mistake the surface report exists to catch
/// (`docs/assurance/field-reports/field-report-2026-08-23-b.md`, finding 3).
///
/// **Under the entry's own line rather than in a block of its own**, where the cost
/// sentences of the inactive entries already sit: a note about `token_revoke` printed
/// after two paragraphs about entries that are off is a note somebody scrolls past.
///
/// It names the grant, because the reader has to write a rule afterwards — *no identity is
/// authorized for `revoke` on `sys/tokens`* names the edit, *nobody can call this* does
/// not. And it names issuing, because that is the part that is not free: the token for
/// such an identity is created on the host, under the store lock, so the half that is
/// still owed is a planned stop rather than an edit.
fn unreachable_lines(unreachable: &Unreachable) -> Vec<String> {
    wrap(
        &format!(
            "note: on, and no identity in this policy file is authorized for \
             '{}' on '{}' -- nobody can call it. Issuing a token for one needs the master \
             key and the store lock, so what is left is a planned stop rather than an edit.",
            unreachable.capability, unreachable.path
        ),
        68,
    )
    .into_iter()
    .map(|line| format!("       {line}"))
    .collect()
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
fn surface_report(active: &ActiveSurface, unreachable: &[Unreachable]) -> Vec<String> {
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
        if let Some(note) = unreachable.iter().find(|note| note.entry == entry.name) {
            lines.extend(unreachable_lines(note));
        }
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
    use super::{check_report, quarantine_warning, surface_report};
    use ciphr_server::{ActiveSurface, Check, StartupError};

    /// The finding of the field report of 2026-08-25 (b), as an assertion rather than a
    /// reading.
    ///
    /// A run of two spaces mid-sentence is what a continuation literal leaves behind when
    /// the following source line is indented to match its surroundings, and it is
    /// invisible in the code — `cargo fmt` had folded the offending literal onto one long
    /// line, where the fourteen spaces read as one. So this asserts the property the line
    /// exists for: it is one line, and it reads as a sentence.
    #[test]
    fn the_startup_warning_reads_as_a_sentence() {
        let warning = quarantine_warning("file-1", "file:/var/log/ciphr/audit.jsonl", 382);

        assert!(
            !warning.contains("  "),
            "the line a human reads has a run of spaces in it: {warning:?}"
        );
        assert_eq!(warning.lines().count(), 1, "one line: {warning:?}");

        // Both identifiers and the sequence, which is what makes it actionable: the label
        // matches `/v1/health`, the device name finds the file to archive.
        assert!(warning.contains("file-1"));
        assert!(warning.contains("file:/var/log/ciphr/audit.jsonl"));
        assert!(warning.contains("seq 382"));
        assert!(warning.contains("docs/operations/audit-trail.md"));
    }

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
                unreachable: Vec::new(),
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
                unreachable: Vec::new(),
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
        let report = surface_report(&ActiveSurface::default(), &[]).join("\n");

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
        let report = surface_report(&active, &[]).join("\n");

        assert!(report.contains("  on   viewer_api"), "{report}");
        assert!(report.contains("  off  bulk_export"), "{report}");
        assert!(
            report.contains("One request per path instead of one for all of them"),
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
        let report = surface_report(&ActiveSurface::default(), &[]).join("\n");

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
