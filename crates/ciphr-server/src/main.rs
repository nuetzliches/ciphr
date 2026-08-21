#![forbid(unsafe_code)]

//! Entry point of the ciphr server.
//!
//! Two arguments and no more: the configuration file, and `--check-config` to validate
//! it without starting. Everything else lives in the configuration file, because a
//! flag that changes behaviour is a difference between what the file says and what the
//! process does.

use std::process::ExitCode;

use ciphr_server::surface::{ActiveEntry, ENTRIES, Entry};
use ciphr_server::{ActiveSurface, Config, Server};

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
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The one place in the workspace that writes to stderr: a process that
            // cannot start has to say why, and there is no audit trail to say it to.
            eprintln!("ciphr-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &str, check_only: bool) -> Result<(), Box<dyn core::error::Error>> {
    let config = Config::load(config_path)?;

    if check_only {
        // Prepared but not served: this checks the policy file, the store, the master
        // key, and every audit device, which is most of what can be wrong.
        let server = Server::prepare(config)?;
        println!("configuration and policies are usable");
        for line in surface_report(server.state().surface()) {
            println!("{line}");
        }
        return Ok(());
    }

    let server = Server::prepare(config)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.serve())?;
    Ok(())
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
    let mut lines = vec![
        String::new(),
        format!(
            "surface: {} of {} entries on (ADR-20)",
            active.entries().len(),
            ENTRIES.len()
        ),
    ];

    // The record each entry was named with, and not its cost: the cost is the input to a
    // decision this deployment has already made.
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
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
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
    use super::surface_report;
    use ciphr_server::ActiveSurface;

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
