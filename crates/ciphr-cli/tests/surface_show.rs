//! What `ciphr surface show` says about a server configuration, through the binary.
//!
//! The property worth an integration test is the *negative* one, and it is the finding
//! this test was written for: a configuration that names an entry, and a configuration
//! that names none, both have to say which entries exist and were left off. An operator
//! looking at a `404` from a route that is off sees exactly what a typo'd path returns,
//! by design (ADR-20) -- so the list of names has to be readable on this side, or the
//! question "was this route never built, or merely never named?" has no answer anywhere.
//!
//! No store and no master key: this command reads a file.

use std::path::Path;
use std::process::{Command, Output};

fn ciphr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ciphr"))
        .args(args)
        .output()
        .expect("run ciphr")
}

fn show(config: &Path) -> (String, String) {
    let output = ciphr(&["surface", "show", &config.display().to_string()]);
    assert!(output.status.success(), "surface show exits zero");
    (
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
    )
}

/// The configuration that started the previous version: no `[[surface]]` stanza at all,
/// which is legal and is what a forgotten upgrade step looks like.
const NAMES_NOTHING: &str = r#"
policies = "/etc/ciphr/policies.toml"

[server]
listen = "0.0.0.0:4400"

[storage]
backend = "sqlite"
path    = "/var/lib/ciphr/store.db"

[seal]
type = "static_env"
env  = "CIPHR_MASTER_KEY"

[[audit]]
type = "sqlite"
"#;

#[test]
fn a_file_that_names_nothing_still_names_every_entry_it_left_off() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("ciphr.toml");
    std::fs::write(&config, NAMES_NOTHING).expect("write config");

    let (stdout, stderr) = show(&config);

    // The sentence that was already right, and is still the first thing said.
    assert!(
        stderr.contains("turns nothing on. That is the ordinary configuration."),
        "{stderr}"
    );

    // And the half that was missing: what "nothing" was chosen from.
    for name in ["viewer_api", "bulk_export", "honeypot_alert"] {
        assert!(
            stdout.contains(&format!("off  {name}")),
            "{name} is missing from the off list:\n{stdout}"
        );
    }
    assert!(!stdout.contains("on   "), "nothing is on:\n{stdout}");

    // The cost sentence is what an operator deciding about an entry reads, and an entry
    // that is off is the only one still being decided about.
    assert!(stdout.contains("The viewer stops working"), "{stdout}");
}

#[test]
fn an_entry_that_is_named_is_reported_apart_from_the_ones_that_are_not() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("ciphr.toml");
    std::fs::write(
        &config,
        format!(
            "{NAMES_NOTHING}\n[[surface]]\nentry    = \"viewer_api\"\n\
             accepted = \"2026-08-21\"\nreason   = \"the audit viewer runs beside the service\"\n"
        ),
    )
    .expect("write config");

    let (stdout, _) = show(&config);

    assert!(stdout.contains("on   viewer_api"), "{stdout}");
    assert!(stdout.contains("accepted  2026-08-21"), "{stdout}");
    assert!(stdout.contains("off  bulk_export"), "{stdout}");
    assert!(stdout.contains("off  honeypot_alert"), "{stdout}");
    assert!(
        !stdout.contains("off  viewer_api"),
        "an entry is on or off, never both:\n{stdout}"
    );
}

/// The claim this deployment cannot correct locally, so it is worth pinning here: the
/// cost of `bulk_export` describes what the route does and does not claim that turning
/// it off removes fetched prefixes. `POST /v1/export` reads the paths a caller names, so
/// whether a prefix is covered is a property of the fetching code -- `GET /v1/list` is
/// not an entry and a caller can still list, then read each path.
#[test]
fn the_bulk_export_cost_does_not_claim_to_remove_fetched_prefixes() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("ciphr.toml");
    std::fs::write(&config, NAMES_NOTHING).expect("write config");

    let (stdout, _) = show(&config);
    let flattened = stdout.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        flattened.contains("It does not decide whether this deployment has fetched prefixes"),
        "{flattened}"
    );
    assert!(
        !flattened.contains("has no fetched prefixes for bait to stay out of"),
        "the claim the code does not support is back:\n{flattened}"
    );
}
