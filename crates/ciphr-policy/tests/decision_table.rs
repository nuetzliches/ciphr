//! The decision table.
//!
//! One policy set, and every case that matters written out as a row. The plan asks
//! for this explicitly, and the reason is that a table is the artifact a reviewer
//! can actually check: the semantics of the evaluator are four sentences, and this
//! is what those four sentences do to concrete inputs.
//!
//! **Extend this table whenever the evaluator changes.** A change in behaviour that
//! does not move a row here is a change nobody can see.

use ciphr_core::{Capability, SecretPath};
use ciphr_policy::{DenyReason, Effect, PolicySet};

/// Covers, between them: a broad grant, a narrow denial inside it, a
/// single-segment wildcard, an exact rule, an administrative path, an identity
/// with two policies that agree, and an identity with none.
const POLICIES: &str = r#"
[[identity]]
name     = "deploy"
kind     = "machine"
policies = ["infra", "ci-tokens"]

[[identity]]
name     = "auditor"
kind     = "human"
policies = ["audit"]

[[identity]]
name     = "idle"
kind     = "machine"
policies = []

[[policy]]
name = "infra"

  # Broad read across the estate.
  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list"]

  # ciphr's own secrets are off limits, including to the runner that deploys it.
  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []

  # One service the runner may also write to.
  [[policy.rule]]
  path         = "infra/service-a/CACHE_KEY"
  capabilities = ["read", "write"]

[[policy]]
name = "ci-tokens"

  # Exactly one segment: a repository, not a subtree.
  [[policy.rule]]
  path         = "ci/*"
  capabilities = ["read"]

[[policy]]
name = "audit"

  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["read"]
"#;

struct Row {
    identity: &'static str,
    path: &'static str,
    capability: Capability,
    expect: Expect,
    why: &'static str,
}

enum Expect {
    Allow {
        rule: &'static str,
    },
    Deny {
        reason: DenyReason,
        rule: Option<&'static str>,
    },
}

#[allow(clippy::too_many_lines)]
fn table() -> Vec<Row> {
    use Capability::{Delete, List, Read, Undelete, Write};
    vec![
        // --- the broad grant ------------------------------------------------
        Row {
            identity: "deploy",
            path: "infra/service-b/DB_PASSWORD",
            capability: Read,
            expect: Expect::Allow { rule: "infra/**" },
            why: "the broad rule grants read across the subtree",
        },
        Row {
            identity: "deploy",
            path: "infra/service-b/DB_PASSWORD",
            capability: List,
            expect: Expect::Allow { rule: "infra/**" },
            why: "and list",
        },
        Row {
            identity: "deploy",
            path: "infra/service-b/DB_PASSWORD",
            capability: Write,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/**"),
            },
            why: "but not write; the rule that refused is named",
        },
        Row {
            identity: "deploy",
            path: "infra/a/b/c/d/e",
            capability: Read,
            expect: Expect::Allow { rule: "infra/**" },
            why: "** covers any depth below the prefix",
        },
        Row {
            identity: "deploy",
            path: "infra",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "** covers one or more segments, so the parent itself is not inside it",
        },
        // --- the narrow denial ----------------------------------------------
        Row {
            identity: "deploy",
            path: "infra/ciphr/MASTER_KEY_BACKUP",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/ciphr/**"),
            },
            why: "two literal segments beat one: the denial wins",
        },
        Row {
            identity: "deploy",
            path: "infra/ciphr/deep/er/still",
            capability: List,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/ciphr/**"),
            },
            why: "the denial covers the whole subtree, at any depth",
        },
        Row {
            identity: "deploy",
            path: "infra/ciphrx/VALUE",
            capability: Read,
            expect: Expect::Allow { rule: "infra/**" },
            why: "segment-aware: ciphrx is not ciphr, so the denial does not apply",
        },
        // --- the exact rule -------------------------------------------------
        Row {
            identity: "deploy",
            path: "infra/service-a/CACHE_KEY",
            capability: Write,
            expect: Expect::Allow {
                rule: "infra/service-a/CACHE_KEY",
            },
            why: "three literal segments beat one, so the narrower grant applies",
        },
        Row {
            identity: "deploy",
            path: "infra/service-a/CACHE_KEY",
            capability: List,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/service-a/CACHE_KEY"),
            },
            why: "the most specific rule wins entirely; it does not inherit list from the broad one",
        },
        Row {
            identity: "deploy",
            path: "infra/service-a/OTHER",
            capability: Write,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/**"),
            },
            why: "the exact rule applies to one path only",
        },
        // --- the single-segment wildcard ------------------------------------
        Row {
            identity: "deploy",
            path: "ci/widget",
            capability: Read,
            expect: Expect::Allow { rule: "ci/*" },
            why: "* covers exactly one segment",
        },
        Row {
            identity: "deploy",
            path: "ci/widget/TOKEN",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "* is exactly one segment, so it does not reach into a subtree",
        },
        Row {
            identity: "deploy",
            path: "ci",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "* requires a segment to be there",
        },
        // --- deny by default ------------------------------------------------
        Row {
            identity: "deploy",
            path: "other/thing",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "nothing matches, so nothing is granted",
        },
        Row {
            identity: "idle",
            path: "infra/service-b/DB_PASSWORD",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "an identity with no policies can do nothing",
        },
        Row {
            identity: "ghost",
            path: "infra/service-b/DB_PASSWORD",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::UnknownIdentity,
                rule: None,
            },
            why: "an unknown identity is refused before any rule is consulted",
        },
        // --- administrative paths are ordinary paths ------------------------
        Row {
            identity: "auditor",
            path: "sys/audit",
            capability: Read,
            expect: Expect::Allow { rule: "sys/audit" },
            why: "the audit endpoint is authorized as a path, not by a special case",
        },
        Row {
            identity: "auditor",
            path: "sys/policies",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "reading the audit trail grants nothing else under sys/",
        },
        Row {
            identity: "deploy",
            path: "sys/audit",
            capability: Read,
            expect: Expect::Deny {
                reason: DenyReason::NoMatchingRule,
                rule: None,
            },
            why: "the deploy runner has no administrative access",
        },
        // --- capabilities nobody granted ------------------------------------
        Row {
            identity: "deploy",
            path: "infra/service-b/DB_PASSWORD",
            capability: Delete,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/**"),
            },
            why: "delete is granted nowhere in this policy set",
        },
        Row {
            identity: "deploy",
            path: "infra/service-b/DB_PASSWORD",
            capability: Undelete,
            expect: Expect::Deny {
                reason: DenyReason::NotGranted,
                rule: Some("infra/**"),
            },
            why: "and neither is undelete",
        },
    ]
}

#[test]
fn every_row_decides_as_documented() {
    let policies = PolicySet::from_toml(POLICIES).expect("the table's policy set must load");

    for row in table() {
        let path = SecretPath::parse(row.path).expect("table paths are valid");
        let decision = policies.evaluate(row.identity, &path, row.capability);
        let context = format!(
            "{} / {} / {} — {}",
            row.identity, row.path, row.capability, row.why
        );

        match row.expect {
            Expect::Allow { rule } => {
                assert_eq!(decision.effect, Effect::Allow, "{context}");
                assert_eq!(
                    decision
                        .rule
                        .as_ref()
                        .map(|matched| matched.pattern.as_str()),
                    Some(rule),
                    "{context}"
                );
            }
            Expect::Deny { reason, rule } => {
                assert_eq!(decision.effect, Effect::Deny, "{context}");
                assert_eq!(decision.reason, Some(reason), "{context}");
                assert_eq!(
                    decision
                        .rule
                        .as_ref()
                        .map(|matched| matched.pattern.as_str()),
                    rule,
                    "{context}"
                );
            }
        }
    }
}

#[test]
fn the_table_covers_every_capability_and_every_deny_reason() {
    // A table that has quietly stopped covering something is worse than a smaller
    // table, because its size suggests coverage it no longer has.
    let rows = table();

    for capability in Capability::ALL {
        assert!(
            rows.iter().any(|row| row.capability == capability),
            "no row exercises {capability}"
        );
    }

    for reason in [
        DenyReason::UnknownIdentity,
        DenyReason::NoMatchingRule,
        DenyReason::NotGranted,
    ] {
        assert!(
            rows.iter().any(|row| matches!(
                row.expect,
                Expect::Deny {
                    reason: actual,
                    ..
                } if actual == reason
            )),
            "no row exercises {reason}"
        );
    }

    // `Tie` needs two policies that disagree at equal specificity, which the unit
    // tests cover; it is not in this table because the table's policy set is
    // deliberately consistent.
}

/// The sharp edge documented in `docs/authorization.md`: specificity counts literal
/// segments and nothing else, so a broad subtree grant and a narrow cross-cutting
/// exception can be equally specific and produce a tie rather than the override the
/// author intended.
///
/// Pinned as a test because the worked example in the documentation is only worth
/// having if it stays true.
#[test]
fn a_cross_cutting_exception_ties_until_it_is_made_more_specific() {
    let template = r#"
[[identity]]
name     = "deploy"
kind     = "machine"
policies = ["p"]

[[policy]]
name = "p"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read"]

  [[policy.rule]]
  path         = "PATTERN"
  capabilities = []
"#;
    let target = SecretPath::parse("infra/host-a/service-b/DB_PASSWORD").expect("valid");

    // One literal each: neither wins, so denial does.
    let tied =
        PolicySet::from_toml(&template.replace("PATTERN", "*/*/*/DB_PASSWORD")).expect("policies");
    let decision = tied.evaluate("deploy", &target, Capability::Read);
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.reason, Some(DenyReason::Tie));

    // Two literals: the exception is more specific and decides on its own.
    let ordered = PolicySet::from_toml(&template.replace("PATTERN", "infra/*/*/DB_PASSWORD"))
        .expect("policies");
    let decision = ordered.evaluate("deploy", &target, Capability::Read);
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(
        decision.reason,
        Some(DenyReason::NotGranted),
        "the narrow rule must decide, not a tie"
    );
    assert_eq!(
        decision.rule.expect("a rule").specificity,
        2,
        "the documented specificity of infra/*/*/DB_PASSWORD"
    );
}
