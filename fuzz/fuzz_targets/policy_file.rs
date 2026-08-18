//! Fuzz policy file loading and evaluation.
//!
//! A policy file is configuration, not attacker-controlled input, so this target is
//! not about untrusted data. It is about the loader's promise: a file either loads
//! completely or not at all, and anything that loads produces an evaluator that
//! answers deny-by-default. A malformed file that half-loads would be a set of
//! permissions nobody wrote.
//!
//! The check that matters is the last one: for a random path, an allow is only ever
//! returned together with the rule that granted it. An allow with no rule attached
//! would mean the audit trail cannot say why an access was permitted.

#![no_main]

use ciphr_core::{Capability, SecretPath};
use ciphr_policy::{Effect, PolicySet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    let Ok(policies) = PolicySet::from_toml(input) else {
        return;
    };

    // Loading again must produce the same thing: the loader has no state and no
    // ordering dependence.
    let reloaded = PolicySet::from_toml(input).expect("a file that loaded must load again");
    assert!(
        policies == reloaded,
        "loading the same file twice produced different policy sets"
    );

    // Every identity's policy references resolve — the loader refuses dangling ones,
    // so an unresolvable reference here would mean validation was skipped.
    for identity in policies.identities() {
        for name in identity.policies() {
            assert!(
                policies.policy(name).is_some(),
                "identity {} refers to missing policy {name}",
                identity.name()
            );
        }
    }

    // A handful of paths, including ones unlikely to appear in the file.
    let paths = [
        "a",
        "infra/service-a/DB_PASSWORD",
        "infra/ciphr/MASTER",
        "sys/audit",
        "ci/widget/TOKEN",
    ];

    for text in paths {
        let path = SecretPath::parse(text).expect("these are valid paths");

        for capability in Capability::ALL {
            let decision = policies.evaluate("does-not-exist", &path, capability);
            assert_eq!(
                decision.effect,
                Effect::Deny,
                "an unknown identity was allowed {capability} on {text}"
            );
            assert!(
                decision.rule.is_none(),
                "a denial for an unknown identity named a rule"
            );
        }

        for identity in policies.identities() {
            for capability in Capability::ALL {
                let decision = policies.evaluate(identity.name(), &path, capability);

                if decision.effect == Effect::Allow {
                    // An allow must always be attributable: the audit trail records
                    // which rule permitted the access.
                    let rule = decision
                        .rule
                        .as_ref()
                        .expect("an allow must name the rule that granted it");
                    assert!(
                        policies.policy(&rule.policy).is_some(),
                        "an allow named a policy that does not exist"
                    );
                    assert!(decision.reason.is_none(), "an allow carried a deny reason");
                } else {
                    assert!(
                        decision.reason.is_some(),
                        "a denial carried no reason for {} on {text}",
                        identity.name()
                    );
                }
            }

            // The convenience view must agree with the decisions it summarizes.
            let effective = policies.effective_capabilities(identity.name(), &path);
            for capability in Capability::ALL {
                assert_eq!(
                    effective.contains(&capability),
                    policies
                        .evaluate(identity.name(), &path, capability)
                        .is_allowed(),
                    "effective_capabilities disagrees with evaluate for {capability} on {text}"
                );
            }
        }
    }
});
