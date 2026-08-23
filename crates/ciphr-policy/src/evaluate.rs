//! The authorization decision.
//!
//! One function decides every access in the system. The rules it follows are
//! binding, because ambiguity here is not a documentation problem but an
//! authorization bug:
//!
//! 1. **Deny by default.** No matching rule means denial. An unknown identity
//!    means denial.
//! 2. **Most specific match wins.** Specificity is the number of literal segments
//!    in the pattern, so `infra/ciphr/**` beats `infra/**`.
//! 3. **On a tie, denial wins.** If two equally specific rules disagree about the
//!    requested capability, the answer is no.
//! 4. **An empty capability set is an explicit denial**, not the absence of a
//!    rule, and it beats any less specific permission.
//!
//! Rules 2 to 4 exist so that "everything under `infra`, except our own secrets"
//! is expressible as two rules rather than as an enumeration of everything that is
//! not excluded. Rule 3 exists because the alternative — picking one of two
//! conflicting rules by file order — would make the meaning of a policy depend on
//! where someone happened to paste it.
//!
//! Every decision carries the rule that produced it, because the audit trail
//! records *why* an access was allowed or refused. A log line saying "denied" and
//! nothing else cannot be acted on.

use std::collections::BTreeSet;

use ciphr_core::{Capability, SecretPath};

use crate::model::PolicySet;

/// Whether an access is permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The access is permitted.
    Allow,
    /// The access is refused.
    Deny,
}

/// Why an access was refused.
///
/// Recorded in the audit trail. "No rule matched" and "a rule explicitly denied
/// this" look identical to the caller and mean very different things to whoever
/// has to fix a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The identity is not in the policy set.
    UnknownIdentity,
    /// No rule of any attached policy matches this path.
    NoMatchingRule,
    /// The most specific matching rule does not grant this capability.
    NotGranted,
    /// Equally specific rules disagreed, so denial won.
    Tie,
}

impl DenyReason {
    /// A short, stable label for the audit trail.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownIdentity => "unknown-identity",
            Self::NoMatchingRule => "no-matching-rule",
            Self::NotGranted => "not-granted",
            Self::Tie => "tie",
        }
    }
}

impl core::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The rule that decided an access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    /// The policy the rule belongs to.
    pub policy: String,
    /// The pattern, as normalized.
    pub pattern: String,
    /// How many literal segments the pattern has.
    pub specificity: usize,
}

/// The outcome of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Allowed or refused.
    pub effect: Effect,
    /// Why, when refused.
    pub reason: Option<DenyReason>,
    /// The rule that decided it, if a rule was involved.
    ///
    /// `None` for an unknown identity or when nothing matched — there is no rule
    /// to name, and inventing one would put a fiction in the audit trail.
    pub rule: Option<MatchedRule>,
}

impl Decision {
    /// Whether the access is permitted.
    pub fn is_allowed(&self) -> bool {
        matches!(self.effect, Effect::Allow)
    }

    fn allow(rule: MatchedRule) -> Self {
        Self {
            effect: Effect::Allow,
            reason: None,
            rule: Some(rule),
        }
    }

    fn deny(reason: DenyReason, rule: Option<MatchedRule>) -> Self {
        Self {
            effect: Effect::Deny,
            reason: Some(reason),
            rule,
        }
    }
}

impl PolicySet {
    /// Decide whether `identity` may perform `capability` on `path`.
    ///
    /// The only authorization entry point. There is no second one for
    /// administrative paths: `sys/audit`, `sys/identities` and `sys/policies` are
    /// ordinary paths evaluated here, which is why no `admin` capability exists to
    /// be obtained by trickery (ADR-3).
    pub fn evaluate(&self, identity: &str, path: &SecretPath, capability: Capability) -> Decision {
        let Some(identity) = self.identity(identity) else {
            return Decision::deny(DenyReason::UnknownIdentity, None);
        };

        // Every matching rule from every attached policy. Collected rather than
        // short-circuited: the most specific match has to be found before anything
        // can be decided, and a rule that denies may sit in a later policy.
        let mut matches: Vec<(&crate::model::Rule, &str)> = Vec::new();
        for policy_name in identity.policies() {
            let Some(policy) = self.policy(policy_name) else {
                // Unreachable: loading refuses a dangling reference. Treated as a
                // denial rather than a panic, because an authorization path should
                // fail closed even when its invariants are violated.
                continue;
            };
            for rule in policy.rules() {
                if rule.pattern().matches(path) {
                    matches.push((rule, policy.name()));
                }
            }
        }

        if matches.is_empty() {
            return Decision::deny(DenyReason::NoMatchingRule, None);
        }

        let most_specific = matches
            .iter()
            .map(|(rule, _)| rule.pattern().specificity())
            .max()
            .unwrap_or(0);

        let mut winners: Vec<(&crate::model::Rule, &str)> = matches
            .into_iter()
            .filter(|(rule, _)| rule.pattern().specificity() == most_specific)
            .collect();

        // Deterministic reporting: which of several equivalent rules gets named in
        // the audit trail must not depend on iteration order.
        winners.sort_by(|(left_rule, left_policy), (right_rule, right_policy)| {
            left_policy.cmp(right_policy).then_with(|| {
                left_rule
                    .pattern()
                    .as_str()
                    .cmp(right_rule.pattern().as_str())
            })
        });

        let granting = winners
            .iter()
            .filter(|(rule, _)| rule.capabilities().contains(&capability))
            .count();

        if granting == winners.len() {
            let (rule, policy) = winners[0];
            return Decision::allow(describe(rule, policy));
        }

        // Something at this specificity refuses. Denial wins, and the rule named is
        // the first refusing one, so the audit trail points at what to change.
        let refusing = winners
            .iter()
            .find(|(rule, _)| !rule.capabilities().contains(&capability))
            .map(|(rule, policy)| describe(rule, policy));

        let reason = if granting == 0 {
            DenyReason::NotGranted
        } else {
            DenyReason::Tie
        };
        Decision::deny(reason, refusing)
    }

    /// Everything `identity` may do at `path`.
    ///
    /// Evaluated capability by capability through [`PolicySet::evaluate`], so it
    /// cannot drift from the decision an actual request would get. Intended for
    /// the read-only views that show which rule applies where — not as a shortcut
    /// for authorizing a request, which must always ask about the one capability it
    /// needs.
    pub fn effective_capabilities(
        &self,
        identity: &str,
        path: &SecretPath,
    ) -> BTreeSet<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|capability| self.evaluate(identity, path, *capability).is_allowed())
            .collect()
    }
}

fn describe(rule: &crate::model::Rule, policy: &str) -> MatchedRule {
    MatchedRule {
        policy: policy.to_owned(),
        pattern: rule.pattern().as_str().to_owned(),
        specificity: rule.pattern().specificity(),
    }
}

#[cfg(test)]
mod tests {
    use super::{DenyReason, Effect, PolicySet};
    use ciphr_core::{Capability, SecretPath};

    fn path(text: &str) -> SecretPath {
        SecretPath::parse(text).expect("test paths are valid")
    }

    fn load(input: &str) -> PolicySet {
        PolicySet::from_toml(input).expect("test policies are valid")
    }

    const DEPLOY: &str = r#"
[[identity]]
name     = "deploy-runner"
kind     = "machine"
policies = ["infra-read"]

[[identity]]
name     = "no-policies"
kind     = "machine"
policies = []

[[policy]]
name = "infra-read"

  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "list"]

  [[policy.rule]]
  path         = "infra/ciphr/**"
  capabilities = []
"#;

    #[test]
    fn grants_what_the_rule_grants() {
        let set = load(DEPLOY);
        let decision = set.evaluate("deploy-runner", &path("infra/a/DB"), Capability::Read);

        assert_eq!(decision.effect, Effect::Allow);
        assert!(decision.is_allowed());
        let rule = decision.rule.expect("an allow names its rule");
        assert_eq!(rule.policy, "infra-read");
        assert_eq!(rule.pattern, "infra/**");
    }

    #[test]
    fn refuses_a_capability_the_rule_does_not_grant() {
        let set = load(DEPLOY);
        let decision = set.evaluate("deploy-runner", &path("infra/a/DB"), Capability::Write);

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.reason, Some(DenyReason::NotGranted));
        // The audit trail must be able to say which rule refused.
        assert_eq!(decision.rule.expect("named").pattern, "infra/**");
    }

    #[test]
    fn a_more_specific_denial_beats_a_broader_grant() {
        let set = load(DEPLOY);
        let decision = set.evaluate(
            "deploy-runner",
            &path("infra/ciphr/MASTER"),
            Capability::Read,
        );

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.reason, Some(DenyReason::NotGranted));
        assert_eq!(decision.rule.expect("named").pattern, "infra/ciphr/**");
    }

    #[test]
    fn denies_by_default() {
        let set = load(DEPLOY);

        // Outside every pattern.
        let elsewhere = set.evaluate("deploy-runner", &path("ci/widget/TOKEN"), Capability::Read);
        assert_eq!(elsewhere.reason, Some(DenyReason::NoMatchingRule));
        assert!(elsewhere.rule.is_none());

        // An identity with no policies.
        let nothing = set.evaluate("no-policies", &path("infra/a/DB"), Capability::Read);
        assert_eq!(nothing.reason, Some(DenyReason::NoMatchingRule));

        // An identity that does not exist.
        let unknown = set.evaluate("ghost", &path("infra/a/DB"), Capability::Read);
        assert_eq!(unknown.reason, Some(DenyReason::UnknownIdentity));
        assert!(unknown.rule.is_none());
    }

    #[test]
    fn the_parent_of_a_subtree_is_not_inside_it() {
        // `infra/**` covers one or more segments, so `infra` itself is not covered.
        let set = load(DEPLOY);
        let decision = set.evaluate("deploy-runner", &path("infra"), Capability::Read);
        assert_eq!(decision.reason, Some(DenyReason::NoMatchingRule));
    }

    #[test]
    fn a_tie_is_a_denial() {
        let set = load(
            r#"
[[identity]]
name     = "runner"
kind     = "machine"
policies = ["allows", "denies"]

[[policy]]
name = "allows"
  [[policy.rule]]
  path         = "infra/*"
  capabilities = ["read"]

[[policy]]
name = "denies"
  [[policy.rule]]
  path         = "*/secret"
  capabilities = ["read"]
"#,
        );

        // Both patterns have one literal segment and both match `infra/secret`.
        // They agree here, so the access is allowed.
        let agreed = set.evaluate("runner", &path("infra/secret"), Capability::Read);
        assert_eq!(agreed.effect, Effect::Allow);

        // Now make them disagree at the same specificity.
        let set = load(
            r#"
[[identity]]
name     = "runner"
kind     = "machine"
policies = ["allows", "denies"]

[[policy]]
name = "allows"
  [[policy.rule]]
  path         = "infra/*"
  capabilities = ["read"]

[[policy]]
name = "denies"
  [[policy.rule]]
  path         = "*/secret"
  capabilities = []
"#,
        );

        let decision = set.evaluate("runner", &path("infra/secret"), Capability::Read);
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.reason, Some(DenyReason::Tie));
        // The rule named is the one that refused, not the one that permitted.
        assert_eq!(decision.rule.expect("named").pattern, "*/secret");
    }

    #[test]
    fn capabilities_from_several_policies_apply_at_the_same_specificity() {
        let set = load(
            r#"
[[identity]]
name     = "runner"
kind     = "machine"
policies = ["reader", "writer"]

[[policy]]
name = "reader"
  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read"]

[[policy]]
name = "writer"
  [[policy.rule]]
  path         = "infra/**"
  capabilities = ["read", "write"]
"#,
        );

        // Equal specificity, and they disagree about `write`: denial wins. This is
        // the rule that makes a policy set additive only where it agrees, which is
        // the conservative reading and the one that cannot surprise.
        let write = set.evaluate("runner", &path("infra/a"), Capability::Write);
        assert_eq!(write.reason, Some(DenyReason::Tie));

        // They agree about `read`.
        assert!(
            set.evaluate("runner", &path("infra/a"), Capability::Read)
                .is_allowed()
        );
    }

    #[test]
    fn effective_capabilities_match_what_evaluate_would_answer() {
        let set = load(DEPLOY);

        let granted = set.effective_capabilities("deploy-runner", &path("infra/a/DB"));
        assert_eq!(
            granted.into_iter().collect::<Vec<_>>(),
            [Capability::Read, Capability::List]
        );

        assert!(
            set.effective_capabilities("deploy-runner", &path("infra/ciphr/X"))
                .is_empty()
        );
        assert!(
            set.effective_capabilities("ghost", &path("infra/a"))
                .is_empty()
        );
    }

    #[test]
    fn administrative_paths_go_through_the_same_evaluator() {
        // No second mechanism and no `admin` capability: the audit endpoint is
        // authorized as an ordinary path. Since ADR-23 the *capability* is `inspect`
        // rather than `read` — and this test's value is that nothing else changed:
        // the evaluator does not know that `sys/` is special, and the path axis still
        // keeps one reserved path from granting another.
        let set = load(
            r#"
[[identity]]
name     = "auditor"
kind     = "human"
policies = ["audit-read"]

[[policy]]
name = "audit-read"
  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["inspect"]
"#,
        );

        assert!(
            set.evaluate("auditor", &path("sys/audit"), Capability::Inspect)
                .is_allowed()
        );
        assert!(
            !set.evaluate("auditor", &path("sys/policies"), Capability::Inspect)
                .is_allowed()
        );
        assert!(
            !set.evaluate("auditor", &path("infra/a"), Capability::Inspect)
                .is_allowed()
        );
        // The half ADR-23 exists for: the grant is `inspect`, so it is not a `read` of
        // anything — and a `read` grant elsewhere cannot become one here.
        assert!(
            !set.evaluate("auditor", &path("sys/audit"), Capability::Read)
                .is_allowed()
        );
    }

    /// The default that ADR-23 turned around, as a test.
    ///
    /// `**` is the shape somebody writes for a break-glass identity meaning *all the
    /// secrets*, and it used to grant the audit trail, the identity inventory and the
    /// map of the authorization model with them. It no longer reaches any of them —
    /// and it still grants every secret, which is the part that must not change.
    #[test]
    fn a_broad_secret_grant_does_not_reach_the_control_plane() {
        let set = load(
            r#"
[[identity]]
name     = "break-glass"
kind     = "human"
policies = ["everything"]

[[policy]]
name = "everything"
  [[policy.rule]]
  path         = "**"
  capabilities = ["read", "write", "delete", "list", "undelete"]
"#,
        );

        assert!(
            set.evaluate("break-glass", &path("infra/a/DB"), Capability::Read)
                .is_allowed(),
            "every secret, as written"
        );

        for reserved in ["sys/audit", "sys/identities", "sys/policies", "sys/tokens"] {
            assert!(
                !set.evaluate("break-glass", &path(reserved), Capability::Inspect)
                    .is_allowed(),
                "{reserved} is not a secret and this rule grants secrets"
            );
            assert!(
                !set.evaluate("break-glass", &path(reserved), Capability::Revoke)
                    .is_allowed(),
                "{reserved} cannot be mutated by a secret grant either"
            );
        }
    }
}
