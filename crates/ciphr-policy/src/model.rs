//! The policy model, and loading it from TOML.
//!
//! The file format is the model, near enough that reading one tells you the
//! other:
//!
//! ```toml
//! [[identity]]
//! name     = "deploy-runner"
//! kind     = "machine"
//! policies = ["infra-read"]
//!
//! [[policy]]
//! name = "infra-read"
//!
//!   [[policy.rule]]
//!   path         = "infra/**"
//!   capabilities = ["read", "list"]
//!
//!   [[policy.rule]]
//!   path         = "infra/ciphr/**"
//!   capabilities = []          # explicit denial: no self-access
//! ```
//!
//! `capabilities` is **required**, including when it is empty. An omitted list
//! would be ambiguous between "denies everything" and "I forgot to write it", and
//! those two readings are opposites in the only case that matters. Writing
//! `capabilities = []` makes an explicit denial explicit.
//!
//! Loading is strict throughout: an unknown key, an unknown capability, a
//! reference to a policy that does not exist, or two rules for the same pattern
//! all refuse the whole file. A policy set that loads partially is a set of
//! permissions nobody wrote.

use std::collections::{BTreeMap, BTreeSet};

use ciphr_core::{Capability, PathPattern};
use serde::Deserialize;

use crate::error::PolicyError;

/// What kind of principal an identity is.
///
/// Machines and humans authenticate the same way in v1 — a bearer token — so this
/// is not an authorization input. It exists so that the audit trail can say which
/// kind of principal read a secret, and so that human tokens can be given shorter
/// lifetimes than machine tokens (ADR-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityKind {
    /// A machine: a CI job, a deploy runner, a service.
    Machine,
    /// A person, signing in to the read-only UI.
    Human,
}

impl IdentityKind {
    /// The configured form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::Human => "human",
        }
    }
}

impl core::fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rule: a pattern and the capabilities it grants.
///
/// An empty capability set is an **explicit denial**, and it is not the same thing
/// as the absence of a rule: it beats any less specific permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pattern: PathPattern,
    capabilities: BTreeSet<Capability>,
}

impl Rule {
    /// The pattern this rule applies to.
    pub fn pattern(&self) -> &PathPattern {
        &self.pattern
    }

    /// The capabilities this rule grants. Empty means explicit denial.
    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    /// Whether this rule denies everything it matches.
    pub fn is_denial(&self) -> bool {
        self.capabilities.is_empty()
    }
}

/// A named set of rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    name: String,
    rules: Vec<Rule>,
}

impl Policy {
    /// The policy name, as referenced by identities.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its rules, in the order they were written.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// A principal and the policies attached to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    name: String,
    kind: IdentityKind,
    policies: Vec<String>,
}

impl Identity {
    /// The identity name, which is what the audit trail records.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Machine or human.
    pub fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// The names of the policies attached to this identity.
    ///
    /// An identity with no policies can do nothing, which is a valid — if
    /// pointless — configuration under deny by default.
    pub fn policies(&self) -> &[String] {
        &self.policies
    }
}

/// Every identity and policy, loaded and validated.
///
/// Immutable once built. There is no way to add a rule at runtime, because there
/// is no policy-write API (ADR-3): the file in version control is the only source,
/// and its commit history is part of the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicySet {
    identities: BTreeMap<String, Identity>,
    policies: BTreeMap<String, Policy>,
}

impl PolicySet {
    /// Parse and validate a policy file.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] on the first problem found. Nothing is loaded
    /// partially: either the whole file is usable or none of it is.
    pub fn from_toml(input: &str) -> Result<Self, PolicyError> {
        let raw: RawConfig = toml::from_str(input)?;

        let mut policies = BTreeMap::new();
        for raw_policy in raw.policy {
            let policy = build_policy(raw_policy)?;
            if policies.contains_key(policy.name()) {
                return Err(PolicyError::DuplicatePolicy { name: policy.name });
            }
            policies.insert(policy.name.clone(), policy);
        }

        let mut identities = BTreeMap::new();
        for raw_identity in raw.identity {
            let identity = build_identity(raw_identity, &policies)?;
            if identities.contains_key(identity.name()) {
                return Err(PolicyError::DuplicateIdentity {
                    name: identity.name,
                });
            }
            identities.insert(identity.name.clone(), identity);
        }

        Ok(Self {
            identities,
            policies,
        })
    }

    /// Look up an identity by name.
    pub fn identity(&self, name: &str) -> Option<&Identity> {
        self.identities.get(name)
    }

    /// Every identity, ordered by name.
    pub fn identities(&self) -> impl Iterator<Item = &Identity> {
        self.identities.values()
    }

    /// Look up a policy by name.
    pub fn policy(&self, name: &str) -> Option<&Policy> {
        self.policies.get(name)
    }

    /// Every policy, ordered by name.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }
}

/// The TOML shape. Separate from the model so that the model can hold parsed,
/// validated types — a `PathPattern` rather than a `String` — and so that nothing
/// in the rest of the crate has to wonder whether a value has been checked.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    identity: Vec<RawIdentity>,
    #[serde(default)]
    policy: Vec<RawPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    name: String,
    kind: String,
    #[serde(default)]
    policies: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    name: String,
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    path: String,
    /// Deliberately not `#[serde(default)]`: see the module documentation.
    capabilities: Vec<String>,
}

fn build_policy(raw: RawPolicy) -> Result<Policy, PolicyError> {
    let mut rules: Vec<Rule> = Vec::with_capacity(raw.rule.len());

    for raw_rule in raw.rule {
        let pattern =
            PathPattern::parse(&raw_rule.path).map_err(|reason| PolicyError::Pattern {
                policy: raw.name.clone(),
                pattern: raw_rule.path.clone(),
                reason,
            })?;

        if rules.iter().any(|existing| existing.pattern == pattern) {
            return Err(PolicyError::DuplicatePattern {
                policy: raw.name,
                pattern: pattern.as_str().to_owned(),
            });
        }

        let mut capabilities = BTreeSet::new();
        for name in raw_rule.capabilities {
            let capability =
                Capability::parse(&name).map_err(|reason| PolicyError::Capability {
                    policy: raw.name.clone(),
                    pattern: pattern.as_str().to_owned(),
                    reason,
                })?;
            if !capabilities.insert(capability) {
                return Err(PolicyError::DuplicateCapability {
                    policy: raw.name.clone(),
                    pattern: pattern.as_str().to_owned(),
                    capability: name,
                });
            }
        }

        rules.push(Rule {
            pattern,
            capabilities,
        });
    }

    Ok(Policy {
        name: raw.name,
        rules,
    })
}

fn build_identity(
    raw: RawIdentity,
    policies: &BTreeMap<String, Policy>,
) -> Result<Identity, PolicyError> {
    let kind = match raw.kind.as_str() {
        "machine" => IdentityKind::Machine,
        "human" => IdentityKind::Human,
        other => {
            return Err(PolicyError::UnknownIdentityKind {
                identity: raw.name,
                found: other.to_owned(),
            });
        }
    };

    let mut seen = BTreeSet::new();
    for policy in &raw.policies {
        if !policies.contains_key(policy) {
            return Err(PolicyError::UnknownPolicy {
                identity: raw.name.clone(),
                policy: policy.clone(),
            });
        }
        if !seen.insert(policy.clone()) {
            return Err(PolicyError::DuplicatePolicyReference {
                identity: raw.name.clone(),
                policy: policy.clone(),
            });
        }
    }

    Ok(Identity {
        name: raw.name,
        kind,
        policies: raw.policies,
    })
}

#[cfg(test)]
mod tests {
    use super::{IdentityKind, PolicySet};
    use crate::error::PolicyError;
    use ciphr_core::Capability;

    const EXAMPLE: &str = r#"
[[identity]]
name     = "deploy-runner"
kind     = "machine"
policies = ["infra-read"]

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
    fn loads_the_documented_example() {
        let set = PolicySet::from_toml(EXAMPLE).expect("the example must load");

        let identity = set.identity("deploy-runner").expect("identity");
        assert_eq!(identity.kind(), IdentityKind::Machine);
        assert_eq!(identity.policies(), ["infra-read"]);

        let policy = set.policy("infra-read").expect("policy");
        assert_eq!(policy.rules().len(), 2);
        assert_eq!(policy.rules()[0].pattern().as_str(), "infra/**");
        assert_eq!(
            policy.rules()[0]
                .capabilities()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [Capability::Read, Capability::List]
        );
        assert!(policy.rules()[1].is_denial());
    }

    #[test]
    fn an_empty_file_is_a_valid_policy_set_that_grants_nothing() {
        let set = PolicySet::from_toml("").expect("an empty file is valid");
        assert_eq!(set.identities().count(), 0);
        assert_eq!(set.policies().count(), 0);
    }

    #[test]
    fn a_missing_capabilities_list_is_refused() {
        // The ambiguity this avoids: "denies everything" versus "I forgot".
        let error = PolicySet::from_toml(
            r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path = "a/**"
"#,
        )
        .expect_err("capabilities is required");
        assert!(matches!(error, PolicyError::Syntax(_)), "got {error}");
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let error = PolicySet::from_toml(
            r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path         = "a/**"
  capabilities = ["read"]
  effect       = "allow"
"#,
        )
        .expect_err("unknown keys must not be ignored");
        assert!(matches!(error, PolicyError::Syntax(_)), "got {error}");
    }

    #[test]
    fn a_dangling_policy_reference_is_refused() {
        let error = PolicySet::from_toml(
            r#"
[[identity]]
name     = "runner"
kind     = "machine"
policies = ["does-not-exist"]
"#,
        )
        .expect_err("a dangling reference must not load");
        assert!(matches!(
            error,
            PolicyError::UnknownPolicy { ref identity, ref policy }
                if identity == "runner" && policy == "does-not-exist"
        ));
    }

    #[test]
    fn duplicates_are_refused() {
        let cases = [
            (
                r#"
[[policy]]
name = "p"
[[policy]]
name = "p"
"#,
                "two policies",
            ),
            (
                r#"
[[identity]]
name = "a"
kind = "machine"
[[identity]]
name = "a"
kind = "machine"
"#,
                "two identities",
            ),
            (
                r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path         = "a/**"
  capabilities = ["read"]
  [[policy.rule]]
  path         = "a/**"
  capabilities = ["write"]
"#,
                "two rules for one pattern",
            ),
            (
                r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path         = "a/**"
  capabilities = ["read", "read"]
"#,
                "a repeated capability",
            ),
        ];

        for (input, what) in cases {
            assert!(
                PolicySet::from_toml(input).is_err(),
                "{what} must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_capability_or_kind_is_refused() {
        assert!(matches!(
            PolicySet::from_toml(
                r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path         = "a/**"
  capabilities = ["admin"]
"#
            ),
            Err(PolicyError::Capability { .. })
        ));

        assert!(matches!(
            PolicySet::from_toml(
                r#"
[[identity]]
name = "a"
kind = "robot"
"#
            ),
            Err(PolicyError::UnknownIdentityKind { .. })
        ));
    }

    #[test]
    fn an_invalid_pattern_is_refused_with_its_policy_named() {
        let error = PolicySet::from_toml(
            r#"
[[policy]]
name = "p"
  [[policy.rule]]
  path         = "infra/**/db"
  capabilities = ["read"]
"#,
        )
        .expect_err("a middle ** must not load");
        assert!(matches!(error, PolicyError::Pattern { .. }));
        assert!(error.to_string().contains("'p'"));
    }
}
