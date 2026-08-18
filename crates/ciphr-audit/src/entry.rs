//! What an audit entry records.
//!
//! The contents are fixed by the threat model, not by convenience. Recorded:
//! who, what, where, which version, allowed or refused, which rule decided it, and
//! the request context. **Never** recorded: the secret value, key material, or a
//! token — only a token's non-secret identifier.
//!
//! That guarantee is structural rather than reviewed. Every field below is a
//! formattable type, and the types that hold secrets implement no `Serialize` at
//! all, so a field that carried one would not compile.
//!
//! Every field is written out, including as `null`. Skipping absent fields would
//! make "not applicable" and "this version of ciphr did not record it"
//! indistinguishable in a file that may be read years later.

use ciphr_core::{Capability, SecretPath, SecretVersion};
use serde::Serialize;

/// What was attempted.
///
/// The five capabilities plus the operations that are not capabilities because they
/// do not go through the API: initializing a store, rotating the master key, and
/// crypto-shredding a version all happen on the host (ADR-3), and all of them are
/// worth a line in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Read a secret value.
    Read,
    /// Write a new version.
    Write,
    /// Soft-delete a version.
    Delete,
    /// List paths or versions.
    List,
    /// Restore a soft-deleted version.
    Undelete,
    /// Initialize a store: generate and seal a root key.
    Init,
    /// Re-wrap the root key under a new master key.
    RotateMasterKey,
    /// Crypto-shred a version, irreversibly.
    Destroy,
    /// An audit device refused a record that another device accepted.
    ///
    /// Not an operation anybody requested — an event in the trail's own life. It exists
    /// because the chain advances when *any* device accepts, so the refusing device is
    /// permanently missing that sequence number, and a gap is indistinguishable from a
    /// deleted entry afterwards. This entry is what makes the difference recoverable:
    /// the trail explains its own gaps instead of leaving whoever finds one to guess,
    /// and guessing wrong means treating a disk hiccup as an unlogged access.
    AuditDeviceFailed,
}

impl Action {
    /// The stable label used in the audit trail.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Undelete => "undelete",
            Self::Init => "init",
            Self::RotateMasterKey => "rotate-master-key",
            Self::Destroy => "destroy",
            Self::AuditDeviceFailed => "audit-device-failed",
        }
    }
}

impl From<Capability> for Action {
    fn from(capability: Capability) -> Self {
        match capability {
            Capability::Read => Self::Read,
            Capability::Write => Self::Write,
            Capability::Delete => Self::Delete,
            Capability::List => Self::List,
            Capability::Undelete => Self::Undelete,
        }
    }
}

impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who acted.
///
/// The token identifier is the non-secret leading part of a token (`cph_<id>`),
/// which is what makes it possible to attribute an access to one credential of an
/// identity — and to answer "which token was that?" after revoking it. The secret
/// half never appears here or anywhere else that is written down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    /// The identity name, as configured.
    pub name: String,
    /// `machine` or `human`, when known.
    pub kind: Option<String>,
    /// The non-secret identifier of the token used, when one was used.
    pub token_id: Option<String>,
}

impl Principal {
    /// A principal known only by name.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: None,
            token_id: None,
        }
    }
}

/// The rule that decided an access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecidingRule {
    /// The policy the rule belongs to.
    pub policy: String,
    /// The pattern, as normalized.
    pub pattern: String,
}

/// Where the request came from.
///
/// All optional, because not every audited action is an HTTP request: `ciphr init`
/// on the host has no client address and no user agent, and inventing one would put
/// a fiction in the record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RequestContext {
    /// The request identifier, for correlating with other logs.
    pub request_id: Option<String>,
    /// The client address, as the listener saw it.
    pub client_ip: Option<String>,
    /// The user agent, truncated by the caller if it is absurd.
    pub user_agent: Option<String>,
    /// The HTTP status that was returned.
    pub http_status: Option<u16>,
    /// A marker for the channel the request arrived through.
    ///
    /// Set to `mcp` by the MCP server (ADR-13), so that it stays possible to
    /// distinguish afterwards what a human read from what flowed into a model
    /// context.
    pub channel: Option<String>,
}

/// One audited access.
///
/// Construct through [`Entry::new`] and the `with_` methods, so that the required
/// facts — who, what, and whether it was allowed — cannot be forgotten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Who acted. `None` when authentication failed before an identity was
    /// established, which is itself worth recording.
    pub principal: Option<Principal>,
    /// What was attempted.
    pub action: Action,
    /// The normalized path, when the action has one.
    pub path: Option<String>,
    /// The version, when the action concerns one.
    pub version: Option<u32>,
    /// Whether the action was permitted.
    pub allowed: bool,
    /// Why it was refused, as a stable label.
    pub deny_reason: Option<String>,
    /// The rule that decided it.
    pub rule: Option<DecidingRule>,
    /// How many items an operation returned, when it authorizes **per returned item**
    /// rather than through one decision.
    ///
    /// Set only by listing. Its presence is what marks the entry as *not* carrying a
    /// single authorization decision — which is why `rule` is `None` there, and why
    /// `allowed` on such an entry means "the operation ran", not "a rule permitted it".
    /// Without this, a listing looked like an allow that no rule had produced, and the
    /// trail could not say how much had been revealed.
    ///
    /// The names themselves are deliberately absent: an audit entry that grew with the
    /// size of a listing would be a way to make records unbounded, and the caller's
    /// policy already bounds what those names can be.
    pub results: Option<u32>,
    /// Where the request came from.
    pub request: RequestContext,
}

impl Entry {
    /// An allowed action.
    pub fn allowed(action: Action) -> Self {
        Self {
            principal: None,
            action,
            path: None,
            version: None,
            allowed: true,
            deny_reason: None,
            rule: None,
            results: None,
            request: RequestContext::default(),
        }
    }

    /// A refused action, with the reason as a stable label.
    pub fn denied(action: Action, reason: impl Into<String>) -> Self {
        Self {
            principal: None,
            action,
            path: None,
            version: None,
            allowed: false,
            deny_reason: Some(reason.into()),
            rule: None,
            results: None,
            request: RequestContext::default(),
        }
    }

    /// Attach the principal.
    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Attach the path. Takes a parsed path, so an unnormalized one cannot be
    /// recorded — an audit trail whose paths do not match the paths authorization
    /// used would be worse than none.
    #[must_use]
    pub fn with_path(mut self, path: &SecretPath) -> Self {
        self.path = Some(path.as_str().to_owned());
        self
    }

    /// Attach the version.
    #[must_use]
    pub fn with_version(mut self, version: SecretVersion) -> Self {
        self.version = Some(version.get());
        self
    }

    /// Record how many items the operation returned.
    ///
    /// For operations that authorize per returned item. See [`Entry::results`].
    #[must_use]
    pub fn with_results(mut self, count: usize) -> Self {
        self.results = Some(u32::try_from(count).unwrap_or(u32::MAX));
        self
    }

    /// Attach the rule that decided the access.
    #[must_use]
    pub fn with_rule(mut self, policy: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.rule = Some(DecidingRule {
            policy: policy.into(),
            pattern: pattern.into(),
        });
        self
    }

    /// Attach the request context.
    #[must_use]
    pub fn with_request(mut self, request: RequestContext) -> Self {
        self.request = request;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Entry, Principal};
    use ciphr_core::{Capability, SecretPath, SecretVersion};

    #[test]
    fn every_capability_maps_to_an_action() {
        for capability in Capability::ALL {
            let action = Action::from(capability);
            assert_eq!(action.as_str(), capability.as_str());
        }
    }

    #[test]
    fn actions_that_are_not_capabilities_exist_for_host_operations() {
        // These happen through the CLI rather than the API, and they are exactly
        // the operations someone would want to find in the trail afterwards.
        for action in [Action::Init, Action::RotateMasterKey, Action::Destroy] {
            assert!(!action.as_str().is_empty());
            assert!(Capability::parse(action.as_str()).is_err());
        }
    }

    #[test]
    fn an_entry_carries_what_it_was_given_and_nothing_else() {
        let path = SecretPath::parse("infra/a/DB").unwrap();
        let entry = Entry::allowed(Action::Read)
            .with_principal(Principal {
                name: "deploy".to_owned(),
                kind: Some("machine".to_owned()),
                token_id: Some("a1b2c3d4".to_owned()),
            })
            .with_path(&path)
            .with_version(SecretVersion::FIRST)
            .with_rule("infra", "infra/**");

        assert!(entry.allowed);
        assert_eq!(entry.path.as_deref(), Some("infra/a/DB"));
        assert_eq!(entry.version, Some(1));
        assert_eq!(entry.deny_reason, None);
        assert_eq!(entry.rule.unwrap().pattern, "infra/**");
        assert_eq!(entry.principal.unwrap().token_id.unwrap(), "a1b2c3d4");
    }

    #[test]
    fn a_denial_records_its_reason() {
        let entry = Entry::denied(Action::Write, "not-granted");
        assert!(!entry.allowed);
        assert_eq!(entry.deny_reason.as_deref(), Some("not-granted"));
    }
}
