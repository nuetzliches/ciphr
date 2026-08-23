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
    /// Issue a token for an identity.
    ///
    /// Recorded because a credential is created here and nowhere else. Until
    /// 2026-08-20 it was not: the `tokens` table grew a row and the trail said
    /// nothing, so a token minted by whoever could reach the store and the master
    /// key was invisible — and every access made with it afterwards read as
    /// ordinary activity of a legitimate identity.
    ///
    /// This does not defend against that reader; nothing in software can, and the
    /// threat model says so (A5). What it changes is that hiding the act now
    /// requires rewriting the chain, which is exactly what the anchor outside the
    /// store detects. A chain can prove nothing was removed. It cannot show
    /// something that was never written into it.
    IssueToken,
    /// Revoke a token.
    ///
    /// One entry per token, including when a whole identity is revoked at once:
    /// the question asked afterwards is "when did *this* credential stop working",
    /// and a single entry with a count cannot answer it.
    RevokeToken,
    /// Change how safe a secret is recorded to be to rotate.
    ///
    /// Its own action rather than a [`Action::Write`], because the question it
    /// answers is different: a write produces a new version and is visible as
    /// one, while a reclassification changes no value and leaves no version
    /// behind. Folding it into `write` would make "who decided this was safe to
    /// rotate?" unanswerable from the trail — and downgrading a classification is
    /// the step that comes immediately before a rotation that destroys data.
    Classify,
    /// An audit device refused a record that another device accepted.
    ///
    /// Not an operation anybody requested — an event in the trail's own life. It exists
    /// because the chain advances when *any* device accepts, so the refusing device is
    /// permanently missing that sequence number, and a gap is indistinguishable from a
    /// deleted entry afterwards. This entry is what makes the difference recoverable:
    /// the trail explains its own gaps instead of leaving whoever finds one to guess,
    /// and guessing wrong means treating a disk hiccup as an unlogged access.
    AuditDeviceFailed,
    /// What optional surface this process started with.
    ///
    /// One entry at startup, naming the active entries of ADR-20's surface list, or
    /// `none`. Not an operation anybody requested — like [`Action::AuditDeviceFailed`],
    /// an event in the trail's own life.
    ///
    /// It exists because a deployment changing its own shape otherwise leaves no record
    /// the trail can be asked about. "Which routes did this service offer in March" is
    /// answerable from a configuration file only if somebody kept the version of it
    /// that was in effect in March, and the interesting case is the one where nobody
    /// did. The entry makes the question answerable from the trail, which is the one
    /// artefact this project keeps tamper-evident.
    SurfaceActive,
    /// Bait was taken (ADR-15).
    ///
    /// **The authoritative record of a trip, and the only one inside the fail-closed
    /// contract.** It replaces the action the entry would otherwise have carried rather
    /// than being written beside it, which is what keeps a trip free of extra work: one
    /// entry either way, the same size, through the same devices. A separate second
    /// entry would be work an ordinary rejected credential does not cause, and therefore
    /// measurable — the bait that announces itself to whoever measures carefully.
    ///
    /// The attempted action is not lost; it goes in [`Entry::detail`], because "they
    /// tried to read" and "they tried to write" are different facts about a compromise.
    ///
    /// The trip row, the marker file and the `/v1/health` flag are *derived* state,
    /// written after the response is flushed and outside the contract. See the dated
    /// decision in ADR-15 for why the split falls here: an audit device and the store
    /// hold separate connections, so a row and a record cannot be made to fail together.
    HoneypotTriggered,
    /// Bait was marked, or the mark was removed, on the host.
    ///
    /// Its own action rather than a [`Action::Classify`], although both attach a word to
    /// a secret without producing a version. `classify` answers "how safe is this to
    /// rotate", and folding bait into it would make two questions share one label — so
    /// "when did this path become bait?" would be answerable only by reading the value
    /// of a field the entry does not carry.
    ///
    /// [`Entry::detail`] says which direction: `marked` or `unmarked`.
    HoneypotMarked,
    /// An operator cleared the open trips, so bait can fire again.
    ///
    /// Distinct from [`Action::HoneypotTriggered`] for the reason that makes the
    /// distinction matter rather than for tidiness: a trail where clearing looks like
    /// firing reports an incident every time somebody tidies up after one, and the
    /// resulting count is the number nobody can use.
    HoneypotCleared,
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
            Self::Classify => "classify",
            Self::IssueToken => "issue-token",
            Self::RevokeToken => "revoke-token",
            Self::AuditDeviceFailed => "audit-device-failed",
            Self::SurfaceActive => "surface-active",
            Self::HoneypotTriggered => "honeypot-triggered",
            Self::HoneypotMarked => "honeypot-marked",
            Self::HoneypotCleared => "honeypot-cleared",
        }
    }
}

impl From<Capability> for Action {
    fn from(capability: Capability) -> Self {
        match capability {
            // **`read` and `inspect` share one action, and the shared arm is the
            // statement** (ADR-23): the trail's vocabulary did not grow with the
            // capability set. Reading `sys/audit` was recorded as `read` before the
            // control plane had a capability of its own and still is — the capability
            // answers *who may*, the action answers *what happened*, and a consumer
            // counting `read` entries sees no change from a split about authorization.
            Capability::Read | Capability::Inspect => Self::Read,
            Capability::Write => Self::Write,
            Capability::Delete => Self::Delete,
            Capability::List => Self::List,
            Capability::Undelete => Self::Undelete,
            // Revocation is the one control-plane mutation, and it already had an action
            // of its own — issued by the CLI since 2026-08-20 and now by the endpoint
            // ADR-24 adds. One spelling for both, so a trail reader does not have to know
            // which side a revocation came from.
            Capability::Revoke => Self::RevokeToken,
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
    /// Who or what the action was *about*, when that is not the actor.
    ///
    /// Set by the token actions and by nothing else so far. An operator on the
    /// host issues a credential *for* an identity, and those are two different
    /// parties: `principal` is `cli:<account>`, `subject` is the identity and the
    /// token's non-secret id. Folding the second into the first would make the
    /// trail say the operator authenticated with a token they had just minted.
    ///
    /// The token id is what joins this entry to every later access made with that
    /// credential, which is the whole reason it is here rather than in prose.
    pub subject: Option<Principal>,
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
    /// What an informational entry is about, when no path or identity says it.
    ///
    /// For entries that record an event in the trail's own life rather than an access:
    /// so far only [`Action::SurfaceActive`], which carries the names of the active
    /// surface entries or `none`.
    ///
    /// **Not a second `deny_reason`, and the difference is worth stating** because the
    /// two look interchangeable. [`Action::AuditDeviceFailed`] keeps naming its device
    /// in `deny_reason` and is right to: a device refused, so that entry has
    /// `allowed: false` and a refusal to explain. A surface entry refuses nothing, so
    /// `deny_reason` on it would make the trail claim a denial that never happened —
    /// which is precisely the confusion `0.4.0` had to warn consumers about when the
    /// correcting entries arrived.
    pub detail: Option<String>,
    /// Where the request came from.
    pub request: RequestContext,
}

impl Entry {
    /// An allowed action.
    pub fn allowed(action: Action) -> Self {
        Self {
            principal: None,
            subject: None,
            action,
            path: None,
            version: None,
            allowed: true,
            deny_reason: None,
            rule: None,
            results: None,
            detail: None,
            request: RequestContext::default(),
        }
    }

    /// A refused action, with the reason as a stable label.
    pub fn denied(action: Action, reason: impl Into<String>) -> Self {
        Self {
            principal: None,
            subject: None,
            action,
            path: None,
            version: None,
            allowed: false,
            deny_reason: Some(reason.into()),
            rule: None,
            results: None,
            detail: None,
            request: RequestContext::default(),
        }
    }

    /// Attach a detail string to an informational entry.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach the principal.
    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Attach the subject: who or what the action was about.
    ///
    /// Distinct from [`Entry::with_principal`], which is who performed it.
    #[must_use]
    pub fn with_subject(mut self, subject: Principal) -> Self {
        self.subject = Some(subject);
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

    /// **The two vocabularies were the same word, and since ADR-23 they are not.** The
    /// five capabilities about a secret still spell their action identically; the two
    /// about the control plane deliberately do not, because the trail's words describe
    /// what happened and the capability's describe who may. Reading `sys/audit` was
    /// recorded as `read` before the split and still is, so a consumer counting actions
    /// sees nothing change.
    #[test]
    fn a_capability_maps_to_the_action_that_describes_what_happened() {
        for capability in [
            Capability::Read,
            Capability::Write,
            Capability::Delete,
            Capability::List,
            Capability::Undelete,
        ] {
            assert_eq!(Action::from(capability).as_str(), capability.as_str());
        }

        assert_eq!(Action::from(Capability::Inspect).as_str(), "read");
        assert_eq!(Action::from(Capability::Revoke).as_str(), "revoke-token");
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
