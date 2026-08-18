-- Migration 003: tokens.
--
-- There is deliberately **no identities table**, which is a departure from the data
-- model sketched in the plan. Identities are defined in the policy file, which is
-- authoritative (ADR-3); a table holding them as well would be a second source of
-- truth for the same fact, and two sources of truth drift. A token therefore
-- references an identity by *name*, and a token whose identity is not in the policy
-- file authenticates to nothing — deny by default already covers that case.
--
-- `verifier` is HMAC-SHA256 of the token's secret half under a pepper derived from
-- the root key. A copy of this database alone does not permit offline verification
-- of guessed tokens, because the pepper cannot be reconstructed without the master
-- key.
--
-- `token_id` is the non-secret leading part of the token. It is the primary key, so
-- authentication is one indexed lookup rather than a scan over every verifier.
CREATE TABLE tokens (
    token_id      TEXT PRIMARY KEY NOT NULL,
    identity_name TEXT    NOT NULL,
    verifier      TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    created_by    TEXT    NOT NULL,
    -- NULL means no expiry. Every token issued for CI should have one; the column
    -- allows its absence because a bootstrap token on a host may legitimately
    -- outlive any TTL someone would pick today.
    expires_at    INTEGER,
    last_used_at  INTEGER,
    revoked_at    INTEGER
) STRICT;

-- Listing and revoking work by identity.
CREATE INDEX tokens_identity ON tokens (identity_name);
