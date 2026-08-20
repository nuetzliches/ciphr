/**
 * The v1 API, as this viewer uses it.
 *
 * ADR-11's consequent rule: **only documented v1 endpoints.** An endpoint that existed
 * for the UI alone would be a design error, because it would mean the CLI could not do
 * something the viewer can. Every call below appears in `openapi.yaml`, and every one of
 * them is a read.
 *
 * Requests go to the same origin as the page. The deployment routes `/` to this
 * container and `/v1/*` to the service (plan section 15), which is why the
 * Content-Security-Policy can say `connect-src 'self'` and why CORS never appears.
 */
import { authorization, signOut } from "./session";

/** The stable machine-readable codes the service returns. */
export type ErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "bad_request"
  | "audit_unavailable"
  | "internal"
  | "unreachable";

/** A failed request, with the service's own code where it gave one. */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly detail: string | null;

  constructor(code: ErrorCode, status: number, message: string, detail: string | null) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.detail = detail;
  }

  /** What to show a person, including the part that describes their request. */
  get text(): string {
    return this.detail === null ? this.message : `${this.message} (${this.detail})`;
  }
}

async function request<T>(path: string, authenticated = true): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };

  if (authenticated) {
    const header = authorization();
    if (header === null) {
      throw new ApiError("unauthenticated", 401, "Not signed in.", null);
    }
    headers["Authorization"] = header;
  }

  let response: Response;
  try {
    response = await fetch(path, {
      method: "GET",
      headers,
      // No cookies exist for this origin and none should be sent if one ever does.
      credentials: "omit",
      // A cached response to a secret read is a secret without an expiry date.
      cache: "no-store",
      redirect: "error",
    });
  } catch (cause) {
    throw new ApiError(
      "unreachable",
      0,
      "The service could not be reached.",
      cause instanceof Error ? cause.message : null,
    );
  }

  if (response.status === 401) {
    // The token is gone, revoked, or expired. Dropping it here means the next view
    // renders the sign-in form instead of a row of identical failures.
    signOut();
  }

  if (!response.ok) {
    let code: ErrorCode = "internal";
    let message = `The service refused the request (HTTP ${response.status}).`;
    let detail: string | null = null;
    try {
      const body = (await response.json()) as {
        error?: ErrorCode;
        message?: string;
        detail?: string;
      };
      if (body.error !== undefined) {
        code = body.error;
      }
      if (body.message !== undefined) {
        message = body.message;
      }
      detail = body.detail ?? null;
    } catch {
      // A non-JSON error body means something other than the service answered — a proxy,
      // most likely. The status line is then all there is to report.
    }
    throw new ApiError(code, response.status, message, detail);
  }

  return (await response.json()) as T;
}

/** `GET /v1/health` — the one unauthenticated route. */
export interface Health {
  status: string;
  sealed: boolean;
  seal: string;
  key_source: string;
  api_version: string;
  /**
   * `accepting` is `null` until this process has written a record, and that third state
   * matters: "nothing recorded yet" is not "the last record was accepted", and a viewer
   * that collapses them either invents an alarm or hides one. The endpoint documents the
   * distinction, and rendering it takes three branches rather than a boolean.
   */
  audit_devices: { name: string; accepting: boolean | null }[];
}

export interface VersionSummary {
  version: number;
  created_at: number;
  created_by: string;
  deleted: boolean;
  destroyed: boolean;
}

/**
 * How safe a secret is recorded to be to rotate.
 *
 * `class` is kept as the string the service sent rather than a union type: a viewer
 * that could not render a class a later service added would be worse than one that
 * shows an unfamiliar word. `needs_care` is the service's own answer to whether this
 * should stop somebody, so the styling below does not re-derive that rule — and
 * `advice` is the same text the CLI prints, which is why it is not duplicated here.
 */
export interface Classification {
  class: string;
  needs_care: boolean;
  advice: string;
}

export interface History {
  path: string;
  rotation: Classification;
  versions: VersionSummary[];
}

export interface Secret {
  path: string;
  version: number;
  value: string;
  created_at: number;
  created_by: string;
}

export interface Listing {
  prefix: string;
  paths: string[];
}

export interface AuditEntry {
  seq: number;
  hash: string;
  record: {
    seq: number;
    ts: string;
    prev_hash: string;
    entry: {
      principal?: { name?: string; kind?: string | null; token_id?: string | null } | null;
      action: string;
      path?: string | null;
      version?: number | null;
      allowed: boolean;
      deny_reason?: string | null;
      rule?: { policy?: string; pattern?: string } | null;
      results?: number | null;
      request?: {
        request_id?: string | null;
        client_ip?: string | null;
        user_agent?: string | null;
        http_status?: number | null;
        channel?: string | null;
      };
    };
  };
}

export interface Identity {
  name: string;
  kind: string;
  policies: string[];
}

export interface PolicyRule {
  path: string;
  capabilities: string[];
  specificity: number;
}

export interface Policy {
  name: string;
  rules: PolicyRule[];
}

/** The filters `GET /v1/audit` accepts. Applied server-side, as the endpoint documents. */
export interface AuditFilters {
  limit?: number;
  after_seq?: number;
  since?: number;
  identity?: string;
  path?: string;
  decision?: "allow" | "deny";
}

/**
 * Whether a set of filters narrows the trail.
 *
 * It decides whether a page can be checked for linkage: a filtered page is a selection
 * of records rather than a run of the chain, so consecutive sequence numbers and
 * matching `prev_hash` values are not expected and their absence proves nothing.
 * `limit` and `after_seq` are paging, not narrowing, and stay out of it.
 */
export function narrows(filters: AuditFilters): boolean {
  return (
    filters.since !== undefined ||
    (filters.identity !== undefined && filters.identity !== "") ||
    (filters.path !== undefined && filters.path !== "") ||
    filters.decision !== undefined
  );
}

function query(filters: AuditFilters): string {
  const parameters = new URLSearchParams();
  if (filters.limit !== undefined) {
    parameters.set("limit", String(filters.limit));
  }
  if (filters.after_seq !== undefined) {
    parameters.set("after_seq", String(filters.after_seq));
  }
  if (filters.since !== undefined) {
    parameters.set("since", String(filters.since));
  }
  if (filters.identity !== undefined && filters.identity !== "") {
    parameters.set("identity", filters.identity);
  }
  if (filters.path !== undefined && filters.path !== "") {
    parameters.set("path", filters.path);
  }
  if (filters.decision !== undefined) {
    parameters.set("decision", filters.decision);
  }
  const text = parameters.toString();
  return text === "" ? "" : `?${text}`;
}

/**
 * A secret path in a URL path segment.
 *
 * Encoded per segment, so that the slashes separating segments survive and anything else
 * does not. The service normalizes and validates what arrives; this only has to avoid
 * sending something different from what was asked for.
 */
function encodePath(path: string): string {
  return path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

export const api = {
  health(): Promise<Health> {
    return request<Health>("/v1/health", false);
  },

  audit(filters: AuditFilters): Promise<{ entries: AuditEntry[] }> {
    return request<{ entries: AuditEntry[] }>(`/v1/audit${query(filters)}`);
  },

  list(prefix: string): Promise<Listing> {
    return request<Listing>(`/v1/list/${encodePath(prefix)}`);
  },

  versions(path: string): Promise<History> {
    return request<History>(`/v1/versions/${encodePath(path)}`);
  },

  /**
   * `GET /v1/secrets/{path}` — the only call that returns plaintext.
   *
   * One value, one call, one audit entry. There is no bulk form in this viewer even
   * though `/v1/export` exists: a bulk reveal would be a bulk audit entry and a bulk
   * leak at once (plan section 15).
   */
  reveal(path: string, version?: number): Promise<Secret> {
    const suffix = version === undefined ? "" : `?version=${version}`;
    return request<Secret>(`/v1/secrets/${encodePath(path)}${suffix}`);
  },

  identities(): Promise<{ identities: Identity[] }> {
    return request<{ identities: Identity[] }>("/v1/identities");
  },

  policies(): Promise<{ policies: Policy[] }> {
    return request<{ policies: Policy[] }>("/v1/policies");
  },
};
