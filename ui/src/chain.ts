/**
 * What this viewer can and cannot say about the audit chain.
 *
 * The endpoint returns each record as the exact stored bytes plus its hash, so a client
 * could recompute those hashes. This viewer does **not**: reproducing the stored bytes in
 * the browser means re-serializing parsed JSON and hoping the encoder agrees with
 * `serde_json` byte for byte. A second implementation of the hashed form is the same
 * class of mistake as a second path normalizer (ADR-9), and its failure mode is worse
 * than useless — a viewer that cries tampering because of an escaping difference is one
 * whose warnings get ignored.
 *
 * What it checks instead uses only what the service reported: that a page of records is a
 * run — consecutive sequence numbers, each record naming its predecessor's hash. That
 * detects a page that does not hang together. It does not detect an edited record whose
 * hash was updated to match, and it does not detect a forward rewrite.
 *
 * The full check is `ciphr audit verify`, and the one that survives a rewrite is
 * `ciphr audit verify --anchor` against a head recorded outside the store. The viewer
 * says so where it shows the result rather than leaving the reader to assume the
 * strongest reading.
 */
import type { AuditEntry } from "./api";

/** Sixty-four zeroes: the `prev_hash` of the first record in a chain. */
const GENESIS = "0".repeat(64);

export type LinkageStatus = "linked" | "broken" | "not-checked";

export interface Linkage {
  status: LinkageStatus;
  /** One sentence, for the badge's title and the panel under the table. */
  summary: string;
  /** Where it breaks, if it does — the sequence number and what is wrong there. */
  problems: string[];
}

/**
 * Check that a page of entries is a contiguous, linked run.
 *
 * `filtered` comes from the caller because only it knows whether narrowing filters were
 * applied. A filtered page is a selection rather than a run, so the check is skipped
 * instead of reporting the gaps that filtering necessarily produces.
 */
export function checkLinkage(entries: AuditEntry[], filtered: boolean): Linkage {
  if (filtered) {
    return {
      status: "not-checked",
      summary:
        "Not checked: a filtered page is a selection of records, not a run of the chain, so gaps between them are expected.",
      problems: [],
    };
  }

  if (entries.length === 0) {
    return { status: "not-checked", summary: "Nothing to check.", problems: [] };
  }

  const problems: string[] = [];
  let previous: AuditEntry | null = null;

  for (const entry of entries) {
    if (entry.seq !== entry.record.seq) {
      problems.push(
        `sequence ${entry.seq}: the record's own sequence number is ${entry.record.seq}, which disagrees with where it is stored`,
      );
    }

    if (previous === null) {
      // The first entry of the page links to something outside it, unless the page
      // starts at the beginning of the chain — where the genesis value is the only
      // correct predecessor.
      if (entry.seq === 1 && entry.record.prev_hash !== GENESIS) {
        problems.push(
          "sequence 1: the first record of a chain must name the genesis hash as its predecessor",
        );
      }
    } else {
      if (entry.seq !== previous.seq + 1) {
        problems.push(
          `sequence ${entry.seq}: expected ${previous.seq + 1}, so records are missing or duplicated here`,
        );
      } else if (entry.record.prev_hash !== previous.hash) {
        problems.push(
          `sequence ${entry.seq}: does not name the hash of sequence ${previous.seq}, so a record was removed, reordered, or inserted`,
        );
      }
    }

    previous = entry;
  }

  if (problems.length > 0) {
    return {
      status: "broken",
      summary: "This page does not hang together. Verify the chain with the CLI before acting on it.",
      problems,
    };
  }

  return {
    status: "linked",
    summary:
      "Every record on this page names its predecessor's hash. That shows the page is a run; it does not show the chain was not rewritten as a whole, which needs `ciphr audit verify --anchor`.",
    problems: [],
  };
}
