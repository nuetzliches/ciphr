/* ciphr — the security layers.
 *
 * The diagram is assembled from the table below, so that geometry and statement sit
 * in one place. It is an ordering of the documentation, not its source: every entry
 * links to the document that decided the thing.
 *
 * Three rules carry the drawing:
 *
 *   1. Rings are boundaries with a gate, not quality levels. Their order is the
 *      order in which a request crosses them.
 *   2. Crates are not rings. The reviewed core is a *band* across several rings,
 *      because that is its property: one shape in every build (ADR-20 P1).
 *   3. What crosses no ring is drawn as a cut. Root on the host and the build
 *      pipeline ignore the onion; an onion without them would be advertising.
 */

'use strict';

const REPO = 'https://github.com/nuetzliches/ciphr';
const src = (path, label) => ({ label: label || path, href: REPO + '/blob/main/' + path });

const SVGNS = 'http://www.w3.org/2000/svg';

/* ── Geometry ───────────────────────────────────────────────────────────── */

const R_ASSET = 108;
const RINGS = [
  { id: 'reach',   r: 425, cls: 'is-deployment' },
  { id: 'tls',     r: 360, cls: '' },
  { id: 'surface', r: 300, cls: 'is-switchable' },
  { id: 'auth',    r: 235, cls: '' },
  { id: 'authz',   r: 170, cls: '' }
];

const BAND = { from: 155, to: 246, rOuter: 268 };

/* Angles are mathematical: 0 to the right, 90 up. */
const pol = (r, deg) => {
  const a = (deg * Math.PI) / 180;
  return [r * Math.cos(a), -r * Math.sin(a)];
};

/* ── Content ────────────────────────────────────────────────────────────── */

const CONTENT = {

  asset: {
    kind: 'Centre · the asset',
    title: 'Plaintext and key material',
    badges: [['tag-plain', 'built'], ['tag-warn', 'A5 reaches it']],
    lead: 'Exactly one process holds both. Everything outside the rings is a client with a token and a policy — the viewer too, the CLI too, and the MCP server if it ever exists.',
    sections: [
      { h: 'What is here', items: [
        '<strong>The master key</strong> wraps the root key, and the root key wraps one data key per secret <em>version</em>. One key encrypts exactly one payload, so nonce reuse <em>on a value</em> cannot occur.',
        '<strong>The nonces of the root-key wraps are random.</strong> There the guarantee is a bound rather than a structure — and <code>docs/crypto.md</code> says so instead of leaving it out.',
        '<strong>Plaintext, for as long as a request runs.</strong> Secret-bearing types implement neither <code>Debug</code> nor <code>Display</code> nor <code>Serialize</code>: logging one is a compile error rather than a review question. That is the main reason for the choice of language (ADR-1).',
        '<strong>ZeroizeOnDrop on key material</strong>, plus a memory limit equal to the swap limit and core dumps switched off — the part the language cannot solve alone.'
      ]},
      { h: 'Who reads it anyway', items: [
        'Root on the host (A5). See the cut — not defended, and deliberately so.'
      ]}
    ],
    sources: [src('docs/crypto.md'), src('docs/threat-model.md'), src('docs/adr/0001-language-rust.md', 'ADR-1')],
    covered: true
  },

  band: {
    kind: 'Band · not a ring',
    title: 'The reviewed core',
    badges: [['tag-plain', '~1500 lines'], ['tag-plain', 'one shape in every build']],
    lead: 'Not the innermost zone, but the code that decides every access — and which is therefore unconditional. It runs across three rings: the authorization, the verification on the auth ring, and the envelope gate to the store.',
    sections: [
      { h: 'What belongs to it', items: [
        '<code>ciphr-crypto</code> and <code>ciphr-policy</code> in full, plus <code>path.rs</code>, <code>pattern.rs</code> and <code>secret.rs</code> from <code>ciphr-core</code>.',
        '<strong>No Cargo feature, no <code>cfg(feature)</code>, no reference to a surface module</strong> — and no features handed to them from outside by a dependent. Four claims that <code>ci/check-core-no-features.sh</code> checks as a blocking gate.',
        '<strong>Where an optional feature needs something from the core, the core gains it unconditionally.</strong> Not a gated function but a general one, read once, present in every build — the optional part sits on top of it and outside.'
      ]},
      { h: 'Why a band and not a ring', items: [
        'A ring would claim the core is a shell with a gate of its own. It is a section through several instead: the HMAC verification of a token is inside it, <em>looking the identity up in <code>ciphr-store</code> is not</em>. What the review of 2026-08-21 read hangs on exactly that edge.',
        '<strong>The boundary is the statement.</strong> If optionality moves into these lines, "the reviewer read the code that decides every access" becomes "… in one configuration". A review that has to be repeated per configuration is a promise to do one later.'
      ]}
    ],
    sources: [src('docs/adr/0020-optional-surface.md', 'ADR-20'), src('ci/check-core-no-features.sh'), src('docs/security-review.md')],
    covered: true
  },

  reach: {
    kind: 'Ring 1 · a property of the deployment',
    title: 'Reachability is the first control',
    badges: [['tag-plain', 'no code'], ['tag-warn', 'finding F5']],
    lead: 'Dashed, because there is no line of code behind it — only the network, the reverse proxy, and the decision not to publish a port. It is the first ring nonetheless, because one class of attack has to cross no other.',
    sections: [
      { h: 'Why the ring is here', items: [
        '<strong>Every request with a missing or invalid token writes an audit entry</strong> — deliberately, because brute force that leaves no trace would be worse.',
        '<strong>And auditing is fail-closed.</strong> Both sentences are decisions the threat model defends. Together they mean: whoever reaches the listener can fill the audit store until the volume is full, and needs no credential to do it.',
        'What follows is a deployment requirement rather than a code change: no published port, deploys through a runner inside the network, a <strong>rate limit on 401s in front of the listener</strong>, and an <strong>alert on the growth</strong> of the audit store rather than only on free space. Growth arrives early enough to act on; a full volume <em>is</em> the outage.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/operations/audit-trail.md')],
    covered: false
  },

  tls: {
    kind: 'Ring 2 · transport',
    title: 'TLS ends at the service, not at the proxy',
    badges: [['tag-plain', 'built'], ['tag-switch', 'never switchable']],
    lead: 'The deliberate deviation from the usual arrangement: the content of these connections is plaintext secrets, and a compromised container on the same network is a realistic adversary (A2).',
    sections: [
      { h: 'What holds', items: [
        'The reverse proxy connects over HTTPS with a <strong>pinned internal certificate</strong> (ADR-8, provenance in ADR-17).',
        '<code>--insecure</code> appears in no example, not even for testing. Even the viewer\'s development proxy disables no certificate check; it points Node at the deployment\'s CA.',
        '<code>ciphr-sdk</code> cannot even trust the public CA set: <code>ureq</code> is built without <code>webpki-roots</code>, so a client that trusts the world is not buildable (ADR-19).'
      ]},
      { h: 'Property 4', items: [
        'TLS at the listener is on the closed list of what may never become a surface entry. Changing that list is a new record.'
      ]}
    ],
    sources: [src('docs/adr/0008-tls-terminates-at-the-service.md', 'ADR-8'), src('docs/adr/0017-certificate-provenance.md', 'ADR-17'), src('docs/ui.md')],
    covered: false,
    p4: true
  },

  surface: {
    kind: 'Ring 3 · surface',
    title: 'Off means absent, not asleep',
    badges: [['tag-switch', 'the only switchable ring'], ['tag-plain', 'ADR-20']],
    lead: 'Is this route registered in this deployment at all? That question is answered <em>before</em> authentication — and not as a convention but in the wiring: <code>api.rs</code> registers routes conditionally, and <code>authenticate()</code> sits inside the handlers.',
    sections: [
      { h: 'The two kinds of switch', items: [
        '<strong>runtime</strong> — composed at startup. Off means the route is never registered and axum answers from the fallback. No <code>if enabled { … } else { 404 }</code> in a living handler, because a sleeping handler is reachable code with a branch, and the branch is where the mistake goes. Absence is also observable from outside; a branch is not.',
        '<strong>build</strong> — a Cargo feature, off in the default build. The choice where a deployment has to prove the code is <em>not there</em> rather than merely not called. It costs a build matrix and is therefore not the standard answer.'
      ]},
      { h: 'An asymmetry worth a label', items: [
        'A route that is <strong>not registered</strong> is answered with a 404 without a token check and without an audit entry. A route that <strong>exists</strong> writes an entry even for an invalid token. The same status code, two entirely different traces.'
      ]},
      { h: 'An entry is a record', items: [
        'Three mandatory fields: whether it is on, the date on which the deployment accepted the cost, and the reason. <strong>The server does not start on an entry that cannot say since when and why</strong> — the same refusal as a start without an audit device.',
        '<code>/v1/health</code> names the active entries, because monitoring that cannot see the shape of what it watches is watching a different system. <strong>The reason is readable only with authentication</strong> (<code>ciphr surface show</code>, <code>GET /v1/surface</code>), because it is prose about one concrete environment.',
        'Startup writes an audit entry about the active surface, so the trail says when a deployment changed its own shape.',
        '<code>/v1/surface</code> is deliberately not an entry itself: a route that disappears when the list is empty would make "nothing is on" and "this build does not have the mechanism" one answer.'
      ]}
    ],
    sources: [src('docs/adr/0020-optional-surface.md', 'ADR-20'), src('crates/ciphr-server/src/api.rs'), src('openapi.yaml')],
    covered: false
  },

  auth: {
    kind: 'Ring 4 · authentication',
    title: 'No anonymous endpoint except /v1/health',
    badges: [['tag-plain', 'built'], ['tag-switch', 'partly never switchable']],
    lead: 'A token of the form <code>cph_</code> plus an 8-character identifier plus a 43-character secret. The sentence about the anonymous endpoint is by now expected to stay true rather than to expire — the one route that would have broken it is deferred.',
    sections: [
      { h: 'What is checked', items: [
        '<strong>A peppered verifier, in constant time.</strong> Token, HMAC and tag comparisons do not reveal where they differ. A token is 256 bits of randomness, so password hashing would be CPU on every request for a dictionary that does not exist.',
        'The eight-character, non-secret identifier goes into the audit trail — and the viewer shows exactly that, so what was seen can be tied to one\'s own entries.',
        '<strong>Every failed attempt is an entry.</strong> See ring 1: that is a decision with a side effect, and both are in the threat model.'
      ]},
      { h: 'Where the band crosses this ring', items: [
        'The verification is in <code>ciphr-crypto</code> and therefore in the reviewed core. Looking the identity up is in <code>ciphr-store</code> and therefore outside it — and that is also where the bait recognition of the build entry <code>honeypot_alert</code> lives.'
      ]}
    ],
    sources: [src('docs/adr/0006-auth-machine-identities-with-tokens.md', 'ADR-6'), src('docs/threat-model.md'), src('docs/security-review.md')],
    covered: true,
    p4: true
  },

  authz: {
    kind: 'Ring 5 · authorization',
    title: 'Deny by default, one normalization',
    badges: [['tag-plain', 'built'], ['tag-switch', 'never switchable']],
    lead: 'Path-based capabilities with glob patterns. The policy comes from configuration under version control rather than from a write API — which makes the commit history an audit trail in itself (ADR-3).',
    sections: [
      { h: 'The rule most likely to surprise', items: [
        '<strong>The most specific match wins entirely and inherits nothing</strong> from broader rules. Specificity is the number of literal segments.',
        'An <strong>empty capability list is an explicit denial</strong>, not a missing entry. The viewer labels both as such rather than leaving it to be derived.'
      ]},
      { h: 'Why there is exactly one normalization', items: [
        'Two normalizations that differ by one character in one edge case are an authorization bypass nobody notices. So the function exists <strong>exactly once</strong> and is called by the router <em>and</em> the evaluator (ADR-9), covered by property tests and a fuzzer.',
        'Unicode NFC belongs to it: two encodings of the same path must not become two different secrets.'
      ]},
      { h: 'Bulk', items: [
        '<strong>One audit entry per secret served, never one per call.</strong> A collective entry for a bulk read is exactly the blind spot that disqualified other candidates during the evaluation.'
      ]}
    ],
    sources: [src('docs/authorization.md'), src('docs/adr/0009-http-stack-axum-but-narrow.md', 'ADR-9'), src('docs/fuzzing.md')],
    covered: true,
    p4: true
  },

  store: {
    kind: 'Lateral boundary',
    title: 'To the disk: SQLite holds only ciphertext',
    badges: [['tag-plain', 'built'], ['tag-switch', 'never switchable']],
    lead: 'Not an outer shell but a boundary <em>to the side</em>. A pure onion knows only inward movement and would leave this edge out.',
    sections: [
      { h: 'What holds here', items: [
        '<strong>Path and version are bound as additional authenticated data.</strong> A ciphertext cannot be moved from path A to path B — whoever can write to the database gets a decryption failure rather than a silent transfer of authority.',
        'Whoever reads the file (a backup, a stolen disk — A4) holds complete ciphertext. <strong>Without the master key the database is worthless</strong> — which is why the key and the backup do not belong in the same bucket, or the backup <em>is</em> the secret store.',
        'The envelope scheme and its AAD binding are on the closed list (property 4).'
      ]}
    ],
    sources: [src('docs/crypto.md'), src('docs/operations/master-key.md'), src('docs/adr/0007-storage-sqlite-behind-a-store-trait.md', 'ADR-7')],
    covered: false,
    p4: true
  },

  audit: {
    kind: 'Lateral boundary · on the way back',
    title: 'To the trail: record before response',
    badges: [['tag-plain', 'built'], ['tag-switch', 'never switchable']],
    lead: 'The only gate that is not on the way in. The entry is stored before the response is produced — if no configured device accepts the record, <strong>the request is refused and no secret is served</strong>.',
    sections: [
      { h: 'What holds', items: [
        'The server does not start without an audit device. The requirement and the ordering are on the closed list — it is the first request anybody will make of the surface mechanism, and property 4 answers it once and in writing, so that it is not renegotiated during an incident.',
        'Entries form a <strong>hash chain</strong>: removing or changing an entry is detectable. <code>ciphr audit verify</code> checks it, and a recovery path for a broken chain is part of the design.',
        '<strong>What the chain does not do:</strong> it detects partial tampering, not a forward rewrite by somebody who may write to the store. The only answer to that is <code>ciphr audit verify --anchor</code> against a head held outside it.',
        'The chain badge in the viewer checks that a <em>page</em> is one run — it recomputes no hashes. A second implementation of the hashed form would be the same class of bug as a second path normalizer, and its failure would be worse than useless.'
      ]}
    ],
    sources: [src('docs/operations/audit-trail.md'), src('docs/ui.md'), src('docs/threat-model.md')],
    covered: false,
    p4: true
  },

  cut_root: {
    kind: 'Cut · not defended',
    title: 'Root on the host (A5)',
    badges: [['tag-warn', 'reaches the centre'], ['tag-warn', 'deliberate']],
    lead: 'No outer ring. A wedge that ignores every ring and lands in the centre — and the only honest way to draw it.',
    sections: [
      { h: 'What holds here', items: [
        'Whoever is root reads the master key where the seal holds it — the mounted file for <code>type = "static_file"</code>, the environment for the variable form — and reads it out of process memory in any case.',
        '<strong>This is the consequence of unattended startup (ADR-5), so an availability decision rather than a cryptographic one.</strong> The same holds for OpenBao with a static seal. The key sits in the same mode-0600 file as other signing secrets: no regression against the status quo and no gain either.',
        'Moving the boundary requires split-key unsealing or a hardware module. <strong>Both are retrofittable without a format change</strong>, because the master key wraps exactly one record.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/adr/0005-seal-static-key-from-environment.md', 'ADR-5'), src('docs/operations/master-key.md')],
    covered: false
  },

  cut_supply: {
    kind: 'Cut · substrate',
    title: 'The build pipeline',
    badges: [['tag-warn', 'replaces the onion'], ['tag-warn', 'not application code']],
    lead: 'Whoever replaces the image wins. This cut crosses no ring — it is the surface all the rings lie on.',
    sections: [
      { h: 'What stands against it', items: [
        'Supply-chain hygiene rather than application code: pinned dependencies, <code>cargo-deny</code> and <code>cargo audit</code> as blocking gates, action hashes instead of action tags, base images by digest instead of by tag.'
      ]},
      { h: 'And the point at which that changes', items: [
        '<strong>Reproducible builds are named and not implemented.</strong> While the repository is private, nobody outside can fetch the source, rebuild the image and compare — reproducibility would be a property nobody can check.',
        '<strong>It buys something the moment the repository becomes public.</strong> That is the point at which this paragraph has to change, and the <code>apt-get install</code> in the runtime stage of the <code>Dockerfile</code> is the first thing that has to go for it.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('Dockerfile'), src('AGENTS.md')],
    covered: false
  },

  cut_dos: {
    kind: 'Cut · the availability axis',
    title: 'Fail-closed: the full audit volume',
    badges: [['tag-warn', 'no radius'], ['tag-plain', 'intended']],
    lead: 'Not a ring but an axis: a full volume is a total outage and not a logging gap. That is intended — and the reason the fill level is a monitored metric rather than a footnote.',
    sections: [
      { h: 'What bounds it', items: [
        '<strong>If ciphr is unavailable, running services keep running</strong> — their configuration is already on their hosts. Only new deploys are blocked. That is precisely what makes a single instance defensible.',
        '<strong>That changes</strong> as soon as services fetch their secrets at startup instead of having them rendered into files: a restart during an outage then fails. Running containers are untouched. This is the deliberate counterweight to the security gain, and it should be understood before the pattern is adopted rather than after.',
        'Together with ring 1: the fill level can be driven by an unauthenticated neighbour, so the <em>rate</em> of growth is the metric that arrives early enough.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/operations/audit-trail.md')],
    covered: false
  },

  /* ── Clients ──────────────────────────────────────────────────────────── */

  ci: {
    kind: 'Client · sector',
    title: 'CI runner (A3)',
    badges: [['tag-plain', 'built']],
    lead: 'The primary consumer — the name contains <em>CI</em>. A runner holds a valid deploy token; the question is not whether it has one but what it reaches with it.',
    sections: [
      { h: 'What holds the boundary', items: [
        'The policy bounds it to that runner\'s paths, and every access is audited.',
        '<strong>Detection is optional and off:</strong> <code>honeypot_alert</code> turns reading bait into a signal that needs no interpretation. It catches enumeration and a credential tried everywhere — <em>not</em> a runner that only reads what it came for. That is what the audit trail is for.',
        '<strong>A secret that has left ciphr is the pipeline\'s problem.</strong> No forge masks a value fetched at runtime, only its own secrets. A bare <code>curl | jq</code> puts secrets into the job log the moment somebody adds <code>set -x</code> — and that log is usually readable by more people than the secret store is. So masking is part of the product: the CI-side fetch emits <code>::add-mask::</code> for every value before it emits anything else (ADR-25).'
      ]}
    ],
    sources: [src('docs/operations/ci.md'), src('docs/threat-model.md'), src('docs/operations/honeypots.md')],
    covered: false
  },

  host: {
    kind: 'Client · sector',
    title: 'Host script',
    badges: [['tag-plain', 'built']],
    lead: 'HTTPS plus a bearer token, so the minimal client is <code>curl</code>. No agent, no plugin, no forge integration required.',
    sections: [
      { h: 'The two rules that shape every command', items: [
        '<strong>A value passed as an argument is readable by every process on the host</strong> while the command runs — and it lands in the shell history.',
        'So the CLI takes values from standard input or from a file, and so the honest end state is <strong>one secret per host</strong> rather than none: plus an audit trail, rotation, and a bounded radius per token. That is an excellent trade and should not be described as "no more secrets on the host".'
      ]}
    ],
    sources: [src('docs/operations/cli.md'), src('docs/threat-model.md')],
    covered: false
  },

  cli: {
    kind: 'Client · sector',
    title: 'ciphr — the CLI',
    badges: [['tag-plain', 'built']],
    lead: 'The host tool. It reads the audit trail, the identities and the policies <strong>directly from the store, without a network hop</strong> — which is why turning <code>viewer_api</code> off costs exactly the viewer and nothing else.',
    sections: [
      { h: 'What only happens here', items: [
        'Everything that writes: setting secrets, issuing and revoking tokens, rotating the master key, <code>audit verify</code>, <code>audit anchor</code>, <code>audit cut</code>, <code>surface show</code>.',
        '<strong>Taking a value somewhere is the CLI\'s job</strong> — not the viewer\'s. Which is why the viewer has no copy button.',
        '<code>ciphr surface show</code> reads a <em>file</em>, not a binary: for a build entry it reports what the deployment asked for, not what it got. Nothing on the host sees the service\'s build — <code>GET /v1/health</code> is there for that. The command states that reservation itself.'
      ]}
    ],
    sources: [src('docs/operations/cli.md'), src('docs/adr/0020-optional-surface.md', 'ADR-20')],
    covered: false
  },

  sdk: {
    kind: 'Client · sector',
    title: 'ciphr-sdk',
    badges: [['tag-plain', 'built']],
    lead: 'For a service that fetches its own secrets. Blocking, over <code>ureq</code> (ADR-19): the call is one fetch at startup, and an async runtime in every consuming application would be a price with nothing behind it.',
    sections: [
      { h: 'What hangs on it', items: [
        'Without <code>bulk_export</code> the SDK keeps working — one request per path instead of one for all. Same coverage, same number of audit entries, more round trips.',
        '<strong>The price of this pattern is on the availability axis:</strong> if a service fetches its secrets at startup, a restart during a ciphr outage fails. Running containers are untouched.'
      ]}
    ],
    sources: [src('docs/adr/0019-sdk-transport-blocking-ureq.md', 'ADR-19'), src('docs/threat-model.md')],
    covered: false
  },

  run: {
    kind: 'Client · sector',
    title: 'ciphr-run',
    badges: [['tag-plain', 'built']],
    lead: 'The wrapper for an image that only understands environment variables: it fetches the values and injects them into a child process (ADR-14).',
    sections: [
      { h: 'What hangs on it', items: [
        '<strong>It no longer needs <code>bulk_export</code> (since 2026-08-24).</strong> Both <code>--prefix</code> and <code>--path</code> used to read exclusively through <code>POST /v1/export</code>, so a deployment that had named no entry had a wrapper that refused with exit code 125 rather than starting a service without its secrets. The client falls back to one request per path now; naming the entry buys one request instead of one per path, at container start, and nothing else.',
        'One rule for the variable name (ADR-18) — exactly one, so that the same path yields the same name everywhere.'
      ]}
    ],
    sources: [src('docs/operations/wrapper.md'), src('docs/adr/0014-ciphr-run-injects-into-a-child-process.md', 'ADR-14'), src('docs/adr/0018-one-rule-for-the-variable-name.md', 'ADR-18')],
    covered: false
  },

  viewer: {
    kind: 'Client · sector',
    title: 'The viewer',
    badges: [['tag-plain', 'built, its own image'], ['tag-runtime', 'needs viewer_api']],
    lead: 'A peer, not a breach. It crosses the same boundary the CLI crosses — HTTPS, token, policy — and holds neither key material nor database access nor an identity of its own. That is what keeps "exactly one process holds plaintext" true.',
    sections: [
      { h: 'What it cannot do', items: [
        '<strong>It cannot write.</strong> No secret, no policy, no identity, no token. That is not a stopgap: a policy write API would be the most dangerous API this project could have (ADR-3), and doing without it keeps the radius of an XSS finding at "reads what the signed-in human may read anyway".',
        '<strong>It is not part of the service.</strong> Its own container with static files (ADR-11). The server has no <code>serve-ui</code> mode, no embedded assets, no template engine — so a bug in asset handling cannot be a bug in the process that holds plaintext.',
        '<strong>It has no private door.</strong> ADR-11\'s follow-on rule: documented v1 endpoints only. An endpoint that exists for the viewer alone would mean the CLI cannot do something the viewer can.'
      ]},
      { h: 'Its own cadence', items: [
        'Its own version numbers, its own release (<code>ui-v*</code>). An npm advisory or a layout fix must not force a new server image — and therefore no restart of the service whose restart demands the most care.'
      ]}
    ],
    sources: [src('docs/ui.md'), src('docs/adr/0011-ui-is-an-optional-separate-package.md', 'ADR-11')],
    covered: false
  },

  browser: {
    kind: 'Outer zone · through the viewer',
    title: 'The browser tab (A7)',
    badges: [['tag-warn', 'a second place with plaintext']],
    lead: 'This is what the viewer really adds — not a breach inwards but <strong>a new zone further out</strong>: a place outside the process where plaintext exists. A DOM, a cache, a screen. That is precisely the cost side.',
    sections: [
      { h: 'This zone\'s own gates', items: [
        '<strong>Reveal is one value, one action.</strong> A single <code>revealed</code> ref; a second reveal replaces the first. There is no bulk form in the viewer, although <code>/v1/export</code> exists.',
        '<strong>Plaintext leaves the state when the view is left.</strong> Views are switched with <code>v-if</code>, so leaving destroys the component, and <code>onUnmounted</code> clears the value as well. Nothing writes a value into a URL, into <code>localStorage</code> or into global state.',
        '<strong>No copy button.</strong> Deliberately: the clipboard is a place where a value outlives the tab, the session and the reader\'s attention, with no expiry date.',
        '<strong>No service worker, no offline cache.</strong> None is registered, <code>main.ts</code> refuses to mount while one from an earlier deployment controls the page, and the container refuses to serve one. A cached response to a secret read is a secret without an expiry date.',
        '<strong>A strict CSP</strong> — <code>default-src \'none\'</code>, no <code>unsafe-inline</code>, no <code>unsafe-eval</code> — defined once, sent as a header <em>and</em> injected into the built document, so that a bundle served elsewhere keeps it. No <code>v-html</code>, no <code>innerHTML</code>, checked by a blocking gate.',
        '<strong>The token in <code>sessionStorage</code>, no cookie.</strong> That removes the whole CSRF class rather than mitigating it, and a token does not survive closing the tab — which on a shared workstation is the difference between a session and a permanent secret.',
        '<strong>One runtime dependency</strong> (<code>vue</code>), with a ceiling for the whole tree, no install scripts, every package with an integrity hash — its own budget, checked as a blocking gate.'
      ]},
      { h: 'Not covered', items: [
        'The review of 2026-08-21 did not read <code>ui/</code>. The security properties above are implemented and documented, but unchecked from outside.'
      ]}
    ],
    sources: [src('docs/ui.md'), src('ci/check-ui-budget.sh'), src('docs/security-review.md')],
    covered: false
  },

  mcp: {
    kind: 'Client · sector',
    title: 'MCP server (A8)',
    badges: [['tag-plain', 'not built'], ['tag-plain', 'post-v1']],
    lead: 'Designed, not built. The line in the threat model is a design commitment rather than a description — which is why it is drawn as absent here.',
    sections: [
      { h: 'What is decided before it exists', items: [
        'A separate, stateless process (ADR-13), without key material, without database access, without an identity of its own.',
        'The real adversary is not the client but the path afterwards: <strong>answers flow into model context and provider logs</strong>. Hence metadata by default, plaintext only through an opt-in capability on narrow paths, and MCP context marked in the audit trail.'
      ]}
    ],
    sources: [src('docs/adr/0013-mcp-separate-stateless-process.md', 'ADR-13'), src('docs/threat-model.md')],
    covered: false, absent: true
  },

  report: {
    kind: 'Client · sector',
    title: 'Anonymous reporter (A9)',
    badges: [['tag-plain', 'deferred']],
    lead: '<code>POST /v1/report</code> — the only anonymous request path this design would ever have. ADR-16 is deferred: it is worth its price only where somebody without a token can reach it.',
    sections: [
      { h: 'Why the line stays although nothing exists', items: [
        '<strong>Because the record stays.</strong> What defends this path was decided before anybody built it, and a deferral is no reason to lose that.',
        'What is decided: an identical answer for a hit and a miss, so the endpoint is not an oracle; size and rate limits <em>before</em> the audit write and before the store lock; one monotonic metadata write per version hit, which nothing that makes a decision reads; and no path to a tripwire tier above <code>alert</code>.',
        'While it is missing: <strong>no unauthenticated endpoint except <code>/v1/health</code></strong> — and that sentence is by now expected to stay true rather than to expire.'
      ]}
    ],
    sources: [src('docs/adr/0016-leak-reports-are-a-one-way-drop-box.md', 'ADR-16'), src('docs/threat-model.md')],
    covered: false, absent: true
  }
};

/* ── Surface entries ────────────────────────────────────────────────────── */

const ENTRIES = [
  {
    id: 'viewer_api', kind: 'runtime', ring: 'surface', angle: 128, span: 12,
    chip: '+3 routes',
    routes: ['GET /v1/audit', 'GET /v1/identities', 'GET /v1/policies'],
    activates: ['viewer', 'browser'],
    title: 'viewer_api',
    lead: 'The three routes that exist for a component which is itself already optional (ADR-11).',
    cost: 'The viewer stops working. The CLI does not: it reads the audit trail, the identities and the policies directly from the store, without a network hop. So a deployment without the viewer was serving these three routes to nobody — and putting the policy structure and the identity inventory on the network for anyone holding any token.',
    extra: [
      'Coverage: the review of 2026-08-21 did not read these handlers; it did read the authorization they use.'
    ]
  },
  {
    id: 'bulk_export', kind: 'runtime', ring: 'surface', angle: 104, span: 12,
    chip: '+1 route',
    routes: ['POST /v1/export'],
    activates: [],
    title: 'bulk_export',
    lead: 'Several named paths in one call, one audit entry per secret.',
    cost: 'One request per path instead of one for all of them, at container start. <strong>Since 2026-08-24 that is the whole cost</strong> (ADR-25): clients read through this route where it exists and fall back to <code>GET /v1/secrets/{path}</code> where it does not, so route B and route C both work on a deployment that named no entry at all. The audit trail does not notice — this route writes one entry per secret served, never one per call.',
    extra: [
      '<strong>It was not always the whole cost.</strong> Until that date <code>ciphr-run</code> could not fetch at all without this entry and refused with exit code 125, which meant a deployment that had made no decision had a broken route B and a <code>404</code> to explain it.',
      '<strong>Correction in v0.5.1:</strong> the cost sentence used to claim that switching this off removes fetched prefixes and so makes placing bait easier. It does not. <code>POST /v1/export</code> reads the paths a caller <em>names</em>; whether a prefix is covered is a property of the fetching code. Somebody who lists <code>GET /v1/list/{prefix}</code> — not an entry — and then reads each path covers the same prefix with this route off.'
    ]
  },
  {
    id: 'token_status', kind: 'runtime', ring: 'surface', angle: 80, span: 12,
    chip: '+1 route',
    routes: ['GET /v1/tokens'],
    activates: [],
    title: 'token_status',
    lead: 'The credential inventory, answered to an authenticated caller: identifiers, identities, expiry, last use and state. Never a verifier and never a token.',
    cost: 'The inventory is answerable only on the host. <code>ciphr token list</code> reads it read-only while the service runs (ADR-22), so nothing becomes unanswerable — what is missing is the <em>authenticated</em> answer, where the caller is a token identity and the read lands in the trail rather than as <code>cli:$USER</code> in the shell history of whoever ran it.',
    extra: [
      '<strong>Its own entry rather than part of <code>viewer_api</code>, because the cost is its own.</strong> Which credentials exist, and which have never been used, is a good list of the ones nobody would notice being used.',
      'Authorized as <code>inspect</code> on <code>sys/tokens</code> — a control-plane capability, not a secret one (ADR-23). A rule that still says <code>read</code> under that prefix is refused when the policy file loads.',
      'The question it answers is the one an incident asks first: is this credential still valid, when does it expire, when was it last used. The host half of that was closed by ADR-22; this is the half where the trail can name who asked.'
    ],
    sources: [
      src('docs/adr/0022-the-trail-records-what-consumed-an-authority.md', 'ADR-22'),
      src('docs/adr/0023-the-control-plane-is-its-own-capability.md', 'ADR-23'),
      src('docs/operations/cli.md'),
      src('openapi.yaml')
    ]
  },
  {
    id: 'token_revoke', kind: 'runtime', ring: 'surface', angle: 56, span: 12,
    chip: '+1 route · the only write',
    routes: ['POST /v1/tokens/{token_id}/revoke'],
    activates: [],
    title: 'token_revoke',
    lead: 'The single write this API may do (ADR-24), and the only one in the document that is not about a secret: revoking one leaked credential without an outage.',
    cost: 'Revoking means stopping the service. <code>ciphr token revoke</code> opens a session and takes the store lock the running server holds, so the only route is stop, revoke, start — taking down every consumer in order to invalidate one token, at the one moment that cannot be scheduled. <code>docs/operations/honeypots.md</code> fires exactly then.',
    extra: [
      'On, it is one token per request, authorized as <code>revoke</code> on <code>sys/tokens</code>, with no master key in reach. <strong>Issuing stays on the host either way</strong> — that one is routine, and a planned window is a defensible answer for it.',
      '<strong>A named exception to ADR-3, not a repeal of it.</strong> Administration comes from configuration under version control; this is the one operation that cannot wait for a commit and a restart.',
      '<strong>Turning it on costs the outage once, and that belongs in the runbook before the incident.</strong> The revoking identity needs a token, and issuing one needs the service stopped — so a deployment that names this entry during an incident pays exactly the outage it was trying to avoid.'
    ],
    sources: [
      src('docs/adr/0024-revocation-is-the-one-write-the-api-may-do.md', 'ADR-24'),
      src('docs/adr/0003-policies-from-configuration.md', 'ADR-3'),
      src('docs/operations/honeypots.md'),
      src('openapi.yaml')
    ]
  },
  {
    id: 'honeypot_alert', kind: 'build', ring: 'auth', angle: 45, span: 14,
    chip: '+1 route, +2 audit actions',
    routes: ['GET /v1/honeypots'],
    activates: [],
    title: 'honeypot_alert',
    lead: 'Bait that no legitimate consumer touches turns a read into a signal. The <code>alert</code> tier only; the severe tiers are designed and deliberately not built.',
    cost: 'No detection of bait. A deployment that plants none pays nothing for the absence and gets the strongest form of ADR-15\'s indistinguishability claim: code that is not compiled in has no timing that could be wrong. With the entry the weaker form applies — see below.',
    extra: [
      '<strong>A build entry, and therefore absent from the default build.</strong> That is exactly why its arc sits on the auth ring: it adds code on the authentication path — bait recognition in the token verification of <code>ciphr-store</code>, a tier lookup and a latch in <code>ciphr-server</code>.',
      '<strong>Newer than the accepted review.</strong> Claims C11, C12 and D10 describe it and are marked as not covered. Turning it on is a decision about accepting unreviewed code on the authentication path.',
      '<strong>Indistinguishable in the <em>response</em>, not in the work</strong> (narrowed on 2026-08-22, claim C11). Status, body and headers are identical and tested. What is not equalized: a malformed token returns before any database work, a known identifier costs one verifier query more, and recognized bait writes a larger audit entry before the <code>401</code>. Somebody holding a credential whose secret matches can separate <em>bait</em> from <em>expired</em> by that — precisely the question an attacker asks. Whether it stays measurable over a network is unmeasured; what bounds enumeration is the 48-bit identifier.',
      'An alarm nobody polls is not an alarm: the signal is a field on <code>/v1/health</code> and an entry in the trail. Nothing here can wake a human.',
      'Bait under a prefix that something fetches goes off again in week two — a prefix fetch reads every path under it.'
    ],
    build: [
      '<strong>No published artefact contains it.</strong> The <code>Dockerfile</code> and both release workflows build without <code>--features</code>, so no released image and no released binary. There is <em>no</em> second image, and that is the decision: a feature image would be a second artefact with the same version, and a checksum that does not say which one you hold.',
      'Whoever wants it builds it: <code>cargo build --release --locked --features honeypot_alert --bin ciphr-server</code>. For a container the same in a <strong>derived image</strong> — copy the <code>Dockerfile</code>, add the flag to the <code>cargo build</code> line, publish under your own tag.',
      '<strong>Build and configuration then have to match, and the service enforces it:</strong> it does not start if the feature is compiled in and the stanza is missing — nor if the stanza is there and the feature is not. The second refusal is the important one: without it a deployment could believe it has detection, have written down when and why, and have none. Bait that cannot fire looks exactly like bait nobody took. <code>ciphr-server --check-config</code> checks the pair beforehand.',
      '<strong>Making this build is a decision to run unreviewed code</strong> — and the reason the default artefact stays the default. Not doing it costs nothing but bait nobody can recognize; a deployment that plants none loses nothing at all.'
    ],
    sources: [
      src('docs/operations/honeypots.md'),
      src('docs/adr/0015-honeypots-and-what-a-tripwire-may-do.md', 'ADR-15'),
      src('docs/adr/0020-optional-surface.md', 'ADR-20'),
      src('Dockerfile')
    ]
  }
];

const P4 = [
  'The audit device requirement', 'The fail-closed ordering — the record stored before the response is produced',
  'Deny by default', 'TLS at the listener', 'The envelope scheme and its AAD binding',
  'The one path normalization', 'Constant-time comparison of credentials'
];

/* ── Clients and lateral gates ──────────────────────────────────────────── */

const CLIENTS = [
  { id: 'report',  angle: 172, label: 'POST /v1/report', sub: 'A9 — deferred',        state: 'absent' },
  { id: 'mcp',     angle: 149, label: 'ciphr-mcp',       sub: 'A8 — not built',       state: 'absent' },
  { id: 'viewer',  angle: 128, label: 'ciphr-ui',        sub: 'viewer, its own image', state: 'entry' },
  { id: 'run',     angle: 104, label: 'ciphr-run',       sub: 'wrapper, route B',     state: 'on' },
  { id: 'sdk',     angle: 79,  label: 'ciphr-sdk',       sub: 'a service fetches its own', state: 'on' },
  { id: 'cli',     angle: 56,  label: 'ciphr',           sub: 'the CLI on the host',  state: 'on' },
  { id: 'host',    angle: 33,  label: 'curl',            sub: 'host script',          state: 'on' },
  { id: 'ci',      angle: 10,  label: 'CI runner',       sub: 'A3 — holds a token',   state: 'on' }
];

const LATERALS = [
  { id: 'store', angle: 215, label: 'SQLite', sub: 'ciphertext only, AAD-bound' },
  { id: 'audit', angle: 320, label: 'Audit devices', sub: 'append-only, hash chain' }
];

/* ── State ──────────────────────────────────────────────────────────────── */

const state = {
  entries: {
    viewer_api: false,
    bulk_export: false,
    token_status: false,
    token_revoke: false,
    honeypot_alert: false
  },
  lensP4: false,
  lensReview: false,
  lensCuts: true,
  active: null
};

/* ── SVG-Helfer ─────────────────────────────────────────────────────────── */

const svg = document.getElementById('canvas');

function el(name, attrs, parent) {
  const node = document.createElementNS(SVGNS, name);
  for (const k in attrs) node.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(node);
  return node;
}

function text(parent, x, y, cls, content, anchor) {
  const t = el('text', { x: x, y: y, class: cls }, parent);
  if (anchor) t.setAttribute('text-anchor', anchor);
  t.textContent = content;
  return t;
}

/* One ring segment as a path, for arcs and wedges. */
function arcPath(r, from, to) {
  const [x1, y1] = pol(r, from);
  const [x2, y2] = pol(r, to);
  const large = Math.abs(to - from) > 180 ? 1 : 0;
  const sweep = from > to ? 1 : 0;
  return 'M ' + x1 + ' ' + y1 + ' A ' + r + ' ' + r + ' 0 ' + large + ' ' + sweep + ' ' + x2 + ' ' + y2;
}

function wedgePath(rInner, rOuter, from, to) {
  const [ax, ay] = pol(rOuter, from);
  const [bx, by] = pol(rOuter, to);
  const [cx, cy] = pol(rInner, to);
  const [dx, dy] = pol(rInner, from);
  const large = Math.abs(to - from) > 180 ? 1 : 0;
  const sweep = from > to ? 1 : 0;
  let p = 'M ' + ax + ' ' + ay + ' A ' + rOuter + ' ' + rOuter + ' 0 ' + large + ' ' + sweep + ' ' + bx + ' ' + by;
  p += ' L ' + cx + ' ' + cy;
  if (rInner > 0) p += ' A ' + rInner + ' ' + rInner + ' 0 ' + large + ' ' + (1 - sweep) + ' ' + dx + ' ' + dy;
  return p + ' Z';
}

/* A clickable node, with focus and keyboard operation. */
function node(id, parent) {
  const g = el('g', { class: 'node', tabindex: '0', role: 'button', 'data-id': id }, parent);
  const info = CONTENT[id];
  if (info) g.setAttribute('aria-label', info.title);
  g.addEventListener('click', (e) => { e.stopPropagation(); select(id); });
  g.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(id); }
  });
  return g;
}

/* ── Building the diagram ──────────────────────────────────────────────────── */

const layers = {};

function build() {
  svg.textContent = '';
  const defs = el('defs', {}, svg);
  const marker = el('marker', {
    id: 'arrow', viewBox: '0 0 10 10', refX: '9', refY: '5',
    markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse'
  }, defs);
  el('path', { d: 'M 0 1 L 9 5 L 0 9 z', fill: 'var(--gate)' }, marker);
  const markerCut = el('marker', {
    id: 'arrow-cut', viewBox: '0 0 10 10', refX: '9', refY: '5',
    markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse'
  }, defs);
  el('path', { d: 'M 0 1 L 9 5 L 0 9 z', fill: 'var(--cut)' }, markerCut);

  layers.substrate = el('g', {}, svg);
  layers.cuts = el('g', {}, svg);
  layers.band = el('g', {}, svg);
  layers.rings = el('g', {}, svg);
  layers.arcs = el('g', {}, svg);
  layers.lateral = el('g', {}, svg);
  layers.clients = el('g', {}, svg);
  layers.asset = el('g', {}, svg);
  layers.labels = el('g', {}, svg);

  buildSubstrate();
  buildCuts();
  buildBand();
  buildRings();
  buildLaterals();
  buildClients();
  buildAsset();
  buildRingLabels();
}

function buildSubstrate() {
  const g = node('cut_supply', layers.substrate);
  el('rect', {
    x: -790, y: -720, width: 1580, height: 1300, rx: 26, class: 'substrate'
  }, g);
  el('rect', { x: -790, y: -720, width: 1580, height: 1300, rx: 26, class: 'hit' }, g);
  text(g, -770, 552, 'cut-label', 'Substrate: the build pipeline — whoever replaces the image wins');
  text(g, -770, 572, 'ring-sub', 'Crosses no ring. Reproducible builds: named, not implemented — and checkable only once the repository is public.');
}

function buildCuts() {
  /* A5: a wedge from the outside all the way into the centre. */
  const g = node('cut_root', layers.cuts);
  el('path', { d: wedgePath(0, 470, 263, 277), class: 'cut-area' }, g);
  el('path', { d: wedgePath(0, 470, 263, 277), class: 'hit', 'stroke-width': '10' }, g);
  const [tipA, tipB] = pol(206, 270);
  const [tipC, tipD] = pol(118, 270);
  const tip = el('path', {
    d: 'M ' + tipA + ' ' + tipB + ' L ' + tipC + ' ' + tipD,
    stroke: 'var(--cut)', 'stroke-width': '1.8', fill: 'none'
  }, g);
  tip.setAttribute('marker-end', 'url(#arrow-cut)');
  const [lx, ly] = pol(492, 270);
  text(g, lx, ly + 4, 'cut-label', 'root on the host (A5) — not defended', 'middle');
  text(g, lx, ly + 22, 'ring-sub', 'reads the master key where the seal holds it, and out of process memory', 'middle');

  /* The availability axis: it hangs off the audit gate, but it is not a radius. */
  const d = node('cut_dos', layers.cuts);
  el('rect', { x: 470, y: 392, width: 250, height: 54, rx: 3, class: 'cut-area' }, d);
  el('rect', { x: 470, y: 392, width: 250, height: 54, rx: 3, class: 'hit', 'stroke-width': '6' }, d);
  text(d, 482, 414, 'cut-label', 'fail-closed: a full volume');
  text(d, 482, 432, 'ring-sub', 'a total outage, not a logging gap — intended');
}

function buildBand() {
  const g = node('band', layers.band);
  el('path', { d: wedgePath(0, BAND.rOuter, BAND.from, BAND.to), class: 'band-area' }, g);
  el('path', { d: wedgePath(0, BAND.rOuter, BAND.from, BAND.to), class: 'hit', 'stroke-width': '8' }, g);
  const mid = (BAND.from + BAND.to) / 2;
  const [ax, ay] = pol(BAND.rOuter, mid);
  const [lx, ly] = pol(452, mid);
  el('path', { d: 'M ' + ax + ' ' + ay + ' L ' + lx + ' ' + ly, class: 'leader' }, g);
  text(g, lx - 8, ly - 4, 'band-label', 'reviewed core', 'end');
  text(g, lx - 8, ly + 13, 'ring-sub', '~1500 lines, one shape in every build', 'end');
  text(g, lx - 8, ly + 29, 'ring-sub', 'ciphr-crypto, ciphr-policy, path/pattern/secret', 'end');
}

function buildRings() {
  RINGS.forEach((ring) => {
    const g = node(ring.id, layers.rings);
    el('circle', { cx: 0, cy: 0, r: ring.r, class: 'ring-line ' + ring.cls }, g);
    el('circle', { cx: 0, cy: 0, r: ring.r, class: 'hit' }, g);
    if (state.lensP4 && CONTENT[ring.id] && CONTENT[ring.id].p4) {
      el('circle', { cx: 0, cy: 0, r: ring.r, class: 'p4-mark' }, g);
    }
  });

  /* Switchable arcs sit on the ring they add something to. */
  ENTRIES.forEach((entry) => {
    const ring = RINGS.find((r) => r.id === entry.ring);
    const on = state.entries[entry.id];
    const g = node('entry:' + entry.id, layers.arcs);
    const p = el('path', {
      d: arcPath(ring.r, entry.angle + entry.span, entry.angle - entry.span),
      fill: 'none',
      stroke: on ? 'var(--switch)' : 'var(--absent)',
      'stroke-width': on ? 7 : 4,
      'stroke-linecap': 'butt',
      'stroke-dasharray': on ? '' : '2 5'
    }, g);
    p.setAttribute('opacity', on ? '0.9' : '0.65');
    el('path', { d: arcPath(ring.r, entry.angle + entry.span, entry.angle - entry.span), class: 'hit' }, g);

    const [cx, cy] = pol(ring.r - 30, entry.angle);
    const t = text(g, cx, cy, 'chip-text', entry.id + (on ? ' · ' + entry.chip : ' · off'), 'middle');
    t.setAttribute('fill', on ? 'var(--switch)' : 'var(--absent)');
    const k = text(g, cx, cy + 14, 'ring-sub', entry.kind === 'build'
      ? (on ? 'in the binary' : 'not in the binary')
      : (on ? 'route registered' : 'route not registered'), 'middle');
    k.setAttribute('fill', on ? 'var(--switch)' : 'var(--absent)');
  });
}

function buildLaterals() {
  LATERALS.forEach((lat) => {
    const g = node(lat.id, layers.lateral);
    const [ax, ay] = pol(R_ASSET + 6, lat.angle);
    const [bx, by] = pol(468, lat.angle);
    const line = el('path', { d: 'M ' + ax + ' ' + ay + ' L ' + bx + ' ' + by, class: 'lateral-arrow' }, g);
    line.setAttribute('marker-end', 'url(#arrow)');
    const [px, py] = pol(500, lat.angle);
    const w = 216;
    const bx0 = px < 0 ? px - w + 40 : px - 40;
    el('rect', { x: bx0, y: py - 8, width: w, height: 56, rx: 3, class: 'lateral-box' }, g);
    el('rect', { x: bx0, y: py - 8, width: w, height: 56, rx: 3, class: 'hit', 'stroke-width': '6' }, g);
    text(g, bx0 + 12, py + 14, 'lateral-label', lat.label);
    text(g, bx0 + 12, py + 33, 'lateral-sub', lat.sub);
  });
}

function buildClients() {
  CLIENTS.forEach((c) => {
    let cls = 'node';
    let on = c.state === 'on';
    if (c.state === 'absent') { cls += ' is-absent'; on = false; }
    if (c.state === 'entry') {
      on = ENTRIES.some((e) => state.entries[e.id] && e.activates.indexOf(c.id) >= 0);
      if (!on) cls += ' is-inactive';
    }

    const g = node(c.id, layers.clients);
    g.setAttribute('class', cls);

    const [sx, sy] = pol(432, c.angle);
    const [ex, ey] = pol(478, c.angle);
    el('path', { d: 'M ' + sx + ' ' + sy + ' L ' + ex + ' ' + ey, class: 'spoke' }, g);

    const [px, py] = pol(482, c.angle);
    const w = 186, h = 50;
    const bx = px < 0 ? px - w : px;
    const by = py - h / 2;
    el('rect', { x: bx, y: by, width: w, height: h, rx: 3, class: 'client-box' }, g);
    el('rect', { x: bx, y: by, width: w, height: h, rx: 3, class: 'hit', 'stroke-width': '6' }, g);
    text(g, bx + 12, by + 21, 'client-label', c.label);
    text(g, bx + 12, by + 38, 'client-sub', c.sub);

    /* The viewer drags an outer zone of its own along with it. */
    if (c.id === 'viewer') {
      const b = node('browser', layers.clients);
      b.setAttribute('class', on ? 'node' : 'node is-inactive');
      const [qx, qy] = pol(560, c.angle);
      const [rx, ry] = pol(614, c.angle);
      el('path', { d: 'M ' + qx + ' ' + qy + ' L ' + rx + ' ' + ry, class: 'spoke' }, b);
      const [tx, ty] = pol(620, c.angle);
      const bw = 214, bh = 52;
      const bbx = tx - bw, bby = ty - bh / 2;
      el('rect', { x: bbx, y: bby, width: bw, height: bh, rx: 3, class: 'client-box' }, b);
      el('rect', { x: bbx, y: bby, width: bw, height: bh, rx: 3, class: 'hit', 'stroke-width': '6' }, b);
      text(b, bbx + 12, bby + 21, 'client-label', 'Browser tab (A7)');
      text(b, bbx + 12, bby + 38, 'client-sub', 'a second place with plaintext');
    }
  });

  /* One sentence that clears up the most common misreading. */
  const [lx, ly] = pol(700, 90);
  text(layers.clients, lx, ly, 'ring-sub', 'Everything out here is a peer on one boundary: HTTPS, token, policy. None of them breaches a ring for another.', 'middle');
}

function buildAsset() {
  const g = node('asset', layers.asset);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, fill: 'var(--bg-sunk)' }, g);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, class: 'asset-disc' }, g);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, class: 'hit', 'stroke-width': '10' }, g);
  text(g, 0, -12, 'asset-label', 'Plaintext');
  text(g, 0, 6, 'asset-label', '+ key material');
  text(g, 0, 28, 'asset-sub', 'exactly one process');
}

function buildRingLabels() {
  const colX = 470;
  RINGS.forEach((ring, i) => {
    const y = -20 + i * 40;
    const angle = -2 - i * 4;
    const [px, py] = pol(ring.r, angle);
    const g = node(ring.id, layers.labels);
    el('path', {
      d: 'M ' + px + ' ' + py + ' L ' + (colX - 12) + ' ' + y,
      class: 'leader'
    }, g);
    const info = LABELS[ring.id];
    text(g, colX, y - 2, 'ring-label', (i + 1) + '. ' + info[0]);
    text(g, colX, y + 15, 'ring-sub', info[1]);
    el('rect', { x: colX - 6, y: y - 18, width: 320, height: 40, class: 'hit', 'stroke-width': '2' }, g);
  });
  text(layers.labels, colX, 196, 'ring-sub', 'in the order in which a request crosses them');
}

const LABELS = {
  reach:   ['Reachability', 'a property of the deployment, not code'],
  tls:     ['TLS ends here', 'ADR-8, certificate ADR-17'],
  surface: ['Surface: registered?', 'ADR-20 — the only switchable ring'],
  auth:    ['Authentication', 'token, constant time, no anonymous endpoint'],
  authz:   ['Authorization', 'deny by default, one normalization']
};

/* ── Panel ──────────────────────────────────────────────────────────────── */

const panelEmpty = document.getElementById('panel-empty');
const panelBody = document.getElementById('panel-body');

function badge(cls, label) {
  return '<span class="tag ' + cls + '">' + label + '</span>';
}

function renderEntry(entry) {
  const on = state.entries[entry.id];
  let html = '<button type="button" class="panel-close" id="panel-close">close</button>';
  html += '<p class="panel-kind">Surface entry · ' + entry.kind + '</p>';
  html += '<h2><code>' + entry.id + '</code></h2>';
  html += '<p class="panel-badges">' +
    badge(entry.kind === 'build' ? 'tag-build' : 'tag-runtime', entry.kind) +
    badge(on ? 'tag-switch' : 'tag-plain', on ? 'on' : 'off (default)') +
    (entry.id === 'honeypot_alert' ? badge('tag-warn', 'not covered by the review') : '') +
    '</p>';
  html += '<p class="lead">' + entry.lead + '</p>';
  html += '<h3>What switching it off costs</h3><blockquote>' + entry.cost + '</blockquote>';
  html += '<h3>Routes</h3><ul>' + entry.routes.map((r) => '<li><code>' + r + '</code></li>').join('') + '</ul>';
  if (entry.extra && entry.extra.length) {
    html += '<h3>Also</h3><ul>' + entry.extra.map((x) => '<li>' + x + '</li>').join('') + '</ul>';
  }
  if (entry.build && entry.build.length) {
    html += '<h3>Where a build with the feature comes from</h3><ul>' +
      entry.build.map((x) => '<li>' + x + '</li>').join('') + '</ul>';
  }
  const sources = entry.sources || [
    src('docs/adr/0020-optional-surface.md', 'ADR-20'),
    src('crates/ciphr-cli/src/main.rs', 'crates/ciphr-cli/src/main.rs — KNOWN'),
    src('openapi.yaml')
  ];
  html += '<h3>Sources</h3><ul class="panel-sources">' +
    sources.map((s) => '<li><a href="' + s.href + '">' + s.label + '</a></li>').join('') + '</ul>';
  return html;
}

function renderContent(info) {
  let html = '<button type="button" class="panel-close" id="panel-close">close</button>';
  html += '<p class="panel-kind">' + info.kind + '</p>';
  html += '<h2>' + info.title + '</h2>';
  if (info.badges) {
    html += '<p class="panel-badges">' + info.badges.map((b) => badge(b[0], b[1])).join('') + '</p>';
  }
  html += '<p class="lead">' + info.lead + '</p>';
  (info.sections || []).forEach((s) => {
    html += '<h3>' + s.h + '</h3><ul>' + s.items.map((i) => '<li>' + i + '</li>').join('') + '</ul>';
  });
  if (info.p4) {
    html += '<h3>The closed list</h3><ul><li>Named in ADR-20 property 4: <strong>may never become a surface entry</strong>. Adding something to that list, or removing something from it, is a new record.</li></ul>';
  }
  if (info.sources) {
    html += '<h3>Sources</h3><ul class="panel-sources">' +
      info.sources.map((s) => '<li><a href="' + s.href + '">' + s.label + '</a></li>').join('') + '</ul>';
  }
  return html;
}

function select(id) {
  state.active = id;
  let html = null;

  if (id && id.indexOf('entry:') === 0) {
    const entry = ENTRIES.find((e) => e.id === id.slice(6));
    if (entry) html = renderEntry(entry);
  } else if (CONTENT[id]) {
    html = renderContent(CONTENT[id]);
  }

  if (!html) { clearSelection(); return; }

  panelBody.innerHTML = html;
  panelBody.hidden = false;
  panelEmpty.hidden = true;
  document.getElementById('panel-close').addEventListener('click', clearSelection);
  document.querySelector('.panel').scrollTop = 0;
  if (location.hash.slice(1) !== id) {
    history.replaceState(null, '', location.pathname + location.search + '#' + id);
  }
  markActive();
}

function clearSelection() {
  state.active = null;
  panelBody.hidden = true;
  panelBody.innerHTML = '';
  panelEmpty.hidden = false;
  history.replaceState(null, '', location.pathname + location.search);
  markActive();
}

function markActive() {
  svg.querySelectorAll('.node').forEach((n) => {
    const id = n.getAttribute('data-id');
    n.classList.toggle('is-active', !!state.active && (id === state.active ||
      (state.active.indexOf('entry:') === 0 && id === state.active)));
  });
}

/* ── Ebenen ─────────────────────────────────────────────────────────────── */

function applyLenses() {
  svg.querySelectorAll('.node').forEach((n) => {
    const id = n.getAttribute('data-id');
    const info = CONTENT[id];
    const dim = state.lensReview && info && info.covered !== true;
    n.classList.toggle('dimmed', !!dim);
  });
  layers.cuts.classList.toggle('hidden', !state.lensCuts);
  layers.substrate.classList.toggle('hidden', !state.lensCuts);
}

function buildReadout() {
  const on = ENTRIES.filter((e) => state.entries[e.id]);
  const readout = document.getElementById('build-readout');
  if (!on.length) {
    readout.textContent = 'Default build — no entry named. The artefact a deployment gets.';
    return;
  }
  const routes = on.reduce((n, e) => n + e.routes.length, 0);
  readout.textContent = on.map((e) => e.id).join(' + ') + ' — ' + routes +
    ' additional route(s)' +
    (state.entries.honeypot_alert ? ', of which code on the authentication path, not covered by the review' : '');
}

function rebuild() {
  build();
  applyLenses();
  buildReadout();
  markActive();
}

/* ── Controls ──────────────────────────────────────────────────────────── */

const switchList = document.getElementById('surface-switches');
ENTRIES.forEach((entry) => {
  const li = document.createElement('li');
  const label = document.createElement('label');
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.id = 'entry-' + entry.id;
  const span = document.createElement('span');
  span.textContent = entry.id;
  const tag = document.createElement('span');
  tag.className = 'tag ' + (entry.kind === 'build' ? 'tag-build' : 'tag-runtime');
  tag.textContent = entry.kind;
  label.appendChild(box);
  label.appendChild(span);
  label.appendChild(tag);
  const note = document.createElement('span');
  note.className = 'switch-note';
  note.textContent = entry.kind === 'build'
    ? 'A Cargo feature — off means not in the binary. No release contains it; a derived image builds it.'
    : 'The route is not registered at startup';
  li.appendChild(label);
  li.appendChild(note);
  switchList.appendChild(li);
  box.addEventListener('change', () => {
    state.entries[entry.id] = box.checked;
    writeQuery();
    rebuild();
    if (box.checked) select('entry:' + entry.id);
  });
});

/* The active surface is in the URL, so a link shows a configuration rather than
 * only a page. With no parameter it is the default build. */
function readQuery() {
  const on = new URLSearchParams(location.search).get('on');
  if (!on) return;
  on.split(',').map((s) => s.trim()).forEach((id) => {
    if (id in state.entries) {
      state.entries[id] = true;
      const box = document.getElementById('entry-' + id);
      if (box) box.checked = true;
    }
  });
}

function writeQuery() {
  const on = ENTRIES.filter((e) => state.entries[e.id]).map((e) => e.id);
  const query = on.length ? '?on=' + on.join(',') : '';
  history.replaceState(null, '', location.pathname + query + location.hash);
}

document.getElementById('lens-p4').addEventListener('change', (e) => {
  state.lensP4 = e.target.checked;
  rebuild();
  if (e.target.checked) {
    panelBody.innerHTML = '<button type="button" class="panel-close" id="panel-close">close</button>' +
      '<p class="panel-kind">ADR-20 · property 4</p><h2>What may never become switchable</h2>' +
      '<p class="lead">A closed list. Adding something to the surface list is an ordinary change; adding something to <em>this</em> list, or removing something from it, is a new record.</p>' +
      '<ul>' + P4.map((p) => '<li><strong>' + p + '</strong></li>').join('') + '</ul>' +
      '<h3>Why it exists</h3><ul><li>The one realistic failure mode of the surface mechanism is that it grows inwards — step by step, each step sounding reasonable. What helps against that is a list somebody can point at.</li>' +
      '<li>The first request made of this mechanism will be to make auditing or fail-closed switchable: a deployment under load, a full volume, and a boolean that makes the problem go away. Property 4 answers that once and in writing, so it is not negotiated during an incident.</li></ul>' +
      '<h3>Quellen</h3><ul class="panel-sources"><li><a href="' + REPO + '/blob/main/docs/adr/0020-optional-surface.md">ADR-20</a></li></ul>';
    panelBody.hidden = false;
    panelEmpty.hidden = true;
    document.getElementById('panel-close').addEventListener('click', clearSelection);
  }
});

document.getElementById('lens-review').addEventListener('change', (e) => {
  state.lensReview = e.target.checked;
  applyLenses();
  if (e.target.checked) {
    panelBody.innerHTML = '<button type="button" class="panel-close" id="panel-close">close</button>' +
      '<p class="panel-kind">Review · 2026-08-21, against v0.3.0</p><h2>What the review read</h2>' +
      '<p class="panel-badges"><span class="tag tag-warn">not a human practitioner</span></p>' +
      '<p class="lead">What stays lit is what was in the binding scope: <code>ciphr-crypto</code>, <code>ciphr-policy</code> and <code>path.rs</code>, <code>pattern.rs</code>, <code>secret.rs</code> from <code>ciphr-core</code> — plus the second-tier files the coverage section names.</p>' +
      '<h3>What is dimmed</h3><ul>' +
      '<li><code>ciphr-audit</code>, most of <code>ciphr-store</code>, the configuration and TLS code of the server, <code>ui/</code>. Unreviewed — and this decision does not make them otherwise.</li>' +
      '<li><strong>That is why the band does not cross the outer rings.</strong> The geometry is not aesthetics: it is the reach of the review.</li></ul>' +
      '<h3>Who performed it</h3><ul>' +
      '<li>An AI model, commissioned by the maintainer — a different one from the model that co-authored the code, and <strong>not the human practitioner</strong> the working paper asks for. It falsified two claims that the same model had noted as holding on 2026-08-18.</li>' +
      '<li>Two conditions of its fitness statement — unwiped heap copies of a token secret, and a reserved-path refusal that only the HTTP layer enforced — are discharged. <strong>For the hours in between, the acceptance rested on a statement with open conditions</strong>, and the record says so.</li>' +
      '<li><strong>Three claims are newer than the acceptance</strong> (C11, C12, D10): the honeypot entry. New surface on the authentication path does not inherit it.</li></ul>' +
      '<h3>Quellen</h3><ul class="panel-sources"><li><a href="' + REPO + '/blob/main/docs/security-review.md">docs/security-review.md</a></li>' +
      '<li><a href="' + REPO + '/blob/main/docs/review-2026-08-21.md">docs/review-2026-08-21.md</a></li></ul>';
    panelBody.hidden = false;
    panelEmpty.hidden = true;
    document.getElementById('panel-close').addEventListener('click', clearSelection);
  }
});

document.getElementById('lens-cuts').addEventListener('change', (e) => {
  state.lensCuts = e.target.checked;
  applyLenses();
});

/* ── Pan and zoom ───────────────────────────────────────────────────────── */

const view = { cx: -30, cy: -30, scale: 1, baseW: 1720 };

function applyView() {
  const rect = svg.getBoundingClientRect();
  const aspect = rect.height > 0 ? rect.height / rect.width : 0.8;
  const vw = view.baseW / view.scale;
  const vh = vw * aspect;
  svg.setAttribute('viewBox', (view.cx - vw / 2) + ' ' + (view.cy - vh / 2) + ' ' + vw + ' ' + vh);
}

function fit() {
  const rect = svg.getBoundingClientRect();
  const aspect = rect.height > 0 ? rect.height / rect.width : 0.8;
  /* The content is about 1620 wide and 1300 high. Both have to fit. */
  view.baseW = Math.max(1700, 1340 / Math.max(aspect, 0.35));
  view.scale = 1;
  view.cx = -30;
  view.cy = -30;
  applyView();
}

function clientToSvg(clientX, clientY) {
  const rect = svg.getBoundingClientRect();
  const vb = svg.getAttribute('viewBox').split(' ').map(Number);
  return [
    vb[0] + ((clientX - rect.left) / rect.width) * vb[2],
    vb[1] + ((clientY - rect.top) / rect.height) * vb[3]
  ];
}

svg.addEventListener('wheel', (e) => {
  e.preventDefault();
  const [mx, my] = clientToSvg(e.clientX, e.clientY);
  const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
  const next = Math.min(6, Math.max(0.45, view.scale * factor));
  const ratio = view.scale / next;
  view.cx = mx + (view.cx - mx) * ratio;
  view.cy = my + (view.cy - my) * ratio;
  view.scale = next;
  applyView();
}, { passive: false });

let drag = null;
svg.addEventListener('pointerdown', (e) => {
  drag = { x: e.clientX, y: e.clientY, cx: view.cx, cy: view.cy, moved: false };
  svg.classList.add('dragging');
  svg.setPointerCapture(e.pointerId);
});
svg.addEventListener('pointermove', (e) => {
  if (!drag) return;
  const rect = svg.getBoundingClientRect();
  const vb = svg.getAttribute('viewBox').split(' ').map(Number);
  const dx = ((e.clientX - drag.x) / rect.width) * vb[2];
  const dy = ((e.clientY - drag.y) / rect.height) * vb[3];
  if (Math.abs(dx) > 3 || Math.abs(dy) > 3) drag.moved = true;
  view.cx = drag.cx - dx;
  view.cy = drag.cy - dy;
  applyView();
});
svg.addEventListener('pointerup', (e) => {
  if (drag && !drag.moved && e.target === svg) clearSelection();
  drag = null;
  svg.classList.remove('dragging');
});

function zoomBy(factor) {
  view.scale = Math.min(6, Math.max(0.45, view.scale * factor));
  applyView();
}

document.getElementById('zoom-in').addEventListener('click', () => zoomBy(1.25));
document.getElementById('zoom-out').addEventListener('click', () => zoomBy(1 / 1.25));
document.getElementById('zoom-reset').addEventListener('click', fit);

window.addEventListener('resize', applyView);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') clearSelection(); });

/* ── Start ──────────────────────────────────────────────────────────────── */

/* The two links in the masthead are written in the markup now: the page sits in a
   site with a shared navigation bar, and a link that only exists once a script has
   run is a link that is missing in the one situation a reader most needs it. */

readQuery();
rebuild();
fit();

const initial = location.hash.slice(1);
if (initial) select(decodeURIComponent(initial));
