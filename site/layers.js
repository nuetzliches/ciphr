/* ciphr — die Sicherheitsschichten.
 *
 * Die Grafik wird aus der Tabelle unten aufgebaut, damit Geometrie und Aussage an
 * einer Stelle stehen. Sie ist eine Ordnung der Dokumentation, nicht ihre Quelle:
 * jeder Eintrag verweist auf das Dokument, das die Sache entschieden hat.
 *
 * Drei Regeln, die die Darstellung tragen:
 *
 *   1. Ringe sind Grenzen mit einem Gate, keine Qualitätsstufen. Ihre Reihenfolge
 *      ist die Reihenfolge, in der ein Request sie kreuzt.
 *   2. Crates sind keine Ringe. Der reviewed core ist ein *Band* über mehrere Ringe,
 *      weil das seine Eigenschaft ist: in jedem Build in einer Gestalt (ADR-20 P1).
 *   3. Was keinen Ring kreuzt, wird als Schnitt gezeichnet. root auf dem Host und
 *      die Build-Pipeline ignorieren die Zwiebel; eine Zwiebel ohne sie wäre Werbung.
 */

'use strict';

const REPO = 'https://github.com/nuetzliches/ciphr';
const src = (path, label) => ({ label: label || path, href: REPO + '/blob/main/' + path });

const SVGNS = 'http://www.w3.org/2000/svg';

/* ── Geometrie ──────────────────────────────────────────────────────────── */

const R_ASSET = 108;
const RINGS = [
  { id: 'reach',   r: 425, cls: 'is-deployment' },
  { id: 'tls',     r: 360, cls: '' },
  { id: 'surface', r: 300, cls: 'is-switchable' },
  { id: 'auth',    r: 235, cls: '' },
  { id: 'authz',   r: 170, cls: '' }
];

const BAND = { from: 155, to: 246, rOuter: 268 };

/* Winkel mathematisch: 0 rechts, 90 oben. */
const pol = (r, deg) => {
  const a = (deg * Math.PI) / 180;
  return [r * Math.cos(a), -r * Math.sin(a)];
};

/* ── Inhalt ─────────────────────────────────────────────────────────────── */

const CONTENT = {

  asset: {
    kind: 'Zentrum · der Asset',
    title: 'Plaintext und Keymaterial',
    badges: [['tag-plain', 'gebaut'], ['tag-warn', 'A5 erreicht es']],
    lead: 'Genau ein Prozess hält beides. Alles außerhalb der Ringe ist ein Client mit einem Token und einer Policy — auch der Viewer, auch die CLI, auch der MCP-Server, wenn er einmal existiert.',
    sections: [
      { h: 'Was hier liegt', items: [
        '<strong>Der Master Key</strong> wrappt den Root Key, der Root Key wrappt einen Data Key pro Secret-<em>Version</em>. Ein Key verschlüsselt genau ein Payload, deshalb kann eine Nonce-Wiederverwendung <em>auf einem Wert</em> nicht auftreten.',
        '<strong>Die Nonces der Root-Key-Wraps sind zufällig.</strong> Dort ist die Garantie eine Schranke, keine Struktur — und <code>docs/crypto.md</code> sagt das, statt es zu verschweigen.',
        '<strong>Plaintext, solange ein Request läuft.</strong> Secret-tragende Typen implementieren weder <code>Debug</code> noch <code>Display</code> noch <code>Serialize</code>: eines davon zu loggen ist ein Compile-Fehler, keine Review-Frage. Das ist der Hauptgrund für die Sprachwahl (ADR-1).',
        '<strong>ZeroizeOnDrop auf Keymaterial</strong>, dazu Memory-Limit gleich Swap-Limit und abgeschaltete Core-Dumps — der Teil, den die Sprache nicht allein lösen kann.'
      ]},
      { h: 'Wer es trotzdem liest', items: [
        'Root auf dem Host (A5). Siehe den Schnitt — nicht verteidigt, und zwar absichtlich.'
      ]}
    ],
    sources: [src('docs/crypto.md'), src('docs/threat-model.md'), src('docs/adr/0001-language-rust.md', 'ADR-1')],
    covered: true
  },

  band: {
    kind: 'Band · nicht Ring',
    title: 'Der reviewed core',
    badges: [['tag-plain', '~1500 Zeilen'], ['tag-plain', 'eine Gestalt in jedem Build']],
    lead: 'Nicht die innerste Zone, sondern der Code, der jeden Zugriff entscheidet — und der deshalb unkonditional ist. Er läuft quer über drei Ringe: die Autorisierung, die Verifikation auf dem Auth-Ring und das Envelope-Gate zum Store.',
    sections: [
      { h: 'Was dazugehört', items: [
        '<code>ciphr-crypto</code> und <code>ciphr-policy</code> vollständig, dazu <code>path.rs</code>, <code>pattern.rs</code> und <code>secret.rs</code> aus <code>ciphr-core</code>.',
        '<strong>Kein Cargo-Feature, kein <code>cfg(feature)</code>, keine Referenz auf ein Surface-Modul</strong> — und keine Features, die ein Dependent ihnen von außen mitgibt. Vier Behauptungen, die <code>ci/check-core-no-features.sh</code> blockierend prüft.',
        '<strong>Wo ein Feature etwas aus dem Kern braucht, wächst der Kern unbedingt.</strong> Keine gegatete Funktion, sondern eine allgemeine, einmal gelesen, in jedem Build vorhanden — das Optionale liegt darüber und außerhalb.'
      ]},
      { h: 'Warum als Band und nicht als Ring', items: [
        'Ein Ring würde behaupten, der Kern sei eine Schale mit einem eigenen Gate. Er ist stattdessen ein Ausschnitt aus mehreren: die HMAC-Verifikation eines Tokens liegt darin, <em>das Nachschlagen der Identität in <code>ciphr-store</code> nicht</em>. Genau an dieser Kante hängt, was das Review von 2026-08-21 gelesen hat.',
        '<strong>Die Grenze ist die Aussage.</strong> Wenn Optionalität in diese Zeilen wandert, wird aus „der Reviewer hat den Code gelesen, der jeden Zugriff entscheidet" ein „… in einer Konfiguration". Ein Review, das pro Konfiguration wiederholt werden muss, ist die Zusage, später eines zu machen.'
      ]}
    ],
    sources: [src('docs/adr/0020-optional-surface.md', 'ADR-20'), src('ci/check-core-no-features.sh'), src('docs/security-review.md')],
    covered: true
  },

  reach: {
    kind: 'Ring 1 · Eigenschaft des Deployments',
    title: 'Erreichbarkeit ist die erste Kontrolle',
    badges: [['tag-plain', 'kein Code'], ['tag-warn', 'Finding F5']],
    lead: 'Gestrichelt, weil dahinter keine Codezeile steht — nur Netz, Reverse Proxy und die Entscheidung, keinen Port zu veröffentlichen. Es ist trotzdem der erste Ring, weil eine Klasse von Angriffen keinen weiteren kreuzen muss.',
    sections: [
      { h: 'Warum der Ring hier steht', items: [
        '<strong>Jeder Request mit fehlendem oder ungültigem Token schreibt einen Audit-Eintrag</strong> — absichtlich, weil spurenloses Brute Force schlimmer wäre.',
        '<strong>Und Auditing ist fail-closed.</strong> Beide Sätze sind Entscheidungen, die das Threat Model verteidigt. Zusammen ergeben sie: wer den Listener erreicht, kann den Audit-Store bis zum vollen Volume füllen — und braucht dafür kein Credential.',
        'Was folgt, ist eine Deployment-Anforderung, keine Codeänderung: kein veröffentlichter Port, Deploys über einen Runner im LAN, <strong>401-Rate-Limit vor dem Listener</strong>, und <strong>Alarm auf das Wachstum</strong> des Audit-Stores statt nur auf freien Platz. Wachstum kommt früh genug, um zu handeln; ein volles Volume <em>ist</em> der Ausfall.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/operations/audit-trail.md')],
    covered: false
  },

  tls: {
    kind: 'Ring 2 · Transport',
    title: 'TLS endet am Dienst, nicht am Proxy',
    badges: [['tag-plain', 'gebaut'], ['tag-switch', 'nie schaltbar']],
    lead: 'Die bewusste Abweichung von der üblichen Anordnung: der Inhalt dieser Verbindungen sind Plaintext-Secrets, und ein kompromittierter Container im selben Netz ist ein realistischer Gegner (A2).',
    sections: [
      { h: 'Was gilt', items: [
        'Der Reverse Proxy verbindet über HTTPS mit einem <strong>gepinnten internen Zertifikat</strong> (ADR-8, Provenienz in ADR-17).',
        '<code>--insecure</code> kommt in keinem Beispiel vor, auch nicht zum Testen. Selbst der Dev-Proxy des Viewers deaktiviert keine Zertifikatsprüfung, sondern zeigt Node auf die CA des Deployments.',
        '<code>ciphr-sdk</code> kann dem öffentlichen CA-Set nicht einmal vertrauen: <code>ureq</code> wird ohne <code>webpki-roots</code> gebaut, also ist ein Client, der die Welt vertraut, nicht baubar (ADR-19).'
      ]},
      { h: 'Property 4', items: [
        'TLS am Listener steht auf der geschlossenen Liste dessen, was nie ein Surface Entry werden darf. Diese Liste zu ändern, ist ein neuer ADR.'
      ]}
    ],
    sources: [src('docs/adr/0008-tls-terminates-at-the-service.md', 'ADR-8'), src('docs/adr/0017-certificate-provenance.md', 'ADR-17'), src('docs/ui.md')],
    covered: false,
    p4: true
  },

  surface: {
    kind: 'Ring 3 · Surface',
    title: 'Aus heißt abwesend, nicht schlafend',
    badges: [['tag-switch', 'der einzige schaltbare Ring'], ['tag-plain', 'ADR-20']],
    lead: 'Ist diese Route in diesem Deployment überhaupt registriert? Diese Frage wird <em>vor</em> der Authentifizierung beantwortet — und nicht als Konvention, sondern in der Verdrahtung: <code>api.rs</code> registriert Routen bedingt, <code>authenticate()</code> steht in den Handlern.',
    sections: [
      { h: 'Die zwei Arten von Schalter', items: [
        '<strong>runtime</strong> — beim Start komponiert. Aus bedeutet: die Route wird nie registriert, axum antwortet aus dem Fallback. Kein <code>if enabled { … } else { 404 }</code> in einem lebenden Handler, denn ein schlafender Handler ist erreichbarer Code mit einem Zweig, und der Zweig ist die Stelle für den Fehler. Abwesenheit ist außerdem von außen beobachtbar, ein Zweig nicht.',
        '<strong>build</strong> — ein Cargo-Feature, im Default-Build aus. Die Wahl, wenn ein Deployment beweisen muss, dass der Code <em>nicht da</em> ist statt nur nicht aufgerufen. Kostet eine Build-Matrix und ist deshalb nicht die Standardantwort.'
      ]},
      { h: 'Eine Asymmetrie, die ein Label wert ist', items: [
        'Eine <strong>nicht registrierte</strong> Route wird ohne Tokenprüfung und ohne Audit-Eintrag mit 404 beantwortet. Eine <strong>existierende</strong> Route erzeugt auch mit ungültigem Token einen Eintrag. Derselbe Statuscode, zwei ganz verschiedene Spuren.'
      ]},
      { h: 'Ein Entry ist ein Record', items: [
        'Drei Pflichtfelder: ob er an ist, das Datum, an dem das Deployment die Kosten akzeptiert hat, und der Grund. <strong>Der Server startet nicht bei einem Entry, der nicht sagen kann, seit wann und warum</strong> — dieselbe Verweigerung wie ein Start ohne Audit-Device.',
        '<code>/v1/health</code> nennt die aktiven Entries, weil ein Monitoring, das die Form des Überwachten nicht sieht, ein anderes System beobachtet. <strong>Der Grund ist nur authentifiziert lesbar</strong> (<code>ciphr surface show</code>, <code>GET /v1/surface</code>), denn er ist Prosa über eine konkrete Umgebung.',
        'Der Start schreibt einen Audit-Eintrag über die aktive Surface — damit der Trail sagt, wann ein Deployment seine eigene Form geändert hat.',
        '<code>/v1/surface</code> ist absichtlich selbst kein Entry: eine Route, die verschwindet, wenn die Liste leer ist, macht „nichts ist an" und „dieser Build hat den Mechanismus nicht" zu einer Antwort.'
      ]}
    ],
    sources: [src('docs/adr/0020-optional-surface.md', 'ADR-20'), src('crates/ciphr-server/src/api.rs'), src('openapi.yaml')],
    covered: false
  },

  auth: {
    kind: 'Ring 4 · Authentifizierung',
    title: 'Kein anonymer Endpoint außer /v1/health',
    badges: [['tag-plain', 'gebaut'], ['tag-switch', 'teils nie schaltbar']],
    lead: 'Ein Token der Form <code>cph_</code> + 8 Zeichen Identifier + 43 Zeichen Secret. Der Satz über den anonymen Endpoint wird inzwischen erwartet, wahr zu bleiben, statt abzulaufen — die einzige Route, die ihn je gebrochen hätte, ist zurückgestellt.',
    sections: [
      { h: 'Was geprüft wird', items: [
        '<strong>Gepfefferter Verifier, konstante Zeit.</strong> Token-, HMAC- und Tag-Vergleiche verraten nicht, wo sie abweichen. Ein Token ist 256 Bit Zufall, deshalb wäre Password-Hashing CPU auf jedem Request für ein Wörterbuch, das es nicht gibt.',
        'Der achtstellige, nicht geheime Identifier landet im Audit-Trail — und der Viewer zeigt genau ihn, damit sich das Gesehene an die eigenen Einträge binden lässt.',
        '<strong>Jeder Fehlversuch ist ein Eintrag.</strong> Siehe Ring 1: das ist eine Entscheidung mit einer Nebenwirkung, und beide stehen im Threat Model.'
      ]},
      { h: 'Wo das Band diesen Ring kreuzt', items: [
        'Die Verifikation liegt in <code>ciphr-crypto</code> und damit im reviewed core. Das Nachschlagen der Identität liegt in <code>ciphr-store</code> und damit außerhalb — und dort hängt auch die Bait-Erkennung des Build-Entries <code>honeypot_alert</code>.'
      ]}
    ],
    sources: [src('docs/adr/0006-auth-machine-identities-with-tokens.md', 'ADR-6'), src('docs/threat-model.md'), src('docs/security-review.md')],
    covered: true,
    p4: true
  },

  authz: {
    kind: 'Ring 5 · Autorisierung',
    title: 'Deny by default, eine Normalisierung',
    badges: [['tag-plain', 'gebaut'], ['tag-switch', 'nie schaltbar']],
    lead: 'Pfadbasierte Capabilities mit Glob-Mustern. Die Policy kommt aus Konfiguration unter Versionskontrolle, nicht aus einer Write-API — die Commit-Historie ist damit selbst ein Audit-Trail (ADR-3).',
    sections: [
      { h: 'Die Regel, die am ehesten überrascht', items: [
        '<strong>Der spezifischste Treffer gewinnt vollständig und erbt nichts</strong> von breiteren Regeln. Spezifität ist die Zahl der literalen Segmente.',
        'Eine <strong>leere Capability-Liste ist eine explizite Verweigerung</strong>, keine fehlende Angabe. Der Viewer beschriftet beides so, statt es ableiten zu lassen.'
      ]},
      { h: 'Warum es genau eine Normalisierung gibt', items: [
        'Zwei Normalisierungen, die sich in einem Randfall um ein Zeichen unterscheiden, sind ein Autorisierungs-Bypass, den niemand bemerkt. Deshalb existiert die Funktion <strong>genau einmal</strong> und wird von Router <em>und</em> Evaluator aufgerufen (ADR-9), abgedeckt von Property-Tests und einem Fuzzer.',
        'Unicode-NFC gehört dazu: zwei Kodierungen desselben Pfades dürfen nicht zwei verschiedene Secrets werden.'
      ]},
      { h: 'Bulk', items: [
        '<strong>Ein Audit-Eintrag pro ausgeliefertem Secret, nie einer pro Call.</strong> Ein Sammel-Eintrag für einen Bulk-Read wäre genau der blinde Fleck, der andere Kandidaten in der Evaluation disqualifiziert hat.'
      ]}
    ],
    sources: [src('docs/authorization.md'), src('docs/adr/0009-http-stack-axum-but-narrow.md', 'ADR-9'), src('docs/fuzzing.md')],
    covered: true,
    p4: true
  },

  store: {
    kind: 'Laterale Grenze',
    title: 'Zur Platte: SQLite hält nur Ciphertext',
    badges: [['tag-plain', 'gebaut'], ['tag-switch', 'nie schaltbar']],
    lead: 'Keine äußere Schale, sondern eine Grenze <em>zur Seite</em>. Eine reine Zwiebel kennt nur Einwärtsbewegung und würde diese Kante unterschlagen.',
    sections: [
      { h: 'Was hier gilt', items: [
        '<strong>Pfad und Version sind als zusätzliche authentifizierte Daten gebunden.</strong> Ein Ciphertext lässt sich nicht von Pfad A nach Pfad B verschieben — wer in die Datenbank schreiben kann, bekommt einen Entschlüsselungsfehler statt einer stillen Rechteübertragung.',
        'Wer die Datei liest (Backup, gestohlene Platte — A4), hält vollständigen Ciphertext. <strong>Ohne den Master Key ist die Datenbank wertlos</strong> — weshalb Key und Backup nicht in denselben Eimer gehören, sonst <em>ist</em> das Backup der Secret-Store.',
        'Das Envelope-Schema und seine AAD-Bindung stehen auf der geschlossenen Liste (Property 4).'
      ]}
    ],
    sources: [src('docs/crypto.md'), src('docs/operations/master-key.md'), src('docs/adr/0007-storage-sqlite-behind-a-store-trait.md', 'ADR-7')],
    covered: false,
    p4: true
  },

  audit: {
    kind: 'Laterale Grenze · auf dem Rückweg',
    title: 'Zum Trail: Record vor Response',
    badges: [['tag-plain', 'gebaut'], ['tag-switch', 'nie schaltbar']],
    lead: 'Das einzige Gate, das nicht auf dem Hinweg liegt. Der Eintrag ist gespeichert, bevor die Antwort entsteht — nimmt kein konfiguriertes Device den Record an, <strong>wird der Request verweigert und kein Secret ausgeliefert</strong>.',
    sections: [
      { h: 'Was gilt', items: [
        'Der Server startet ohne Audit-Device nicht. Die Pflicht und die Reihenfolge stehen auf der geschlossenen Liste — es ist die erste Anfrage, die jemand an den Surface-Mechanismus stellen wird, und Property 4 antwortet einmal und schriftlich darauf, damit sie nicht während eines Incidents neu verhandelt wird.',
        'Einträge bilden eine <strong>Hash-Chain</strong>: Entfernen oder Ändern eines Eintrags ist erkennbar. <code>ciphr audit verify</code> prüft sie, und ein Wiederherstellungspfad für eine gebrochene Kette ist Teil des Entwurfs.',
        '<strong>Was die Kette nicht leistet:</strong> sie erkennt partielles Tampering, nicht einen Vorwärts-Rewrite durch jemanden, der in den Store schreiben darf. Dagegen hilft nur <code>ciphr audit verify --anchor</code> gegen einen außerhalb festgehaltenen Head.',
        'Der Chain-Badge im Viewer prüft, dass eine <em>Seite</em> ein Lauf ist — er rechnet keine Hashes nach. Eine zweite Implementierung der gehashten Form wäre dieselbe Fehlerklasse wie ein zweiter Pfadnormalisierer, und ihr Versagen wäre schlimmer als nutzlos.'
      ]}
    ],
    sources: [src('docs/operations/audit-trail.md'), src('docs/ui.md'), src('docs/threat-model.md')],
    covered: false,
    p4: true
  },

  cut_root: {
    kind: 'Schnitt · nicht verteidigt',
    title: 'Root auf dem Host (A5)',
    badges: [['tag-warn', 'erreicht das Zentrum'], ['tag-warn', 'absichtlich']],
    lead: 'Kein äußerer Ring. Ein Keil, der jeden Ring ignoriert und im Zentrum landet — und die einzige ehrliche Art, ihn zu zeichnen.',
    sections: [
      { h: 'Was hier gilt', items: [
        'Wer root ist, liest den Master Key dort, wo das Seal ihn hält — die gemountete Datei bei <code>type = "static_file"</code>, die Umgebung bei der Variablenform — und liest ihn ohnehin aus dem Prozessspeicher.',
        '<strong>Das ist die Folge unbeaufsichtigten Starts (ADR-5), also eine Verfügbarkeitsentscheidung und keine kryptografische.</strong> Für OpenBao mit statischem Seal gilt dasselbe. Der Key liegt in derselben Datei mit Modus 0600 wie andere Signaturgeheimnisse: kein Rückschritt gegenüber dem Status quo und kein Gewinn.',
        'Die Grenze zu verschieben, verlangt Split-Key-Unsealing oder ein Hardwaremodul. <strong>Beides ist ohne Formatänderung nachrüstbar</strong>, weil der Master Key genau einen Record wrappt.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/adr/0005-seal-static-key-from-environment.md', 'ADR-5'), src('docs/operations/master-key.md')],
    covered: false
  },

  cut_supply: {
    kind: 'Schnitt · Substrat',
    title: 'Die Build-Pipeline',
    badges: [['tag-warn', 'ersetzt die Zwiebel'], ['tag-warn', 'kein Applikationscode']],
    lead: 'Wer das Image ersetzt, gewinnt. Dieser Schnitt kreuzt keinen Ring — er ist die Fläche, auf der alle Ringe liegen.',
    sections: [
      { h: 'Was dagegen steht', items: [
        'Supply-Chain-Hygiene statt Applikationscode: gepinnte Abhängigkeiten, <code>cargo-deny</code> und <code>cargo audit</code> als blockierende Gates, Action-Hashes statt Action-Tags, Base-Images per Digest statt per Tag.'
      ]},
      { h: 'Und der Punkt, an dem sich das ändert', items: [
        '<strong>Reproduzierbare Builds sind benannt und nicht implementiert.</strong> Solange das Repository privat ist, kann niemand von außen den Quellcode holen, das Image nachbauen und vergleichen — Reproduzierbarkeit wäre eine Eigenschaft, die niemand prüfen kann.',
        '<strong>Sie kauft etwas in dem Moment, in dem das Repository öffentlich wird.</strong> Das ist der Punkt, an dem dieser Absatz sich ändern muss, und das <code>apt-get install</code> in der Runtime-Stage des <code>Dockerfile</code> ist das erste, was dafür weichen muss.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('Dockerfile'), src('AGENTS.md')],
    covered: false
  },

  cut_dos: {
    kind: 'Schnitt · Verfügbarkeitsachse',
    title: 'Fail-closed: das volle Audit-Volume',
    badges: [['tag-warn', 'kein Radius'], ['tag-plain', 'gewollt']],
    lead: 'Kein Ring, sondern eine Achse: ein volles Volume ist ein Totalausfall und keine Logging-Lücke. Das ist beabsichtigt — und der Grund, warum der Füllstand eine überwachte Metrik ist und keine Fußnote.',
    sections: [
      { h: 'Was das begrenzt', items: [
        '<strong>Ist ciphr nicht verfügbar, laufen laufende Dienste weiter</strong> — ihre Konfiguration liegt schon auf ihren Hosts. Nur neue Deploys sind blockiert. Genau das macht eine einzelne Instanz verteidigbar.',
        '<strong>Das ändert sich</strong>, sobald Dienste ihre Secrets beim Start holen statt sie in Dateien gerendert zu bekommen: dann scheitert ein Neustart während eines Ausfalls. Laufende Container bleiben unberührt. Das ist der bewusste Gegenposten zum Sicherheitsgewinn und sollte vor der Einführung des Musters verstanden sein, nicht danach.',
        'Zusammen mit Ring 1: den Füllstand kann ein unauthentifizierter Nachbar treiben, also ist die <em>Rate</em> des Wachstums die Metrik, die früh genug kommt.'
      ]}
    ],
    sources: [src('docs/threat-model.md'), src('docs/operations/audit-trail.md')],
    covered: false
  },

  /* ── Clients ──────────────────────────────────────────────────────────── */

  ci: {
    kind: 'Client · Sektor',
    title: 'CI-Runner (A3)',
    badges: [['tag-plain', 'gebaut']],
    lead: 'Der primäre Konsument — der Name enthält <em>CI</em>. Ein Runner hält ein gültiges Deploy-Token; die Frage ist nicht, ob er eines hat, sondern was er damit erreicht.',
    sections: [
      { h: 'Was die Grenze hält', items: [
        'Die Policy begrenzt ihn auf die Pfade dieses Runners, und jeder Zugriff ist auditiert.',
        '<strong>Detection ist optional und aus:</strong> <code>honeypot_alert</code> macht aus dem Lesen von Bait ein Signal, das keine Interpretation braucht. Es fängt Enumeration und ein überall probiertes Credential — <em>nicht</em> einen Runner, der nur liest, wofür er gekommen ist. Dafür ist der Audit-Trail da.',
        '<strong>Ein Secret, das ciphr verlassen hat, ist das Problem der Pipeline.</strong> Kein Forge maskiert einen zur Laufzeit geholten Wert, nur seine eigenen Secrets. Ein nacktes <code>curl | jq</code> legt Secrets in das Job-Log, sobald jemand <code>set -x</code> hinzufügt — und dieses Log lesen meist mehr Leute als den Secret-Store. Deshalb ist Maskierung Teil des Produkts: <code>export --format actions-env</code> gibt <code>::add-mask::</code> für jeden Wert aus, bevor es irgendetwas anderes ausgibt.'
      ]}
    ],
    sources: [src('docs/operations/cli.md'), src('docs/threat-model.md'), src('docs/operations/honeypots.md')],
    covered: false
  },

  host: {
    kind: 'Client · Sektor',
    title: 'Host-Script',
    badges: [['tag-plain', 'gebaut']],
    lead: 'HTTPS plus Bearer-Token, deshalb ist der minimale Client <code>curl</code>. Kein Agent, kein Plugin, keine Forge-Integration nötig.',
    sections: [
      { h: 'Die zwei Regeln, die jedes Kommando formen', items: [
        '<strong>Ein Wert als Argument ist für jeden Prozess auf dem Host lesbar</strong>, solange das Kommando läuft — und landet in der Shell-History.',
        'Deshalb nimmt die CLI Werte über stdin oder aus einer Datei, und deshalb ist der ehrliche Endzustand <strong>ein Secret pro Host</strong>, nicht keines: dazu ein Audit-Trail, Rotation und ein begrenzter Radius pro Token. Das ist ein exzellenter Tausch und sollte nicht als „keine Secrets mehr auf dem Host" beschrieben werden.'
      ]}
    ],
    sources: [src('docs/operations/cli.md'), src('docs/threat-model.md')],
    covered: false
  },

  cli: {
    kind: 'Client · Sektor',
    title: 'ciphr — die CLI',
    badges: [['tag-plain', 'gebaut']],
    lead: 'Das Host-Werkzeug. Es liest den Audit-Trail, die Identitäten und die Policies <strong>direkt aus dem Store, ohne Netz-Hop</strong> — deshalb kostet <code>viewer_api</code> aus genau den Viewer und nichts sonst.',
    sections: [
      { h: 'Was nur hier geht', items: [
        'Alles Schreibende: Secrets setzen, Tokens ausstellen und widerrufen, den Master Key rotieren, <code>audit verify</code>, <code>audit anchor</code>, <code>audit cut</code>, <code>surface show</code>.',
        '<strong>Einen Wert irgendwohin mitzunehmen, ist die Aufgabe der CLI</strong> — nicht die des Viewers. Deshalb hat der Viewer keinen Copy-Button.',
        '<code>ciphr surface show</code> liest eine <em>Datei</em>, kein Binary: für einen Build-Entry berichtet es, was das Deployment angefordert hat, nicht was es bekommen hat. Nichts auf dem Host sieht den Build des Dienstes — dafür ist <code>GET /v1/health</code> da. Das Kommando sagt diesen Vorbehalt selbst.'
      ]}
    ],
    sources: [src('docs/operations/cli.md'), src('docs/adr/0020-optional-surface.md', 'ADR-20')],
    covered: false
  },

  sdk: {
    kind: 'Client · Sektor',
    title: 'ciphr-sdk',
    badges: [['tag-plain', 'gebaut']],
    lead: 'Für einen Dienst, der seine Secrets selbst holt. Blockierend über <code>ureq</code> (ADR-19): der Aufruf ist ein Fetch beim Start, und eine async-Runtime in jeder konsumierenden Anwendung wäre ein Preis ohne Gegenwert.',
    sections: [
      { h: 'Was daran hängt', items: [
        'Ohne <code>bulk_export</code> arbeitet das SDK weiter — ein Request pro Pfad statt einem für alle. Gleiche Abdeckung, gleiche Zahl an Audit-Einträgen, mehr Round-Trips.',
        '<strong>Der Preis dieses Musters steht auf der Verfügbarkeitsachse:</strong> holt ein Dienst seine Secrets beim Start, scheitert ein Neustart während eines ciphr-Ausfalls. Laufende Container bleiben unberührt.'
      ]}
    ],
    sources: [src('docs/adr/0019-sdk-transport-blocking-ureq.md', 'ADR-19'), src('docs/threat-model.md')],
    covered: false
  },

  run: {
    kind: 'Client · Sektor',
    title: 'ciphr-run',
    badges: [['tag-plain', 'gebaut'], ['tag-runtime', 'braucht bulk_export']],
    lead: 'Der Wrapper für ein Image, das nur Umgebungsvariablen versteht: er holt die Werte und injiziert sie in einen Kindprozess (ADR-14).',
    sections: [
      { h: 'Was daran hängt', items: [
        '<strong>Ohne <code>bulk_export</code> kann er gar nicht holen:</strong> sowohl <code>--prefix</code> als auch <code>--path</code> lesen über <code>POST /v1/export</code>. Er verweigert dann mit Exit-Code 125, statt einen Dienst ohne seine Secrets zu starten.',
        'Eine Regel für den Variablennamen (ADR-18) — genau eine, damit derselbe Pfad überall denselben Namen ergibt.'
      ]}
    ],
    sources: [src('docs/operations/wrapper.md'), src('docs/adr/0014-ciphr-run-injects-into-a-child-process.md', 'ADR-14'), src('docs/adr/0018-one-rule-for-the-variable-name.md', 'ADR-18')],
    covered: false
  },

  viewer: {
    kind: 'Client · Sektor',
    title: 'Der Viewer',
    badges: [['tag-plain', 'gebaut, eigenes Image'], ['tag-runtime', 'braucht viewer_api']],
    lead: 'Ein Peer, kein Durchbruch. Er kreuzt dieselbe Grenze wie die CLI — HTTPS, Token, Policy — und hält weder Keymaterial noch Datenbankzugriff noch eine eigene Identität. Das ist es, was „genau ein Prozess hält Plaintext" wahr hält.',
    sections: [
      { h: 'Was er nicht kann', items: [
        '<strong>Er kann nicht schreiben.</strong> Kein Secret, keine Policy, keine Identität, kein Token. Das ist kein Behelf: eine Policy-Write-API wäre die gefährlichste API, die dieses Projekt haben könnte (ADR-3), und darauf zu verzichten hält den Radius eines XSS-Fundes bei „liest, was der angemeldete Mensch ohnehin lesen darf".',
        '<strong>Er ist nicht Teil des Dienstes.</strong> Ein eigener Container mit statischen Dateien (ADR-11). Der Server hat keinen <code>serve-ui</code>-Modus, keine eingebetteten Assets, keine Template-Engine — ein Fehler in der Asset-Behandlung kann also kein Fehler im Prozess sein, der Plaintext hält.',
        '<strong>Er hat keine private Tür.</strong> ADR-11s Folgeregel: nur dokumentierte v1-Endpoints. Ein Endpoint, der allein für den Viewer existiert, würde heißen, dass die CLI etwas nicht kann, was der Viewer kann.'
      ]},
      { h: 'Eigene Kadenz', items: [
        'Eigene Versionsnummern, eigenes Release (<code>ui-v*</code>). Eine npm-Meldung oder ein Layout-Fix darf kein neues Server-Image erzwingen — und damit keinen Neustart des Dienstes, dessen Neustart die größte Vorsicht verlangt.'
      ]}
    ],
    sources: [src('docs/ui.md'), src('docs/adr/0011-ui-is-an-optional-separate-package.md', 'ADR-11')],
    covered: false
  },

  browser: {
    kind: 'Äußere Zone · durch den Viewer',
    title: 'Der Browser-Tab (A7)',
    badges: [['tag-warn', 'zweiter Ort mit Plaintext']],
    lead: 'Das ist, was der Viewer wirklich hinzufügt — nicht einen Durchbruch nach innen, sondern <strong>eine neue Zone weiter außen</strong>: einen Ort außerhalb des Prozesses, an dem Plaintext existiert. Ein DOM, ein Cache, ein Bildschirm. Genau das ist die Kostenseite.',
    sections: [
      { h: 'Die eigenen Gates dieser Zone', items: [
        '<strong>Reveal ist ein Wert, eine Aktion.</strong> Ein einziges <code>revealed</code>-Ref; ein zweites Reveal ersetzt das erste. Es gibt keine Bulk-Form im Viewer, obwohl <code>/v1/export</code> existiert.',
        '<strong>Plaintext verlässt den State, wenn man die View verlässt.</strong> Views werden mit <code>v-if</code> gewechselt, also zerstört das Verlassen die Komponente, und <code>onUnmounted</code> löscht den Wert zusätzlich. Nichts schreibt einen Wert in eine URL, in <code>localStorage</code> oder in globalen State.',
        '<strong>Kein Copy-Button.</strong> Absichtlich: das Clipboard ist ein Ort, an dem ein Wert den Tab, die Sitzung und die Aufmerksamkeit des Lesers überlebt, ohne Ablaufdatum.',
        '<strong>Kein Service Worker, kein Offline-Cache.</strong> Keiner wird registriert, <code>main.ts</code> deregistriert einen aus einem früheren Deployment, und der Container weigert sich, einen auszuliefern. Eine gecachte Antwort auf einen Secret-Read ist ein Secret ohne Ablaufdatum.',
        '<strong>Strikte CSP</strong> — <code>default-src \'none\'</code>, kein <code>unsafe-inline</code>, kein <code>unsafe-eval</code> — einmal definiert, als Header gesendet <em>und</em> in das gebaute Dokument injiziert, damit ein anderswo ausgeliefertes Bundle sie behält. Kein <code>v-html</code>, kein <code>innerHTML</code>, geprüft von einem blockierenden Gate.',
        '<strong>Token in <code>sessionStorage</code>, kein Cookie.</strong> Damit ist die ganze CSRF-Klasse weg statt gemildert, und ein Token überlebt das Schließen des Tabs nicht — was auf einer geteilten Workstation der Unterschied zwischen einer Sitzung und einem dauerhaften Secret ist.',
        '<strong>Eine Runtime-Abhängigkeit</strong> (<code>vue</code>), mit Obergrenze für den ganzen Baum, ohne Install-Scripts, jedes Paket mit Integrity-Hash — ein eigenes Budget, blockierend geprüft.'
      ]},
      { h: 'Nicht abgedeckt', items: [
        '<code>ui/</code> hat das Review von 2026-08-21 nicht gelesen. Die Sicherheitseigenschaften oben sind implementiert und dokumentiert, aber ungeprüft von außen.'
      ]}
    ],
    sources: [src('docs/ui.md'), src('ci/check-ui-budget.sh'), src('docs/security-review.md')],
    covered: false
  },

  mcp: {
    kind: 'Client · Sektor',
    title: 'MCP-Server (A8)',
    badges: [['tag-plain', 'nicht gebaut'], ['tag-plain', 'post-v1']],
    lead: 'Entworfen, nicht gebaut. Die Zeile im Threat Model ist eine Entwurfszusage, keine Beschreibung — und wird hier deshalb als abwesend gezeichnet.',
    sections: [
      { h: 'Was entschieden ist, bevor es existiert', items: [
        'Ein separater, zustandsloser Prozess (ADR-13), ohne Keymaterial, ohne Datenbankzugriff, ohne eigene Identität.',
        'Der eigentliche Gegner ist nicht der Client, sondern der Weg danach: <strong>Antworten fließen in Modellkontext und Provider-Logs</strong>. Deshalb Metadaten als Standard, Plaintext nur über eine opt-in-Capability auf engen Pfaden, und MCP-Kontext im Audit-Trail markiert.'
      ]}
    ],
    sources: [src('docs/adr/0013-mcp-separate-stateless-process.md', 'ADR-13'), src('docs/threat-model.md')],
    covered: false, absent: true
  },

  report: {
    kind: 'Client · Sektor',
    title: 'Anonymer Reporter (A9)',
    badges: [['tag-plain', 'zurückgestellt']],
    lead: '<code>POST /v1/report</code> — der einzige anonyme Request-Pfad, den dieser Entwurf je hätte. ADR-16 ist zurückgestellt: es ist seinen Preis nur dort wert, wo jemand ohne Token es erreichen kann.',
    sections: [
      { h: 'Warum die Zeile bleibt, obwohl nichts existiert', items: [
        '<strong>Weil der Record bleibt.</strong> Was diesen Pfad verteidigt, wurde entschieden, bevor jemand ihn gebaut hat, und eine Zurückstellung ist kein Grund, das zu verlieren.',
        'Entschieden wäre: identische Antwort für Treffer und Fehlschlag, damit der Endpoint kein Oracle ist; Größen- und Rate-Limits <em>vor</em> dem Audit-Write und vor dem Store-Lock; ein monotoner Metadaten-Schreibvorgang pro getroffener Version, den nichts liest, das eine Entscheidung trifft; kein Pfad zu einem Tripwire-Tier oberhalb von <code>alert</code>.',
        'Solange er fehlt, gilt: <strong>kein unauthentifizierter Endpoint außer <code>/v1/health</code></strong> — und dieser Satz wird inzwischen erwartet, wahr zu bleiben, statt abzulaufen.'
      ]}
    ],
    sources: [src('docs/adr/0016-leak-reports-are-a-one-way-drop-box.md', 'ADR-16'), src('docs/threat-model.md')],
    covered: false, absent: true
  }
};

/* ── Surface Entries ────────────────────────────────────────────────────── */

const ENTRIES = [
  {
    id: 'viewer_api', kind: 'runtime', ring: 'surface', angle: 128, span: 12,
    chip: '+3 Routen',
    routes: ['GET /v1/audit', 'GET /v1/identities', 'GET /v1/policies'],
    activates: ['viewer', 'browser'],
    title: 'viewer_api',
    lead: 'Die drei Routen, die für eine Komponente existieren, die selbst schon optional ist (ADR-11).',
    cost: 'Der Viewer hört auf zu arbeiten. Die CLI nicht: sie liest Audit-Trail, Identitäten und Policies direkt aus dem Store, ohne Netz-Hop. Ein Deployment ohne Viewer hat diese drei Routen also an niemanden ausgeliefert — und die Policy-Struktur samt Identitäten-Inventar an jeden, der irgendein Token hält.',
    extra: [
      'Deckung: das Review von 2026-08-21 hat diese Handler nicht gelesen; die Autorisierung, die sie benutzen, hat es gelesen.'
    ]
  },
  {
    id: 'bulk_export', kind: 'runtime', ring: 'surface', angle: 104, span: 12,
    chip: '+1 Route',
    routes: ['POST /v1/export'],
    activates: ['run'],
    title: 'bulk_export',
    lead: 'Mehrere benannte Pfade in einem Call, ein Audit-Eintrag pro Secret.',
    cost: '<code>ciphr-run</code> kann gar nicht holen: sowohl <code>--prefix</code> als auch <code>--path</code> lesen über diese Route, also verweigert Route B mit Exit-Code 125, statt einen Dienst ohne seine Secrets zu starten. Route C liest stattdessen einen Pfad pro Request — gleiche Abdeckung, gleiche Zahl an Audit-Einträgen, mehr Round-Trips.',
    extra: [
      '<strong>Korrektur in v0.5.1:</strong> der Kostensatz behauptete früher, das Abschalten entferne gefetchte Prefixes und mache damit die Platzierung von Bait leichter. Das tut es nicht. <code>POST /v1/export</code> liest die Pfade, die ein Caller <em>nennt</em>; ob ein Prefix abgedeckt ist, ist eine Eigenschaft des holenden Codes. Wer <code>GET /v1/list/{prefix}</code> — kein Entry — auflistet und dann jeden Pfad liest, deckt denselben Prefix mit dieser Route aus ab.'
    ]
  },
  {
    id: 'honeypot_alert', kind: 'build', ring: 'auth', angle: 45, span: 14,
    chip: '+1 Route, +2 Audit-Actions',
    routes: ['GET /v1/honeypots'],
    activates: [],
    title: 'honeypot_alert',
    lead: 'Bait, die kein legitimer Konsument anfasst, macht aus einem Read ein Signal. Nur das Tier <code>alert</code>; die schweren Tiers sind entworfen und bewusst nicht gebaut.',
    cost: 'Keine Erkennung von Bait. Ein Deployment, das keine pflanzt, zahlt für die Abwesenheit nichts und bekommt die stärkste Form der Ununterscheidbarkeits-Behauptung von ADR-15: Code, der nicht mitkompiliert ist, hat kein Timing, das falsch sein könnte.',
    extra: [
      '<strong>Ein Build-Entry, und deshalb im Default-Build nicht vorhanden.</strong> Genau darum sitzt sein Bogen auf dem Auth-Ring: er fügt Code auf dem Authentifizierungspfad hinzu — Bait-Erkennung in der Token-Verifikation von <code>ciphr-store</code>, ein Tier-Lookup und ein Latch in <code>ciphr-server</code>.',
      '<strong>Neuer als das akzeptierte Review.</strong> Die Claims C11, C12 und D10 beschreiben ihn und sind als nicht abgedeckt markiert. Ihn anzuschalten ist eine Entscheidung darüber, ungeprüften Code auf dem Authentifizierungspfad zu akzeptieren.',
      'Ein Alarm, den niemand pollt, ist kein Alarm: das Signal ist ein Feld auf <code>/v1/health</code> und ein Eintrag im Trail. Nichts hier kann einen Menschen wecken.',
      'Bait unter einem Prefix, den etwas holt, geht in Woche zwei wieder aus — ein Prefix-Fetch liest jeden Pfad darunter.'
    ],
    build: [
      '<strong>Kein veröffentlichtes Artefakt enthält ihn.</strong> Das <code>Dockerfile</code> und beide Release-Workflows bauen ohne <code>--features</code> — also kein released Image und kein released Binary. Es gibt <em>kein</em> zweites Image, und das ist die Entscheidung: ein Feature-Image wäre ein zweites Artefakt mit derselben Version, und eine Checksumme, die nicht sagt, welches man hält.',
      'Wer ihn will, baut selbst: <code>cargo build --release --locked --features honeypot_alert --bin ciphr-server</code>. Für einen Container dasselbe in einem <strong>abgeleiteten Image</strong> — <code>Dockerfile</code> kopieren, das Flag an die <code>cargo build</code>-Zeile, unter eigenem Tag veröffentlichen.',
      '<strong>Danach muss Build und Konfiguration zusammenpassen, und der Dienst erzwingt das:</strong> er startet nicht, wenn das Feature einkompiliert ist und die Stanza fehlt — und ebenso nicht, wenn die Stanza da ist und das Feature nicht. Die zweite Verweigerung ist die wichtige: ohne sie könnte ein Deployment glauben, Detection zu haben, aufgeschrieben haben wann und warum, und keine haben. Bait, die nicht feuern kann, sieht genau aus wie Bait, die niemand genommen hat. <code>ciphr-server --check-config</code> prüft das Paar vorher.',
      '<strong>Diesen Build zu machen ist eine Entscheidung darüber, ungeprüften Code zu betreiben</strong> — und der Grund, warum das Default-Artefakt das Default bleibt. Es nicht zu tun kostet nichts außer Bait, die niemand erkennen kann; ein Deployment, das keine pflanzt, verliert gar nichts.'
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
  'Die Audit-Device-Pflicht', 'Die Fail-closed-Reihenfolge — Record gespeichert, bevor die Antwort entsteht',
  'Deny by default', 'TLS am Listener', 'Das Envelope-Schema und seine AAD-Bindung',
  'Die eine Pfadnormalisierung', 'Konstant-zeitiger Vergleich von Credentials'
];

/* ── Clients und laterale Gates ─────────────────────────────────────────── */

const CLIENTS = [
  { id: 'report',  angle: 172, label: 'POST /v1/report', sub: 'A9 — zurückgestellt', state: 'absent' },
  { id: 'mcp',     angle: 149, label: 'ciphr-mcp',       sub: 'A8 — nicht gebaut',   state: 'absent' },
  { id: 'viewer',  angle: 128, label: 'ciphr-ui',        sub: 'Viewer, eigenes Image', state: 'entry' },
  { id: 'run',     angle: 104, label: 'ciphr-run',       sub: 'Wrapper, Route B',    state: 'entry' },
  { id: 'sdk',     angle: 79,  label: 'ciphr-sdk',       sub: 'Dienst holt selbst',  state: 'on' },
  { id: 'cli',     angle: 56,  label: 'ciphr',           sub: 'CLI auf dem Host',    state: 'on' },
  { id: 'host',    angle: 33,  label: 'curl',            sub: 'Host-Script',         state: 'on' },
  { id: 'ci',      angle: 10,  label: 'CI-Runner',       sub: 'A3 — hält ein Token', state: 'on' }
];

const LATERALS = [
  { id: 'store', angle: 215, label: 'SQLite', sub: 'nur Ciphertext, AAD-gebunden' },
  { id: 'audit', angle: 320, label: 'Audit-Devices', sub: 'append-only, Hash-Chain' }
];

/* ── Zustand ────────────────────────────────────────────────────────────── */

const state = {
  entries: { viewer_api: false, bulk_export: false, honeypot_alert: false },
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

/* Ein Ringsegment als Pfad, für Bögen und Keile. */
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

/* Ein anklickbarer Knoten mit Fokus und Tastaturbedienung. */
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

/* ── Aufbau der Grafik ──────────────────────────────────────────────────── */

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
  text(g, -770, 552, 'cut-label', 'Substrat: die Build-Pipeline — wer das Image ersetzt, gewinnt');
  text(g, -770, 572, 'ring-sub', 'kreuzt keinen Ring. Reproduzierbare Builds: benannt, nicht implementiert — und erst prüfbar, wenn das Repository öffentlich ist.');
}

function buildCuts() {
  /* A5: ein Keil von außen bis ins Zentrum. */
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
  text(g, lx, ly + 4, 'cut-label', 'root auf dem Host (A5) — nicht verteidigt', 'middle');
  text(g, lx, ly + 22, 'ring-sub', 'liest den Master Key, wo das Seal ihn hält, und aus dem Prozessspeicher', 'middle');

  /* Verfügbarkeitsachse: hängt am Audit-Gate, ist aber kein Radius. */
  const d = node('cut_dos', layers.cuts);
  el('rect', { x: 470, y: 392, width: 250, height: 54, rx: 3, class: 'cut-area' }, d);
  el('rect', { x: 470, y: 392, width: 250, height: 54, rx: 3, class: 'hit', 'stroke-width': '6' }, d);
  text(d, 482, 414, 'cut-label', 'fail-closed: volles Volume');
  text(d, 482, 432, 'ring-sub', 'Totalausfall, keine Logging-Lücke — gewollt');
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
  text(g, lx - 8, ly + 13, 'ring-sub', '~1500 Zeilen, eine Gestalt in jedem Build', 'end');
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

  /* Schaltbare Bögen liegen auf dem Ring, dem sie etwas hinzufügen. */
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
    const t = text(g, cx, cy, 'chip-text', entry.id + (on ? ' · ' + entry.chip : ' · aus'), 'middle');
    t.setAttribute('fill', on ? 'var(--switch)' : 'var(--absent)');
    const k = text(g, cx, cy + 14, 'ring-sub', entry.kind === 'build'
      ? (on ? 'im Binary' : 'nicht im Binary')
      : (on ? 'Route registriert' : 'Route nicht registriert'), 'middle');
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

    /* Der Viewer schleppt eine eigene äußere Zone mit sich. */
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
      text(b, bbx + 12, bby + 21, 'client-label', 'Browser-Tab (A7)');
      text(b, bbx + 12, bby + 38, 'client-sub', 'zweiter Ort mit Plaintext');
    }
  });

  /* Ein Satz, der die häufigste Verwechslung abräumt. */
  const [lx, ly] = pol(700, 90);
  text(layers.clients, lx, ly, 'ring-sub', 'Alle hier sind Peers auf derselben Grenze: HTTPS, Token, Policy. Keiner durchbricht einen Ring des anderen.', 'middle');
}

function buildAsset() {
  const g = node('asset', layers.asset);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, fill: 'var(--bg-sunk)' }, g);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, class: 'asset-disc' }, g);
  el('circle', { cx: 0, cy: 0, r: R_ASSET, class: 'hit', 'stroke-width': '10' }, g);
  text(g, 0, -12, 'asset-label', 'Plaintext');
  text(g, 0, 6, 'asset-label', '+ Keymaterial');
  text(g, 0, 28, 'asset-sub', 'genau ein Prozess');
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
  text(layers.labels, colX, 196, 'ring-sub', 'in der Reihenfolge, in der ein Request sie kreuzt');
}

const LABELS = {
  reach:   ['Erreichbarkeit', 'Eigenschaft des Deployments, kein Code'],
  tls:     ['TLS endet hier', 'ADR-8, Zertifikat ADR-17'],
  surface: ['Surface: registriert?', 'ADR-20 — der einzige schaltbare Ring'],
  auth:    ['Authentifizierung', 'Token, konstante Zeit, kein anonymer Endpoint'],
  authz:   ['Autorisierung', 'deny by default, eine Normalisierung']
};

/* ── Panel ──────────────────────────────────────────────────────────────── */

const panelEmpty = document.getElementById('panel-empty');
const panelBody = document.getElementById('panel-body');

function badge(cls, label) {
  return '<span class="tag ' + cls + '">' + label + '</span>';
}

function renderEntry(entry) {
  const on = state.entries[entry.id];
  let html = '<button type="button" class="panel-close" id="panel-close">schließen</button>';
  html += '<p class="panel-kind">Surface Entry · ' + entry.kind + '</p>';
  html += '<h2><code>' + entry.id + '</code></h2>';
  html += '<p class="panel-badges">' +
    badge(entry.kind === 'build' ? 'tag-build' : 'tag-runtime', entry.kind) +
    badge(on ? 'tag-switch' : 'tag-plain', on ? 'an' : 'aus (Default)') +
    (entry.id === 'honeypot_alert' ? badge('tag-warn', 'nicht vom Review gedeckt') : '') +
    '</p>';
  html += '<p class="lead">' + entry.lead + '</p>';
  html += '<h3>Was das Abschalten kostet</h3><blockquote>' + entry.cost + '</blockquote>';
  html += '<h3>Routen</h3><ul>' + entry.routes.map((r) => '<li><code>' + r + '</code></li>').join('') + '</ul>';
  if (entry.extra && entry.extra.length) {
    html += '<h3>Dazu</h3><ul>' + entry.extra.map((x) => '<li>' + x + '</li>').join('') + '</ul>';
  }
  if (entry.build && entry.build.length) {
    html += '<h3>Woher ein Build mit dem Feature kommt</h3><ul>' +
      entry.build.map((x) => '<li>' + x + '</li>').join('') + '</ul>';
  }
  const sources = entry.sources || [
    src('docs/adr/0020-optional-surface.md', 'ADR-20'),
    src('crates/ciphr-cli/src/main.rs', 'crates/ciphr-cli/src/main.rs — KNOWN'),
    src('openapi.yaml')
  ];
  html += '<h3>Quellen</h3><ul class="panel-sources">' +
    sources.map((s) => '<li><a href="' + s.href + '">' + s.label + '</a></li>').join('') + '</ul>';
  return html;
}

function renderContent(info) {
  let html = '<button type="button" class="panel-close" id="panel-close">schließen</button>';
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
    html += '<h3>Geschlossene Liste</h3><ul><li>Steht in ADR-20 Property 4: <strong>darf nie ein Surface Entry werden</strong>. Etwas zu dieser Liste hinzuzufügen oder daraus zu entfernen, ist ein neuer ADR.</li></ul>';
  }
  if (info.sources) {
    html += '<h3>Quellen</h3><ul class="panel-sources">' +
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
    readout.textContent = 'Default-Build — kein Entry benannt. Das Artefakt, das ein Deployment bekommt.';
    return;
  }
  const routes = on.reduce((n, e) => n + e.routes.length, 0);
  readout.textContent = on.map((e) => e.id).join(' + ') + ' — ' + routes +
    ' zusätzliche Route(n)' +
    (state.entries.honeypot_alert ? ', davon Code auf dem Authentifizierungspfad, nicht vom Review gedeckt' : '');
}

function rebuild() {
  build();
  applyLenses();
  buildReadout();
  markActive();
}

/* ── Steuerung ──────────────────────────────────────────────────────────── */

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
    ? 'Cargo-Feature — aus heißt: nicht im Binary. Kein Release enthält es; ein abgeleitetes Image baut es selbst.'
    : 'Route wird beim Start nicht registriert';
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

/* Die aktive Surface steht in der URL, damit ein Link eine Konfiguration zeigt
 * und nicht nur eine Seite. Ohne Parameter ist es der Default-Build. */
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
    panelBody.innerHTML = '<button type="button" class="panel-close" id="panel-close">schließen</button>' +
      '<p class="panel-kind">ADR-20 · Property 4</p><h2>Was nie schaltbar werden darf</h2>' +
      '<p class="lead">Eine geschlossene Liste. Etwas zur Surface-Liste hinzuzufügen ist eine gewöhnliche Änderung; zu <em>dieser</em> Liste etwas hinzuzufügen oder daraus zu entfernen, ist ein neuer ADR.</p>' +
      '<ul>' + P4.map((p) => '<li><strong>' + p + '</strong></li>').join('') + '</ul>' +
      '<h3>Warum sie existiert</h3><ul><li>Der einzige realistische Ausfallmodus des Surface-Mechanismus ist, dass er nach innen wächst — Schritt für Schritt, jeder einzelne vernünftig klingend. Dagegen hilft eine Liste, auf die jemand zeigen kann.</li>' +
      '<li>Die erste Anfrage an diesen Mechanismus wird sein, Auditing oder Fail-closed schaltbar zu machen: ein Deployment unter Last, ein volles Volume und ein Boolean, das das Problem verschwinden lässt. Property 4 antwortet einmal und schriftlich, damit es nicht während eines Incidents verhandelt wird.</li></ul>' +
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
    panelBody.innerHTML = '<button type="button" class="panel-close" id="panel-close">schließen</button>' +
      '<p class="panel-kind">Review · 2026-08-21, gegen v0.3.0</p><h2>Was das Review gelesen hat</h2>' +
      '<p class="panel-badges"><span class="tag tag-warn">kein menschlicher Prüfer</span></p>' +
      '<p class="lead">Hell bleibt, was in der verbindlichen Reichweite lag: <code>ciphr-crypto</code>, <code>ciphr-policy</code> und <code>path.rs</code>, <code>pattern.rs</code>, <code>secret.rs</code> aus <code>ciphr-core</code> — plus die Dateien zweiter Ordnung, die der Deckungsabschnitt nennt.</p>' +
      '<h3>Was ausgeblendet ist</h3><ul>' +
      '<li><code>ciphr-audit</code>, der größte Teil von <code>ciphr-store</code>, Konfiguration und TLS-Code des Servers, <code>ui/</code>. Ungeprüft — und diese Entscheidung macht sie nicht anders.</li>' +
      '<li><strong>Deshalb kreuzt das Band die äußeren Ringe nicht.</strong> Die Geometrie ist keine Ästhetik: sie ist die Reichweite.</li></ul>' +
      '<h3>Wer es war</h3><ul>' +
      '<li>Ein KI-Modell, beauftragt vom Maintainer — ein anderes als das, das den Code mitgeschrieben hat, und <strong>nicht der menschliche Praktiker</strong>, den das Arbeitspapier verlangt. Es hat zwei Claims falsifiziert, die der Durchgang desselben Modells vom 2026-08-18 als haltend notiert hatte.</li>' +
      '<li>Zwei Bedingungen seiner Eignungsaussage — nicht gewischte Heap-Kopien eines Token-Secrets und eine Reserved-Path-Verweigerung, die nur die HTTP-Schicht erzwang — sind erledigt. <strong>Für die Stunden dazwischen stand die Annahme auf einer Aussage mit offenen Bedingungen</strong>, und der Record sagt das.</li>' +
      '<li><strong>Drei Claims sind neuer als die Annahme</strong> (C11, C12, D10): der Honeypot-Eintrag. Neue Surface auf dem Authentifizierungspfad erbt die Annahme nicht.</li></ul>' +
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

/* ── Pan und Zoom ───────────────────────────────────────────────────────── */

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
  /* Der Inhalt ist etwa 1620 breit und 1300 hoch. Beides soll hineinpassen. */
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

document.getElementById('repo-link').href = REPO;
document.getElementById('tm-link').href = REPO + '/blob/main/docs/threat-model.md';

readQuery();
rebuild();
fit();

const initial = location.hash.slice(1);
if (initial) select(decodeURIComponent(initial));
