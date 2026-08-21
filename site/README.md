# site/ — die Sicherheitsschichten als Seite

**Status:** current as of 2026-08-21, gegen `v0.5.1`. Die Seite existiert und läuft lokal.
**Sie ist nicht veröffentlicht**, und der Workflow, der sie veröffentlichen würde, existiert
absichtlich nicht — siehe *Veröffentlichung* unten.

Eine interaktive Darstellung der Sicherheitsschichten: `index.html`, `layers.css`, `layers.js`.
Drei Dateien, keine Abhängigkeit, kein externer Request. Sie ordnet, was in `docs/` steht; sie ist
nicht dessen Quelle. Jedes Element verweist auf das Dokument, das die Sache entschieden hat.

## Ansehen

Das Dokument trägt eine strikte Content-Security-Policy (`default-src 'none'`, kein
`unsafe-inline`), dieselbe Haltung wie beim Viewer. `'self'` passt bei `file://` nicht, also über
einen Server öffnen:

```sh
cd site && python -m http.server 8791     # dann http://localhost:8791/
```

Zustand steckt in der URL: `?on=viewer_api,bulk_export` zeigt eine Surface-Konfiguration,
`#band` oder `#cut_root` springt auf ein Element. Ohne Parameter ist es der **Default-Build** —
das Artefakt, das ein Deployment tatsächlich bekommt.

## Was die Darstellung behauptet, und warum sie so gebaut ist

Drei Regeln, die die Geometrie tragen. Sie stehen hier, weil eine Änderung an der Grafik, die eine
davon bricht, keine Layout-Änderung ist, sondern eine inhaltliche.

1. **Ringe sind Grenzen mit einem Gate, keine Qualitätsstufen.** Ihre Reihenfolge ist die
   Reihenfolge, in der ein Request sie kreuzt. Nach außen nimmt nicht die Qualität ab, sondern die
   Zahl der Parteien zu.
2. **Crates sind keine Ringe.** Der reviewed core ist ein *Band* über mehrere Ringe, weil das seine
   Eigenschaft ist: in jedem Build in einer Gestalt (ADR-20 Property 1). Dass es Zentrum, Authz- und
   Auth-Ring kreuzt und die äußeren nicht, ist die Reichweite des Reviews vom 2026-08-21 — Geometrie
   als Aussage, nicht als Ästhetik.
3. **Was keinen Ring kreuzt, wird als Schnitt gezeichnet.** Root auf dem Host und die
   Build-Pipeline ignorieren die Zwiebel. Eine Zwiebel ohne diese Schnitte wäre Werbung.

Und die Regeln aus [`../docs/README.md`](../docs/README.md) gelten hier genauso: die Seite zeigt,
was gebaut ist, und markiert getrennt, was **entworfen und nicht gebaut** (MCP, die schweren
Tripwire-Tiers) und was **zurückgestellt** ist (ADR-16, `POST /v1/report`). Sie trägt ihr eigenes
Datum, und sie ändert sich im selben Commit wie die Aussage, die sie darstellt.

**Keine deployment-spezifischen Angaben.** Keine Hostnamen, keine Pfade, und nicht, welche
Surface-Entries *unsere* Instanz benannt hat. Die Seite beschreibt das Produkt, nicht eine
Installation — dieselbe Trennung, die die Produktdokumentation einhält.

## Veröffentlichung

**Kein Workflow, und das ist eine Entscheidung, keine Lücke.** Diese Seite geht mit der
Entscheidung, das Repository öffentlich zu machen, online — nicht vorher und nicht getrennt davon.

Der Grund ist nicht Geheimhaltung: die Grafik enthält nichts, was `docs/` nicht ohnehin sagt, und
das Threat Model beruft sich ausdrücklich nicht auf Unklarheit. Der Grund ist, dass eine
veröffentlichte Seite aus einem privaten Repository eine Aussage über ein System wäre, dessen
Quelle niemand nachlesen kann — jeder Verweis auf `docs/…` und jede Zeilenangabe führt dann ins
Leere. Das ist genau der Zustand, in dem eine Dokumentation zuversichtliche Fehler produziert.

Was die go-public-Entscheidung für diese Seite auslöst:

- **Einen Actions-Workflow** (`upload-pages-artifact` / `deploy-pages`) für `site/`. Aus einem
  Branch veröffentlicht GitHub Pages nur `/` oder `/docs`, und `/docs` würde die Markdown-Doku durch
  Jekyll schicken. Der Workflow ist der einzige Weg, der `site/` publiziert und `docs/` unberührt
  lässt. Actions dritter Anbieter werden auf einen Commit-Hash gepinnt, nicht auf einen Tag — wie in
  `ci.yml` und `release.yml`.
- **Einen Verweis** aus [`../README.md`](../README.md) und [`../docs/README.md`](../docs/README.md).
  Bewusst noch nicht gesetzt, solange die Seite nirgends erreichbar ist.
- **Die Links prüfen.** Alle Quellenverweise zeigen auf `blob/main/…` im Repository. Aus einem
  privaten Repository sind sie für Fremde 404, und das fällt erst öffentlich auf.

Zwei Absätze, die dieselbe Entscheidung auslöst und die nicht hierher gehören, aber zusammen
gelesen werden sollten: die Reproduzierbarkeit der Builds in
[`../docs/threat-model.md`](../docs/threat-model.md) — sie kauft erst etwas, wenn ein Dritter ein
Image gegen die Quelle nachbauen kann, und das `apt-get install` in der Runtime-Stage des
`Dockerfile` muss dafür weichen — und die Messlatte für das externe Review in
[`../docs/security-review.md`](../docs/security-review.md), die mit einem öffentlichen Repository
wieder auf einen menschlichen Prüfer steigt.
