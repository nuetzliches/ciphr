import { codeToTokens } from "shiki";

const samples = {
  yaml: '- name: Fetch secrets\n  uses: nuetzliches/ciphr@<tag>\n  with:\n    url: ${{ vars.CIPHR_URL }}   # a comment\n',
  bash: 'set -eu    # and not `set -x`\nvalue=$(curl --fail --cacert "$CIPHR_CA" -H "Authorization: Bearer $T" | jq -er \'.value\')\n',
  toml: '[[identity]]\nname     = "ci-widget"\npolicies = ["ci-widget"]\n',
  rust: 'use ciphr_sdk::{Client, SecretPath};\n// a comment\nlet client = Client::builder("https://x", &std::fs::read_to_string("/p")?)\n    .build()?;\n',
};

for (const [lang, code] of Object.entries(samples)) {
  const { tokens } = await codeToTokens(code, {
    lang,
    theme: "github-dark",
    includeExplanation: "scopeName",
  });
  console.log("=====", lang);
  for (const line of tokens) {
    for (const token of line) {
      const scopes = (token.explanation ?? []).flatMap((part) =>
        (part.scopes ?? []).map((s) => s.scopeName ?? s),
      );
      console.log(JSON.stringify(token.content), "|", [...new Set(scopes)].join(" "));
    }
  }
}
