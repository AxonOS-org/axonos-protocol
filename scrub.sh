#!/usr/bin/env bash
# Run inside a fresh clone, AFTER copying README.md, SPEC.md, Cargo.toml,
# src/lib.rs, LICENSE-APACHE, LICENSE-MIT over the working tree.
# Local edits only — no git, no network. Verify with cargo afterwards.
set -eu

echo "→ 1/3  Crate identity: axonos_consent → axonos_protocol (imports / doctests)…"
grep -rl 'axonos_consent' --include='*.rs' . 2>/dev/null | while read -r f; do
  sed -i 's/axonos_consent/axonos_protocol/g' "$f"; echo "      $f"
done

echo "→ 2/3  De-SYM.BOT / MMP → AxonOS Consent Protocol (comments + vector metadata; no wire values)…"
grep -rlE 'sym\.bot|MMP' --include='*.rs' --include='*.json' . 2>/dev/null | while read -r f; do
  sed -i \
    -e 's#https://sym\.bot/spec/mmp-consent#SPEC.md#g' \
    -e 's/MMP Consent Extension v0\.1\.0/the AxonOS Consent Protocol/g' \
    -e 's/MMP Consent Extension/the AxonOS Consent Protocol/g' \
    -e 's/per MMP Section \([0-9][0-9.]*\)/per the AxonOS Consent Protocol (SPEC §\1)/g' \
    -e 's/MMP Section \([0-9][0-9.]*\)/SPEC §\1/g' \
    -e 's/MMP §\([0-9][0-9.]*\)/SPEC §\1/g' \
    -e 's/MMP nodeId/AxonOS mesh node id/g' \
    -e 's/\bMMP\b/AxonOS Consent Protocol/g' \
    "$f"; echo "      $f"
done

echo "→ 3/3  Removing redundant plain LICENSE (full Apache now in LICENSE-APACHE)…"
rm -f LICENSE

cat <<'NOTE'

Done — repo is now purely AxonOS. VERIFY before committing:

    cargo fmt
    cargo test
    cargo test --features json

If green, the vectors still validate and nothing external remains. Then:
    git add -A
    git status
    git commit -m "protocol: v0.3 — AxonOS Consent Protocol (own SPEC.md), de-couple from external MMP/SYM.BOT, real LICENSE-APACHE"
    git push origin main
NOTE
