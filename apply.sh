#!/usr/bin/env bash
# Run inside a fresh clone of axonos-protocol, AFTER copying the four files
# (README.md, Cargo.toml, LICENSE-APACHE, LICENSE-MIT) over the working tree.
# This performs only local edits — no git, no network. Verify with cargo after.
set -eu

echo "→ Renaming crate import path axonos_consent → axonos_protocol (use/doctests)…"
grep -rl 'axonos_consent' --include='*.rs' . 2>/dev/null | while read -r f; do
  sed -i 's/axonos_consent/axonos_protocol/g' "$f"; echo "    patched $f"
done

echo "→ Polishing lib.rs doc header…"
sed -i 's/# axonos-consent/# axonos-protocol/; s/AxonOS Consent Engine/AxonOS protocol layer/' src/lib.rs

echo "→ Removing the redundant plain LICENSE (full Apache now lives in LICENSE-APACHE)…"
rm -f LICENSE

cat <<'NOTE'

Done. Now VERIFY in your Rust environment before committing:

    cargo fmt
    cargo test
    cargo test --features json
    # optional: cargo +nightly fuzz build

Only if those are green:
    git add -A
    git status
    git commit -m "protocol: fix crate identity (axonos-consent → axonos-protocol), real LICENSE-APACHE, organism README"
    git push origin main
NOTE
