<!--
SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2026 Denis Yermakou <connect@axonos.org>
Part of The AxonOS Project — https://axonos.org
-->

AxonOS Consent Protocol — Dual Licence
======================================

This crate (axonos-protocol) is licensed under your choice of either:

  * Apache License, Version 2.0
    (see LICENSE-APACHE, or http://www.apache.org/licenses/LICENSE-2.0)

  * MIT License
    (see LICENSE-MIT, or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual-licensed as above, without any additional terms or
conditions. This is the "inbound = outbound" model used by the Rust project.

GitHub's licence detector recognises this standard `LICENSE` filename; the
per-licence texts live in LICENSE-APACHE and LICENSE-MIT.


---

## Why this file is not called `LICENSE`

It was, and that had a cost that only became visible on a map.

GitHub detects a repository's licence by reading `LICENSE` and matching it
against known texts. This file is an explanation of dual licensing, not a
licence text, so the detector matched nothing and reported `NOASSERTION` —
which is what an audit tool, a package index or a lawyer's checklist reads as
*unlicensed*.

`LICENSE-APACHE` and `LICENSE-MIT` have been present and correct since the
beginning. Both were being ignored, because a file with prose in it stood where
the detector looks first.

`LICENSE` now carries the MIT text, which is what a detector expects and what a
reader looking for terms wants first. The explanation lives here, under a name
that is not load-bearing.

<sub>© 2026 Denis Yermakou — The AxonOS Project · connect@axonos.org</sub>
