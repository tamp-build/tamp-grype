# Changelog

All notable changes to **Tamp.Grype** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-09-27

### Added

- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)


## [0.1.0] - 2026-05-13

### Added

- Initial release. Wraps [anchore/grype](https://github.com/anchore/grype) —
  the focused OSS CVE / vulnerability scanner. Filed under TAM-198.
  Closes the supply-chain story alongside Tamp.Syft (SBOM), Tamp.TruffleHog.V3
  (secrets), and Tamp.CodeQL.V2 (code-pattern vulns). Each tool wraps one
  focused axis — no overlap.

#### Primary verb

- **`Grype.Scan(...)`** — `grype [SOURCE]` (no subcommand; source is positional).
  Source modes:
  - `SetSbomSource(path)` → `sbom:<path>` — the canonical "feed me a syft
    output" mode; reads CycloneDX, SPDX, or syft-json
  - `SetDirectorySource(path)` → `dir:<path>`
  - `SetFileSource(path)` → `file:<path>` — works on MSIX / NSIS / OCI archives
  - `SetImageSource(image)` / `SetRegistrySource(image)` — container images
  - `SetPurlFileSource(path)` → `purl:<path>` — newline-separated PURLs
- Output formats: `json`, `table`, `sarif`, `cyclonedx`, `cyclonedx-json`,
  `template` (each with its own `AddOutputXxx()` helper). Multi-output
  supported in one invocation. `SetOutputFile(path)` → `--file`.
- **CI gating: `SetFailOn(severity)`** → `-f / --fail-on`. Grype exits with
  code 2 when matched vulns meet the threshold. Validated against
  `{negligible, low, medium, high, critical}`.
- Fix-state filters: `SetOnlyFixed()` and `SetOnlyNotFixed()` (mutually
  exclusive, validated). `SetIgnoreStates("wont-fix,unknown")` for
  more granular control.
- **Risk-based sorting: `SetSortBy("risk")`** (default) — grype's composite
  0-10 score = CVSS + EPSS (exploit probability) + KEV (CISA actively-exploited
  catalog). Alternatives: `severity`, `epss`, `kev`, `package`, `vulnerability`.
  All validated.
- Layer scope for image scans: `SetScope("squashed" | "all-layers" |
  "deep-squashed")`, validated. `SetPlatform("linux/arm64")` for cross-arch.
- Filtering / metadata: `AddExclude(glob)`, `SetName(name)`,
  `SetDistro("alpine@3.20")`, `SetByCve()`, `SetAddCpesIfNone()`,
  `SetShowSuppressed()`.
- **VEX support**: `AddVexDocument(path)` for already-assessed findings.
  Pairs with [openvex.dev](https://openvex.dev/) documents to suppress
  triaged false positives without losing them from `--show-suppressed`.
- Template output: `SetTemplatePath(path)` required when `AddOutputTemplate()`
  is in the format list — validated at `ToCommandPlan` time.

#### Database management

- **`Grype.Db.{Update, Check, Status, List, Providers, Delete}`** — daemon-free
  verbs for vuln DB lifecycle. `Update` downloads the latest; `Check` reports
  whether an update is available without downloading; `Status` shows local DB
  age / location / hash.
- **`Grype.Db.Import(path-or-url)`** — air-gapped DB install. Required arg
  validated.
- **`Grype.Db.Search(terms)`** — local DB search by package name or vuln ID.
  At least one term required.
- **`Grype.Db.Diff(baseDb, targetDb)`** — diff two DB archives.

#### Other

- **`Grype.Explain(...)`** — `grype explain <vuln-id>...` for detailed
  per-finding explanations. At least one vuln ID required.
- **`Grype.Config(...)`** — print resolved configuration (diagnostic).
- **`Grype.Version(...)`** — diagnostic.
- **`Grype.Raw(...)`** — escape hatch for `completion bash` etc.

#### Shared knobs

- Verbosity: `SetVerbosity(1)` → `-v`, `SetVerbosity(2)` → `-vv`, validated 0-2.
- `SetQuiet()` → `-q`.
- Config files via `AddConfigFile(path)` → `-c`. Profiles via
  `AddProfile(name)` → `--profile`.

### Validation summary

- Primary scan source required (one of the seven setters).
- `OnlyFixed` ⊕ `OnlyNotFixed` mutually exclusive.
- `FailOn` validated against {negligible, low, medium, high, critical}.
- `Scope` validated against {squashed, all-layers, deep-squashed}.
- `SortBy` validated against {package, severity, epss, risk, kev, vulnerability}.
- `template` output format requires `TemplatePath` set.
- `Db.Import` requires source. `Db.Search` requires at least one term.
  `Db.Diff` requires both DBs.
- `Explain` requires at least one vuln ID.
- `Verbosity` validated in [0, 2].

### Tests

- 57 unit tests covering positive paths + negative cases. Surfaces include:
  all 7 source-scheme helpers, all 6 output-format helpers, all 5 fail-on
  severities (+ 3 invalid), all 6 sort-by strategies (+ 1 invalid), all 3
  scope values (+ 1 invalid), `OnlyFixed`/`OnlyNotFixed` mutual exclusion,
  VEX multi-document, all `db` subcommand shapes.

### Requires

- **Tamp.Core ≥ 1.6.0**. Third satellite to ship under the post-1.6.0 regime
  — no IVT entry in `Tamp.Core/AssemblyInfo.cs` needed (Grype doesn't handle
  secrets, but the pattern is the same).

### Notes

- Dogfood-validated against the `tamp-build/tamp` repo's own SBOM (generated
  by Tamp.Syft 0.1.0): one real finding — `okhttp 3.14.9` with
  `GHSA-3cqm-mf7h-prrj` (High severity, fix available in 4.9.2, EPSS 1.0%).
  Pulled in transitively via embedded Java tooling in the .NET coverage
  runner. The chain works end-to-end and the result is actionable.
