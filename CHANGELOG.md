# Changelog

All notable changes to **Tamp.Grype** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-05 - SARIF that survives the trip to a consumer

### Added

- **`GrypeSarif` -- SARIF built from grype's JSON, so findings survive the trip to a consumer** ([#6](https://github.com/tamp-build/tamp-grype/issues/6)). Three defects in grype's own SARIF survived into GitLab's UI and misrepresented the scan; a fourth made repairing that SARIF unsound. All four measured on grype 0.112.0 over one real 299-match scan:

  | | grype's own SARIF | `GrypeSarif.FromJson` |
  |---|---|---|
  | results | 299 | 299 |
  | distinct `(ruleId, location)` keys -- what a deduplicating consumer displays | **268** | **299** |
  | distinct `partialFingerprints` | **62** | **299** |
  | artifact URI | absolute runner path | repository-relative |
  | `level` vs `security-severity` disagreements | 2 | **0** |

  1. **Distinct affected versions collapsed.** `GHSA-587h-7wmj-h5pm-vite` carried two results -- vite 5.4.21 and vite 7.3.1 -- under one rule id at one location, so 31 affected package-versions disappeared. Every component in a lock file reports the same location, so the rule id is the only part of that key able to keep them apart: `GrypeRuleIdScope.AdvisoryPackageVersion` (the default) builds `<advisory>/<package>@<version>`, extending the convention grype already uses.
  2. **Fingerprints identified the package, not the finding.** grype's `primaryLocationLineHash` was shared by 35 different advisories against `hono 4.12.3`; 278 of 299 results carried a fingerprint duplicated by another, so a consumer deduplicating on fingerprints collapses 299 findings to 62. The new fingerprint is SHA-256 over advisory + purl + location, distinguishing both axes.
  3. **The artifact URI was not repository-relative.** `SourceRoot` re-roots it; the absolute path is removed from the message prose too. Path handling is string-based rather than `Path`-based, so a scan captured on a Linux runner converts correctly on Windows and vice versa.
  4. **The version was only in the message prose** -- a result's rule listed `purls: ["pkg:npm/vite@5.4.21"]` while one of its two results was vite 7.3.1, so rule metadata is wrong for that result. **This is why the conversion reads grype's JSON rather than patching its SARIF:** recovering identity from an English sentence would make correctness depend on grype's message wording. The JSON carries `artifact.version`, `artifact.purl`, `artifact.locations[].path`, `vulnerability.cvss[].metrics.baseScore` and `fix` structurally, and yields the same match count.

- **Severity governance is explicit** (`GrypeSeverityGovernance`). grype reports a qualitative label and a CVSS score that do not always agree -- 2 of 299 disagreed, including a `Medium` label carrying CVSS 7.5 that a consumer displays as **High**. `Cvss` (default) puts the real score in `security-severity` and derives SARIF `level` from the same number, so the two cannot disagree; `ScannerLabel` **omits** `security-severity` so a consumer falls back to the label-derived `level`. Neither invents a score or moves a threshold -- one uses the real value, the other omits the field. Both severities travel in result properties either way, so a triage script can see the disagreement instead of inheriting it.

- **`GrypeSarifResult` counts the collapse.** `DistinctRuleLocationKeys`, `DistinctFingerprints` and `Collapses` exist because this failure is invisible in the output: a collapsed list looks exactly like a correct, shorter one. A build can assert on them.

### Notes

- Nothing is filtered, no threshold moved, no score invented: grype decides what is a finding, this decides how a finding is described. Every match becomes exactly one result; anything unusable is counted in `Dropped` rather than quietly skipped.
- Capture grype with `-o json`, not `-o sarif`. Passing grype's SARIF in is refused with that advice, since it is the likeliest mistake.
- New dependency: `Tamp.Sarif`, for the SARIF model and writer. **The `Tamp.Core` floor rises to 1.17.5**: that is the first release with the SARIF `logicalLocations` API ([tamp#114](https://github.com/tamp-build/tamp/pull/114)), which carries each finding's purl. Tamp.Sarif ships in lockstep with Tamp.Core and depends on Tamp.Core >= its own version, so every `Tamp.*` pin moves together or restore fails NU1605.

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
