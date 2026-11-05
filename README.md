# Tamp.Grype

> Wrapper for [anchore/grype](https://github.com/anchore/grype) — focused CVE / vulnerability scanner across 20+ language ecosystems and all major Linux distros. Reads CycloneDX / SPDX / syft-json SBOMs (pairs natively with [`Tamp.Syft`](https://github.com/tamp-build/tamp-syft)) or scans directories, files, and container images directly.

| Package | Status |
|---|---|
| `Tamp.Grype` | 0.1.0 (initial) |

## Why this exists

Tamp's pattern is **one focused tool per security axis**:

| Axis | Tool | Tamp wrapper |
|---|---|---|
| Leaked secrets | TruffleHog | [`Tamp.TruffleHog.V3`](https://www.nuget.org/packages/Tamp.TruffleHog.V3) |
| Code patterns (SQLi, XSS, taint) | CodeQL | [`Tamp.CodeQL.V2`](https://www.nuget.org/packages/Tamp.CodeQL.V2) |
| Software Bill of Materials | syft | [`Tamp.Syft`](https://github.com/tamp-build/tamp-syft) |
| **Dependency CVEs** | **grype** | **`Tamp.Grype`** (this package) |

grype is grype's sibling tool to syft — same project (Anchore), same data model, same install ergonomics. Reading a pre-generated SBOM means you can rescan whenever the vuln database updates without re-cataloging the source.

## What grype catches

- **20+ language ecosystems**: Go, Python, JavaScript, **Java, Rust, Ruby, PHP, .NET**, and more
- **All major Linux distros**: Alpine, Debian, Ubuntu, RHEL, Amazon Linux, Oracle Linux, SUSE, Arch, Gentoo
- **Vuln data sources**: NVD, GitHub Security Advisories (GHSA), Alpine SecDB, Debian Security Tracker, Red Hat, Ubuntu CSV, Amazon Linux ALAS, Oracle Linux ELSA

**Risk scoring** is the differentiator. grype emits a composite 0-10 score per match combining:

- **CVSS severity** (the traditional baseline)
- **EPSS** (Exploit Prediction Scoring System — 30-day likelihood of real-world exploitation)
- **KEV** (CISA's Known Exploited Vulnerabilities catalog — "we have seen this exploited in the wild")

Default sort is `risk` (the composite). Meaningfully better than raw-severity for prioritization — federal / Microsoft Store / enterprise buyers increasingly require KEV-aware reporting.

## Install

```bash
dotnet add package Tamp.Grype
```

Multi-targets net8 / net9 / net10. Requires `Tamp.Core` ≥ **1.17.5** (the first release with the SARIF `logicalLocations` API that `GrypeSarif` uses).

## Tool installation

- **macOS / Linux:** `brew install grype`
- **Windows:** download release `.zip` from [github.com/anchore/grype/releases](https://github.com/anchore/grype/releases), put on PATH
- **GitHub Actions:** [`anchore/scan-action`](https://github.com/anchore/scan-action) installs + invokes grype in one step

## Quick start — the canonical Syft → Grype chain

```csharp
using Tamp;
using Tamp.Syft;
using Tamp.Grype;

class Build : TampBuild
{
    public static int Main(string[] args) => Execute<Build>(args);

    [Parameter] readonly string Version = "1.0.6";
    [Parameter] readonly string FailOnSeverity = "high";   // critical for PR / high for main

    [FromPath("syft")]  readonly Tool SyftTool = null!;
    [FromPath("grype")] readonly Tool GrypeTool = null!;

    AbsolutePath Artifacts => RootDirectory / "artifacts";
    AbsolutePath Sbom => Artifacts / "dasbook.cdx.json";
    AbsolutePath Vulns => Artifacts / "dasbook.vulns.json";

    Target Sbom => _ => _
        .Description("[Compliance] Generate CycloneDX SBOM")
        .Executes(() =>
        {
            Artifacts.CreateDirectory();
            return Syft.Scan(SyftTool, s => s
                .SetDirectorySource(RootDirectory)
                .SetSourceName("DasBook").SetSourceVersion(Version)
                .AddOutputCycloneDxJson(Sbom)
                .AddExcludes("**/node_modules/**", "**/target/**", "**/bin/**", "**/obj/**"));
        });

    Target CveScan => _ => _
        .DependsOn(nameof(Sbom))
        .Description("[Compliance] CVE scan against the SBOM. Fails the build on >= high.")
        .Executes(() => Grype.Scan(GrypeTool, s => s
            .SetSbomSource(Sbom)                      // ← takes the syft output directly
            .AddOutputJson()
            .SetOutputFile(Vulns)
            .SetFailOn(FailOnSeverity)                // ← exit 2 on first >= high finding
            .SetSortBy("risk")                        // ← EPSS + KEV + CVSS composite
            .SetByCve()));                            // ← prefer CVE IDs over GHSA where mappable
}
```

`dotnet tamp CveScan --version 1.0.6 --failOnSeverity critical` for PR builds. Bump to `high` on main. Move to `medium` only on dedicated security-team builds.

## Verb surface

### `grype` (primary verb, no subcommand)

| Setter | Effect |
|---|---|
| `SetSbomSource(path)` | `sbom:<path>` — the canonical "feed me a syft output" mode |
| `SetDirectorySource(path)` | `dir:<path>` |
| `SetFileSource(path)` | `file:<path>` — works on MSIX / NSIS / OCI archive / etc. |
| `SetImageSource(image)` | bare ref — Docker daemon, falls back to registry |
| `SetRegistrySource(image)` | `registry:<image>` — pull from registry directly |
| `SetPurlFileSource(path)` | `purl:<path>` — newline-separated PURLs |
| `AddOutputJson()` / `AddOutputTable()` / `AddOutputSarif()` / `AddOutputCycloneDx()` / `AddOutputCycloneDxJson()` / `AddOutputTemplate()` | output format(s) |
| `SetOutputFile(path)` | `--file` — write default report to file |
| `SetFailOn("critical"\|"high"\|"medium"\|"low"\|"negligible")` | CI gating — exit code 2 if matched; validated |
| `SetOnlyFixed()` / `SetOnlyNotFixed()` | mutually exclusive filters |
| `SetIgnoreStates("wont-fix,unknown")` | ignore matches in specified fix states |
| `SetByCve()` | prefer CVE IDs over GHSA |
| `SetAddCpesIfNone()` | generate CPEs for packages without them |
| `SetDistro("alpine@3.20")` | distro hint for purl/cpes sources |
| `AddExclude(glob)` | path exclusion |
| `SetName(name)` | override target name in output |
| `SetScope("squashed"\|"all-layers"\|"deep-squashed")` | layer scope for image scans |
| `SetPlatform("linux/arm64")` | image platform |
| `SetShowSuppressed()` | show ignored vulns (table only) |
| `SetSortBy("risk"\|"severity"\|"epss"\|"kev"\|"package"\|"vulnerability")` | result sort; validated |
| `AddVexDocument(path)` | VEX docs to suppress already-assessed findings |
| `SetTemplatePath(path)` | required when output format is `template` |

### `grype db` (vuln database management)

| Method | Verb |
|---|---|
| `Grype.Db.Update(tool)` | `grype db update` — download latest DB |
| `Grype.Db.Check(tool)` | `grype db check` — is an update available? |
| `Grype.Db.Status(tool)` | `grype db status` — local DB info |
| `Grype.Db.List(tool)` | `grype db list` |
| `Grype.Db.Providers(tool)` | `grype db providers` — which vuln feeds are baked in |
| `Grype.Db.Delete(tool)` | `grype db delete` |
| `Grype.Db.Import(tool, s => s.SetSource(...))` | `grype db import <file-or-url>` — air-gapped install |
| `Grype.Db.Search(tool, s => s.AddTerm(...))` | `grype db search <terms>` |
| `Grype.Db.Diff(tool, s => s.SetBaseDb(...).SetTargetDb(...))` | `grype db diff <a> <b>` |

### Other

| Method | Verb |
|---|---|
| `Grype.Explain(tool, s => s.AddVulnerability(id))` | `grype explain <vuln-id>` |
| `Grype.Config(tool)` | print resolved config |
| `Grype.Version(tool)` | version stamp |
| `Grype.Raw(tool, ...)` | escape hatch |

## CI gating — when `--fail-on` fires

grype exits with **code 2** when a matched vuln meets the severity threshold. Standard pattern:

```yaml
- name: SBOM
  run: dotnet run --project build -- Sbom
- name: CVE scan (fails build on >= high)
  run: dotnet run --project build -- CveScan --failOnSeverity high
```

Tighten over time: start at `critical` on day 1, ratchet to `high` once you've worked through the backlog, then `medium` once you have VEX assessments suppressing the inevitable false positives.

## VEX — for the "we've already assessed this" case

When the security team has triaged a finding and decided it's not exploitable in your specific use case, encode it as a [VEX](https://openvex.dev/) document and feed it to grype via `AddVexDocument(path)`. The finding gets suppressed (and shown only with `SetShowSuppressed(true)`). Avoids re-triaging the same false positive on every CI run.

## SARIF that survives the trip to GitLab

grype's own SARIF has three defects that survive into GitLab's UI and misrepresent the scan, and a
fourth that makes repairing that SARIF unsound. All four were measured on grype 0.112.0 over one real
299-match scan:

| | grype's own SARIF | `GrypeSarif.FromJson` |
|---|---|---|
| results | 299 | 299 |
| distinct `(ruleId, location)` keys -- **what a deduplicating consumer displays** | **268** | **299** |
| distinct `partialFingerprints` | **62** | **299** |
| artifact URI | `C:\TEMP\claude\multi\frontend\pnpm-lock.yaml` | `frontend/pnpm-lock.yaml` |
| results where `level` and `security-severity` disagree | 2 | **0** |

### The four defects

**1. Distinct affected versions collapse.** `GHSA-587h-7wmj-h5pm-vite` carried two results -- vite
5.4.21 and vite 7.3.1 -- under one rule id at one location. Since every component in a lock file
reports the *same* location, the rule id is the only part of the `(ruleId, location)` key that can
keep them apart. 31 affected package-versions disappeared. One displayed finding is not one affected
version, and anything counting displayed findings as affected packages under-reports.

**2. Fingerprints identify the package, not the finding.** grype's
`partialFingerprints.primaryLocationLineHash` was shared by **35 different advisories** against
`hono 4.12.3`. 278 of 299 results carried a fingerprint duplicated by another result, so a consumer
deduplicating on fingerprints -- their entire purpose -- collapses 299 findings to **62**.

**3. The artifact URI is not repository-relative.** It is whatever absolute path the scan was handed,
so findings anchor to a path on the runner rather than a file in the repository.

**4. The version is only in the message prose.** A result's rule listed
`purls: ["pkg:npm/vite@5.4.21"]` while one of its two results was vite **7.3.1** -- the rule's own
metadata is wrong for that result, and the only per-result carrier of the version is the English
message string. **This is why the conversion reads grype's JSON instead of patching its SARIF:**
repairing identity from a prose sentence would make correctness depend on grype's message wording.

grype's JSON carries all of it structurally -- `artifact.name`, `artifact.version`, `artifact.purl`,
`artifact.locations[].path`, `vulnerability.severity`, `vulnerability.cvss[].metrics.baseScore`,
`fix` -- and yields the same 299 matches.

### Using it

```csharp
Target Vulnerabilities => _ => _
    .Description("[Security] grype, as SARIF a consumer reads correctly")
    .Executes(() =>
    {
        // Capture JSON, not SARIF: the JSON is the richer artifact and the only sound input.
        ProcessRunner.Run(Grype.Scan(GrypeTool, s => s
            .SetSbomSource(Artifacts / "sbom.cdx.json")
            .AddOutputJson()
            .SetOutputFile(Artifacts / "grype.json")));

        var report = GrypeSarif.ConvertFile(
            Artifacts / "grype.json",
            Artifacts / "grype.sarif",
            new GrypeSarifOptions { SourceRoot = RootDirectory });

        Log.Information("{Report}", report);

        // The counters exist because this failure is invisible in the output: a collapsed list looks
        // exactly like a correct, shorter one.
        if (report.Collapses)
            throw new Exception($"findings would collapse in a deduplicating consumer: {report}");
    });
```

```yaml
# .gitlab-ci.yml -- Ultimate tier; SARIF ingestion is GitLab 19.1+, GA in 19.2.
vulnerabilities:
  script: ./tamp.sh Vulnerabilities
  artifacts:
    reports:
      sarif: artifacts/grype.sarif
```

### Identity

`GrypeRuleIdScope.AdvisoryPackageVersion` (the default) builds rule ids as
`<advisory>/<package>@<version>`, so two affected versions of one package under one advisory stay two
findings. That is the convention grype already uses -- it puts the package name in the id -- carried
one field further. `AdvisoryPackage` reproduces grype's own shape (and its collapse) for parity;
`Advisory` collapses further still, for consumers that key suppressions on a bare advisory id.

The fingerprint is SHA-256 over advisory + purl + location, which distinguishes **both** axes grype's
own fingerprint collapses: two versions of one package, and two advisories against one version. The
purl also travels as a `logicalLocation`, so a consumer reading only locations still sees which
version is affected.

### Severity: which one governs, stated

grype reports two severities that do not always agree -- the advisory's qualitative label and a CVSS
base score. Measured over 299 matches, 2 disagreed: a `Medium` label carrying CVSS 7.5, which a
consumer bucketing the number displays as **High**, and a `Low` label carrying 4.3, displayed as
**Medium**. Both numbers are defensible; shipping both without saying which governs means the
displayed severity is not the scanner's severity, and a gate written against one does not hold
against the other.

| `GrypeSeverityGovernance` | `security-severity` | SARIF `level` from | the other value |
|---|---|---|---|
| `Cvss` (default) | the real CVSS base score | the same score, so the two cannot disagree | `grype.severity` in result properties |
| `ScannerLabel` | **omitted** | grype's label | `grype.cvssBaseScore` in result properties |

**Neither option invents a number or moves a threshold.** One uses the real CVSS score; the other
omits the numeric field so a consumer falls back to `level`. Both severities travel with every result
either way, so a triage script can see the disagreement rather than inherit it silently. The CVSS
bands used (9.0+ / 7.0+ / 4.0+ / 0.1+) are the specification's own, not a Tamp invention.

### What is not changed

No match is filtered, no severity threshold is moved, no score is invented. grype decides what counts
as a finding; this decides how a finding is described. Every match becomes exactly one SARIF result,
and anything unusable is counted in `Dropped` rather than quietly skipped. grype's JSON is left in
place -- it is the richer artifact and worth publishing alongside.

## Pairs with

- **[`Tamp.Syft`](https://github.com/tamp-build/tamp-syft)** — SBOM generator. Output flows directly into `Grype.SetSbomSource(...)`.
- **[`Tamp.TruffleHog.V3`](https://www.nuget.org/packages/Tamp.TruffleHog.V3)** — orthogonal axis (secrets, not CVEs).
- **[`Tamp.CodeQL.V2`](https://www.nuget.org/packages/Tamp.CodeQL.V2)** — orthogonal axis (code patterns, not deps).

## Releasing

Releases follow the [Tamp dogfood pattern](MAINTAINERS.md).

## Settings authoring style

Examples above use the fluent `Set*`-chain shape. Every wrapper verb also accepts a `new XxxSettings { ... }` object-init form — both produce identical `CommandPlan`s. The fluent shape stays canonical in docs and the `tamp init` template; opt into object-init scaffolding via `tamp init --settings-style=init`.

See [Build Script Authoring → Two authoring styles](https://github.com/tamp-build/tamp/wiki/Build-Script-Authoring#two-authoring-styles-for-wrapper-calls-120) on the wiki for the side-by-side comparison.

## License

MIT. See [LICENSE](LICENSE).
