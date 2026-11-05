namespace Tamp.Grype;

/// <summary>
/// Which severity a consumer will display, and therefore which one a gate must be written against.
/// </summary>
/// <remarks>
/// grype reports two severities that do not always agree: the advisory's qualitative label
/// (<c>vulnerability.severity</c>) and a CVSS base score. Measured on grype 0.112.0 over 299 matches,
/// 2 disagreed — a <c>Medium</c> label carrying CVSS 7.5, which a consumer bucketing the number
/// displays as <b>High</b>, and a <c>Low</c> label carrying 4.3, displayed as <b>Medium</b>. Both
/// numbers are defensible; shipping both without saying which governs means the displayed severity is
/// not the scanner's severity, and a gate written against one does not hold against the other.
/// <para>
/// Neither option fabricates a number or moves a scanner threshold. One uses the real CVSS score; the
/// other omits the numeric field entirely.
/// </para>
/// </remarks>
public enum GrypeSeverityGovernance
{
    /// <summary>
    /// The CVSS base score governs. <c>security-severity</c> carries the real score, and the SARIF
    /// <c>level</c> is derived from the same number so the two can never disagree. grype's own label
    /// is preserved in result properties as <c>grype.severity</c>.
    /// <para>
    /// The consequence, stated: the displayed severity is CVSS-derived and may differ from what
    /// <c>grype</c>'s own table output shows. That is the trade for a number that matches the level.
    /// </para>
    /// </summary>
    Cvss,

    /// <summary>
    /// grype's label governs. <c>security-severity</c> is <b>omitted</b> — not rewritten — so a
    /// consumer falls back to the SARIF <c>level</c>, which is derived from the label. The CVSS score
    /// stays in result properties as <c>grype.cvssBaseScore</c> for reference.
    /// <para>
    /// Choose this when a gate is written against grype's own severity names.
    /// </para>
    /// </summary>
    ScannerLabel,
}

/// <summary>How much of a finding's identity goes into the rule id.</summary>
/// <remarks>
/// A consumer that deduplicates on <c>(ruleId, location)</c> — GitLab does — collapses every result
/// that shares both. Since every component in a lock file reports the <i>same</i> location, the rule
/// id is the only part of that key able to keep two findings apart.
/// </remarks>
public enum GrypeRuleIdScope
{
    /// <summary>
    /// <c>&lt;advisory&gt;/&lt;package&gt;@&lt;version&gt;</c> — the default. Two affected versions of
    /// one package under one advisory stay two findings.
    /// <para>
    /// Measured on grype 0.112.0: its own SARIF gave <c>GHSA-587h-7wmj-h5pm-vite</c> to both
    /// <c>vite 5.4.21</c> and <c>vite 7.3.1</c> at the same lock-file path, so 299 results displayed
    /// as 268. Extending the id from package to package-version is the same convention grype already
    /// uses (it puts the package name in the id), carried one field further.
    /// </para>
    /// </summary>
    AdvisoryPackageVersion,

    /// <summary>
    /// <c>&lt;advisory&gt;/&lt;package&gt;</c> — grype's own shape. Distinct affected versions of one
    /// package collapse into one displayed finding, so anything counting displayed findings as
    /// affected packages will under-report. Here for parity with grype's native output.
    /// </summary>
    AdvisoryPackage,

    /// <summary>
    /// <c>&lt;advisory&gt;</c> alone. One rule per advisory, and every affected package and version
    /// collapses together. Rarely what you want; offered because some consumers key suppressions on a
    /// bare advisory id.
    /// </summary>
    Advisory,
}

/// <summary>Inputs to <see cref="GrypeSarif"/>.</summary>
public sealed class GrypeSarifOptions
{
    /// <summary>
    /// The repository root, so emitted locations are repository-relative. <b>Strongly recommended.</b>
    /// grype reports the location it was handed, which for an SBOM scan is whatever path syft
    /// recorded — measured: <c>C:\TEMP\claude\gl-syft\multi\frontend\pnpm-lock.yaml</c>. A finding
    /// anchored to an absolute path on a runner points at nothing in the repository.
    /// <para>
    /// It must be expressed in the <b>same space</b> as the locations grype reported. syft often
    /// records against the scan's virtual filesystem, in which case a lockfile at the root of the
    /// scanned tree is <c>/pnpm-lock.yaml</c> and <c>SourceRoot</c> is <c>"/"</c> — no filesystem
    /// directory will ever contain that path (tamp-grype#9). Use the scanned directory only when the
    /// locations are host paths.
    /// </para>
    /// </summary>
    public string? SourceRoot { get; set; }

    /// <summary>Which severity governs what a consumer displays. See <see cref="GrypeSeverityGovernance"/>.</summary>
    public GrypeSeverityGovernance Severity { get; set; } = GrypeSeverityGovernance.Cvss;

    /// <summary>How much identity goes into the rule id. See <see cref="GrypeRuleIdScope"/>.</summary>
    public GrypeRuleIdScope RuleIdScope { get; set; } = GrypeRuleIdScope.AdvisoryPackageVersion;

    /// <summary>
    /// Emit <c>originalUriBaseIds</c> with <c>%SRCROOT%</c> and tag locations with it, which some
    /// consumers use to resolve a relative path. Off by default: GitLab does not need it, and an
    /// unresolvable base id is worse than none.
    /// </summary>
    public bool EmitUriBaseId { get; set; }

    /// <summary>
    /// Fail when a location cannot be made repository-relative, rather than emitting it absolute.
    /// Default <see langword="true"/>, matching <c>Tamp.Syft</c>'s <c>GitLabSbom</c>.
    /// </summary>
    /// <remarks>
    /// An absolute location means the SARIF ingests and anchors the finding to nothing, which is the
    /// failure <see cref="SourceRoot"/> exists to prevent — and the only way a caller previously
    /// learned of it was by inspecting <see cref="GrypeSarifResult.UnrootedLocations"/> after the
    /// fact (tamp-grype#9). Turn it off when some locations legitimately sit outside the repository,
    /// such as a scanned container image alongside a checkout; they are then emitted as grype
    /// reported them and listed in that collection.
    /// </remarks>
    public bool ThrowOnUnrootedPaths { get; set; } = true;

    /// <summary>Set <see cref="ThrowOnUnrootedPaths"/>.</summary>
    public GrypeSarifOptions SetThrowOnUnrootedPaths(bool v = true) { ThrowOnUnrootedPaths = v; return this; }

    /// <summary>Set <see cref="SourceRoot"/>.</summary>
    public GrypeSarifOptions SetSourceRoot(string? path) { SourceRoot = path; return this; }

    /// <summary>Set <see cref="Severity"/>.</summary>
    public GrypeSarifOptions SetSeverity(GrypeSeverityGovernance governance) { Severity = governance; return this; }

    /// <summary>Set <see cref="RuleIdScope"/>.</summary>
    public GrypeSarifOptions SetRuleIdScope(GrypeRuleIdScope scope) { RuleIdScope = scope; return this; }

    /// <summary>Set <see cref="EmitUriBaseId"/>.</summary>
    public GrypeSarifOptions SetEmitUriBaseId(bool v = true) { EmitUriBaseId = v; return this; }
}

/// <summary>
/// What <see cref="GrypeSarif.FromJson"/> produced, for a build log and for assertions. The counts
/// exist because the failure this conversion fixes is invisible in the output: results that collapse
/// in a consumer's UI look like a correct, smaller list.
/// </summary>
public sealed record GrypeSarifResult
{
    /// <summary>The SARIF log.</summary>
    public required Tamp.Sarif.SarifLog Log { get; init; }

    /// <summary>grype's version, from the report descriptor.</summary>
    public string? GrypeVersion { get; init; }

    /// <summary>Matches read from grype's JSON.</summary>
    public required int Matches { get; init; }

    /// <summary>
    /// SARIF results emitted. Equal to <see cref="Matches"/> unless a match was unusable; a shortfall
    /// is listed in <see cref="Dropped"/>.
    /// </summary>
    public required int Results { get; init; }

    /// <summary>
    /// Distinct <c>(ruleId, location)</c> keys. <b>This is the count a consumer that deduplicates on
    /// that pair will display.</b> When it is lower than <see cref="Results"/>, findings are being
    /// collapsed — raise <see cref="GrypeSarifOptions.RuleIdScope"/>.
    /// </summary>
    public required int DistinctRuleLocationKeys { get; init; }

    /// <summary>
    /// Distinct fingerprints. Lower than <see cref="Results"/> means a consumer deduplicating on
    /// fingerprints will collapse findings; with the default scope it should equal <see cref="Results"/>.
    /// </summary>
    public required int DistinctFingerprints { get; init; }

    /// <summary>Locations that could not be made repository-relative, left as grype reported them.</summary>
    public required IReadOnlyList<string> UnrootedLocations { get; init; }

    /// <summary>Matches skipped, with why. Empty in a normal run.</summary>
    public required IReadOnlyList<string> Dropped { get; init; }

    /// <summary>Whether any finding would collapse in a consumer that keys on rule id plus location.</summary>
    public bool Collapses => DistinctRuleLocationKeys < Results || DistinctFingerprints < Results;

    /// <summary>A one-line summary for a build log.</summary>
    public override string ToString()
        => $"grype {GrypeVersion ?? "?"}: {Matches} match(es) -> {Results} SARIF result(s), "
           + $"{DistinctRuleLocationKeys} distinct (ruleId, location) key(s), {DistinctFingerprints} distinct fingerprint(s)"
           + (Collapses ? " — WOULD COLLAPSE in a deduplicating consumer" : "")
           + (UnrootedLocations.Count > 0 ? $", {UnrootedLocations.Count} unrooted location(s)" : "")
           + (Dropped.Count > 0 ? $", {Dropped.Count} dropped" : "");
}
