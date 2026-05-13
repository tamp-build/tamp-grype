namespace Tamp.Grype;

/// <summary>
/// Top-level facade for [anchore/grype](https://github.com/anchore/grype) — focused
/// CVE/vulnerability scanner across 20+ language ecosystems and all major Linux distros.
/// Reads <c>cyclonedx-json</c> / <c>spdx-json</c> / <c>syft-json</c> SBOMs (pairs natively with
/// <c>Tamp.Syft</c>) or scans directories / files / container images directly.
/// </summary>
/// <remarks>
/// <para>
/// <b>Risk-based prioritization:</b> grype's composite 0-10 risk score combines CVSS severity,
/// EPSS exploit probability, and KEV (CISA actively-exploited catalog) status. Default sort is
/// by this composite score — meaningfully better than raw severity for prioritization. Federal /
/// Microsoft Store / enterprise buyers increasingly require KEV-aware reporting.
/// </para>
/// <para>
/// <b>Canonical chain:</b>
/// <code>
/// var sbom = artifactsDir / "sbom.cdx.json";
/// Syft.Scan(syft, s => s.SetDirectorySource(".").AddOutputCycloneDxJson(sbom));
/// Grype.Scan(grype, s => s.SetSbomSource(sbom).AddOutputJson().SetFailOn("high"));
/// </code>
/// </para>
/// <para>
/// <b>Tool resolution:</b>
/// <code>
/// [FromPath("grype")] readonly Tool GrypeTool = null!;
/// </code>
/// Install via <c>brew install grype</c> or download from
/// [github.com/anchore/grype/releases](https://github.com/anchore/grype/releases).
/// </para>
/// </remarks>
public static class Grype
{
    /// <summary>
    /// <c>grype [SOURCE]</c> — primary verb. Source can be an SBOM file
    /// (<c>SetSbomSource(path)</c>), directory, file, image reference, or registry pull.
    /// Set <c>SetFailOn("high")</c> for CI gating.
    /// </summary>
    public static CommandPlan Scan(Tool tool, Action<GrypeScanSettings> configure)
        => Run<GrypeScanSettings>(tool, configure);

    /// <summary><c>grype explain &lt;vuln-id&gt;</c> — explain a vulnerability finding.</summary>
    public static CommandPlan Explain(Tool tool, Action<GrypeExplainSettings> configure)
        => Run<GrypeExplainSettings>(tool, configure);

    /// <summary><c>grype config</c> — print the resolved configuration.</summary>
    public static CommandPlan Config(Tool tool, Action<GrypeConfigSettings>? configure = null)
        => Run<GrypeConfigSettings>(tool, configure);

    /// <summary><c>grype version</c> — diagnostic.</summary>
    public static CommandPlan Version(Tool tool, Action<GrypeVersionSettings>? configure = null)
        => Run<GrypeVersionSettings>(tool, configure);

    /// <summary>Nested verbs under <c>grype db</c> — vuln database management.</summary>
    public static class Db
    {
        public static CommandPlan Update(Tool tool, Action<GrypeDbUpdateSettings>? configure = null)
            => Run<GrypeDbUpdateSettings>(tool, configure);

        public static CommandPlan Check(Tool tool, Action<GrypeDbCheckSettings>? configure = null)
            => Run<GrypeDbCheckSettings>(tool, configure);

        public static CommandPlan Status(Tool tool, Action<GrypeDbStatusSettings>? configure = null)
            => Run<GrypeDbStatusSettings>(tool, configure);

        public static CommandPlan List(Tool tool, Action<GrypeDbListSettings>? configure = null)
            => Run<GrypeDbListSettings>(tool, configure);

        public static CommandPlan Providers(Tool tool, Action<GrypeDbProvidersSettings>? configure = null)
            => Run<GrypeDbProvidersSettings>(tool, configure);

        public static CommandPlan Delete(Tool tool, Action<GrypeDbDeleteSettings>? configure = null)
            => Run<GrypeDbDeleteSettings>(tool, configure);

        public static CommandPlan Import(Tool tool, Action<GrypeDbImportSettings> configure)
            => Run<GrypeDbImportSettings>(tool, configure);

        public static CommandPlan Search(Tool tool, Action<GrypeDbSearchSettings> configure)
            => Run<GrypeDbSearchSettings>(tool, configure);

        public static CommandPlan Diff(Tool tool, Action<GrypeDbDiffSettings> configure)
            => Run<GrypeDbDiffSettings>(tool, configure);
    }

    /// <summary>Raw escape hatch.</summary>
    public static CommandPlan Raw(Tool tool, params string[] arguments)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (arguments is null || arguments.Length == 0)
            throw new ArgumentException("Raw requires at least one argument.", nameof(arguments));
        return new CommandPlan
        {
            Executable = tool.Executable.Value,
            Arguments = arguments.ToList(),
            Environment = new Dictionary<string, string>(),
            WorkingDirectory = tool.WorkingDirectory,
            Secrets = Array.Empty<Secret>(),
        };
    }

    private static CommandPlan Run<T>(Tool tool, Action<T>? configure) where T : GrypeSettingsBase, new()
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        var s = new T();
        configure?.Invoke(s);
        return s.ToCommandPlan(tool);
    }
}
