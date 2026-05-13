namespace Tamp.Grype;

/// <summary>Common shape shared by every <c>grype</c> verb.</summary>
public abstract class GrypeSettingsBase
{
    /// <summary>Working directory for the spawned grype process.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Per-invocation environment variables.</summary>
    public Dictionary<string, string> EnvironmentVariables { get; } = new();

    /// <summary>Grype configuration file(s) (<c>-c / --config</c>).</summary>
    public List<string> ConfigFiles { get; } = new();

    /// <summary>Profile(s) to apply from the config (<c>--profile</c>).</summary>
    public List<string> Profiles { get; } = new();

    /// <summary>Quiet mode (<c>-q / --quiet</c>).</summary>
    public bool Quiet { get; set; }

    /// <summary>Verbosity level (<c>-v</c>, <c>-vv</c>). 0 = none, 1 = info, 2 = debug. Range validated.</summary>
    public int? Verbosity { get; set; }

    protected abstract IEnumerable<string> Verb { get; }
    protected abstract void AppendArguments(List<string> args);

    internal CommandPlan ToCommandPlan(Tool tool)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (Verbosity is < 0 or > 2)
            throw new InvalidOperationException($"Verbosity must be 0, 1, or 2; got {Verbosity}.");

        var args = new List<string>(Verb);
        foreach (var cfg in ConfigFiles) { args.Add("-c"); args.Add(cfg); }
        foreach (var prof in Profiles) { args.Add("--profile"); args.Add(prof); }
        if (Quiet) args.Add("-q");
        if (Verbosity is 1) args.Add("-v");
        if (Verbosity is 2) args.Add("-vv");
        AppendArguments(args);

        return new CommandPlan
        {
            Executable = tool.Executable.Value,
            Arguments = args,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            WorkingDirectory = WorkingDirectory ?? tool.WorkingDirectory,
            Secrets = Array.Empty<Secret>(),
        };
    }
}

/// <summary>
/// Settings for <c>grype [SOURCE]</c> — primary verb. Scans for CVEs across packages identified
/// in a directory, file, container image, or pre-generated SBOM.
/// </summary>
/// <remarks>
/// <para>
/// The canonical pairing is <c>syft scan dir:. -o cyclonedx-json=sbom.cdx.json</c> followed by
/// <c>grype sbom:sbom.cdx.json</c>. This lets you rescan as the vuln database updates without
/// re-cataloging the source — significant CI speed-up vs. re-running syft each time.
/// </para>
/// <para>
/// <b>CI gating:</b> use <c>SetFailOn("high")</c> (or <c>"critical"</c>) to make grype exit
/// with code 2 if any matched vuln has severity ≥ the threshold. Common pattern: critical-only
/// on PR builds, high-only on main, all-severities on the security-team's dashboard build.
/// </para>
/// <para>
/// <b>Risk-based prioritization:</b> set <c>SetSortBy("risk")</c> (the default) and grype sorts
/// by its composite 0-10 score = CVSS + EPSS (exploit probability) + KEV (CISA actively-exploited
/// catalog). Federal / Microsoft Store / enterprise buyers increasingly care about EPSS+KEV more
/// than raw severity.
/// </para>
/// </remarks>
public sealed class GrypeScanSettings : GrypeSettingsBase
{
    /// <summary>The scan target. Source schemes: <c>sbom:path</c>, <c>dir:path</c>, <c>file:path</c>, <c>registry:image</c>, <c>docker:image</c>, raw image refs, <c>purl:path</c>, single PURL string, etc.</summary>
    public string? Source { get; set; }

    /// <summary>Output format(s) (<c>-o</c>). Formats: <c>json</c>, <c>table</c>, <c>cyclonedx</c>, <c>cyclonedx-json</c>, <c>sarif</c>, <c>template</c>.</summary>
    public List<string> Outputs { get; } = new();

    /// <summary>File to write the default report output to (<c>--file</c>).</summary>
    public string? OutputFile { get; set; }

    /// <summary>CI gating threshold (<c>-f / --fail-on</c>): <c>negligible | low | medium | high | critical</c>. Validated.</summary>
    public string? FailOn { get; set; }

    /// <summary>Filter only-fixed vulns (<c>--only-fixed</c>). Mutually exclusive with <see cref="OnlyNotFixed"/>.</summary>
    public bool OnlyFixed { get; set; }

    /// <summary>Filter only-not-fixed vulns (<c>--only-notfixed</c>).</summary>
    public bool OnlyNotFixed { get; set; }

    /// <summary>Comma-separated fix states to ignore (<c>--ignore-states</c>): <c>fixed,not-fixed,unknown,wont-fix</c>.</summary>
    public string? IgnoreStates { get; set; }

    /// <summary>Prefer CVE IDs over GHSA where possible (<c>--by-cve</c>).</summary>
    public bool ByCve { get; set; }

    /// <summary>Generate CPEs for packages missing CPE data (<c>--add-cpes-if-none</c>).</summary>
    public bool AddCpesIfNone { get; set; }

    /// <summary>Distro override for purl/cpes source modes (<c>--distro</c>). Format: <c>distro@version</c>.</summary>
    public string? Distro { get; set; }

    /// <summary>Glob exclusions (<c>--exclude</c>).</summary>
    public List<string> Excludes { get; } = new();

    /// <summary>Source scheme override (<c>--from</c>).</summary>
    public List<string> From { get; } = new();

    /// <summary>Override the target name in output (<c>--name</c>).</summary>
    public string? Name { get; set; }

    /// <summary>Layer scope for container images (<c>-s / --scope</c>): <c>squashed</c>, <c>all-layers</c>, <c>deep-squashed</c>.</summary>
    public string? Scope { get; set; }

    /// <summary>Platform spec for image scans (<c>--platform</c>).</summary>
    public string? Platform { get; set; }

    /// <summary>Show suppressed/ignored vulnerabilities (<c>--show-suppressed</c>). Table format only.</summary>
    public bool ShowSuppressed { get; set; }

    /// <summary>Sort strategy (<c>--sort-by</c>): <c>package | severity | epss | risk | kev | vulnerability</c>. Default: <c>risk</c>. Validated.</summary>
    public string? SortBy { get; set; }

    /// <summary>Path to Go template file (<c>-t / --template</c>). Required when output format includes <c>template</c>.</summary>
    public string? TemplatePath { get; set; }

    /// <summary>VEX documents to consider (<c>--vex</c>) — suppress findings already assessed by the security team.</summary>
    public List<string> VexDocuments { get; } = new();

    public GrypeScanSettings SetSource(string source) { Source = source; return this; }
    public GrypeScanSettings SetSbomSource(string path) { Source = $"sbom:{path}"; return this; }
    public GrypeScanSettings SetDirectorySource(string path) { Source = $"dir:{path}"; return this; }
    public GrypeScanSettings SetFileSource(string path) { Source = $"file:{path}"; return this; }
    public GrypeScanSettings SetImageSource(string image) { Source = image; return this; }
    public GrypeScanSettings SetRegistrySource(string image) { Source = $"registry:{image}"; return this; }
    public GrypeScanSettings SetPurlFileSource(string path) { Source = $"purl:{path}"; return this; }
    public GrypeScanSettings AddOutput(string formatToken) { Outputs.Add(formatToken); return this; }
    public GrypeScanSettings AddOutputJson() { Outputs.Add("json"); return this; }
    public GrypeScanSettings AddOutputTable() { Outputs.Add("table"); return this; }
    public GrypeScanSettings AddOutputSarif() { Outputs.Add("sarif"); return this; }
    public GrypeScanSettings AddOutputCycloneDx() { Outputs.Add("cyclonedx"); return this; }
    public GrypeScanSettings AddOutputCycloneDxJson() { Outputs.Add("cyclonedx-json"); return this; }
    public GrypeScanSettings AddOutputTemplate() { Outputs.Add("template"); return this; }
    public GrypeScanSettings SetOutputFile(string path) { OutputFile = path; return this; }
    public GrypeScanSettings SetFailOn(string severity) { FailOn = severity; return this; }
    public GrypeScanSettings SetOnlyFixed(bool v = true) { OnlyFixed = v; return this; }
    public GrypeScanSettings SetOnlyNotFixed(bool v = true) { OnlyNotFixed = v; return this; }
    public GrypeScanSettings SetIgnoreStates(string commaSeparated) { IgnoreStates = commaSeparated; return this; }
    public GrypeScanSettings SetByCve(bool v = true) { ByCve = v; return this; }
    public GrypeScanSettings SetAddCpesIfNone(bool v = true) { AddCpesIfNone = v; return this; }
    public GrypeScanSettings SetDistro(string distro) { Distro = distro; return this; }
    public GrypeScanSettings AddExclude(string glob) { Excludes.Add(glob); return this; }
    public GrypeScanSettings AddExcludes(params string[] globs) { Excludes.AddRange(globs); return this; }
    public GrypeScanSettings AddFrom(string scheme) { From.Add(scheme); return this; }
    public GrypeScanSettings SetName(string name) { Name = name; return this; }
    public GrypeScanSettings SetScope(string scope) { Scope = scope; return this; }
    public GrypeScanSettings SetPlatform(string platform) { Platform = platform; return this; }
    public GrypeScanSettings SetShowSuppressed(bool v = true) { ShowSuppressed = v; return this; }
    public GrypeScanSettings SetSortBy(string strategy) { SortBy = strategy; return this; }
    public GrypeScanSettings SetTemplatePath(string path) { TemplatePath = path; return this; }
    public GrypeScanSettings AddVexDocument(string path) { VexDocuments.Add(path); return this; }
    public GrypeScanSettings AddConfigFile(string path) { ConfigFiles.Add(path); return this; }
    public GrypeScanSettings AddProfile(string profile) { Profiles.Add(profile); return this; }
    public GrypeScanSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeScanSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public GrypeScanSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    public GrypeScanSettings SetEnvironmentVariable(string name, string value) { EnvironmentVariables[name] = value; return this; }

    protected override IEnumerable<string> Verb => Array.Empty<string>();  // grype takes [SOURCE] directly, no subcommand

    private static readonly HashSet<string> ValidFailOn = new(StringComparer.Ordinal)
        { "negligible", "low", "medium", "high", "critical" };
    private static readonly HashSet<string> ValidScope = new(StringComparer.Ordinal)
        { "squashed", "all-layers", "deep-squashed" };
    private static readonly HashSet<string> ValidSortBy = new(StringComparer.Ordinal)
        { "package", "severity", "epss", "risk", "kev", "vulnerability" };

    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(Source))
            throw new InvalidOperationException(
                "Source is required for `grype` — set via SetSbomSource(path), SetDirectorySource(path), SetImageSource(image), SetRegistrySource(image), or SetSource(raw).");
        if (OnlyFixed && OnlyNotFixed)
            throw new InvalidOperationException("OnlyFixed and OnlyNotFixed are mutually exclusive.");
        if (!string.IsNullOrEmpty(FailOn) && !ValidFailOn.Contains(FailOn))
            throw new InvalidOperationException(
                $"FailOn must be one of {{negligible, low, medium, high, critical}}; got '{FailOn}'.");
        if (!string.IsNullOrEmpty(Scope) && !ValidScope.Contains(Scope))
            throw new InvalidOperationException(
                $"Scope must be one of {{squashed, all-layers, deep-squashed}}; got '{Scope}'.");
        if (!string.IsNullOrEmpty(SortBy) && !ValidSortBy.Contains(SortBy))
            throw new InvalidOperationException(
                $"SortBy must be one of {{package, severity, epss, risk, kev, vulnerability}}; got '{SortBy}'.");
        if (Outputs.Contains("template") && string.IsNullOrEmpty(TemplatePath))
            throw new InvalidOperationException(
                "TemplatePath is required when 'template' is in the output format list — set via SetTemplatePath(path).");

        args.Add(Source!);
        foreach (var o in Outputs) { args.Add("-o"); args.Add(o); }
        if (!string.IsNullOrEmpty(OutputFile)) { args.Add("--file"); args.Add(OutputFile!); }
        if (!string.IsNullOrEmpty(FailOn)) { args.Add("-f"); args.Add(FailOn!); }
        if (OnlyFixed) args.Add("--only-fixed");
        if (OnlyNotFixed) args.Add("--only-notfixed");
        if (!string.IsNullOrEmpty(IgnoreStates)) { args.Add("--ignore-states"); args.Add(IgnoreStates!); }
        if (ByCve) args.Add("--by-cve");
        if (AddCpesIfNone) args.Add("--add-cpes-if-none");
        if (!string.IsNullOrEmpty(Distro)) { args.Add("--distro"); args.Add(Distro!); }
        foreach (var x in Excludes) { args.Add("--exclude"); args.Add(x); }
        foreach (var f in From) { args.Add("--from"); args.Add(f); }
        if (!string.IsNullOrEmpty(Name)) { args.Add("--name"); args.Add(Name!); }
        if (!string.IsNullOrEmpty(Scope)) { args.Add("-s"); args.Add(Scope!); }
        if (!string.IsNullOrEmpty(Platform)) { args.Add("--platform"); args.Add(Platform!); }
        if (ShowSuppressed) args.Add("--show-suppressed");
        if (!string.IsNullOrEmpty(SortBy)) { args.Add("--sort-by"); args.Add(SortBy!); }
        if (!string.IsNullOrEmpty(TemplatePath)) { args.Add("-t"); args.Add(TemplatePath!); }
        foreach (var v in VexDocuments) { args.Add("--vex"); args.Add(v); }
    }
}

/// <summary>Settings for <c>grype explain</c> — explain a set of vulnerability findings (interactive-style).</summary>
public sealed class GrypeExplainSettings : GrypeSettingsBase
{
    /// <summary>Vulnerability IDs to explain (positional arguments).</summary>
    public List<string> VulnerabilityIds { get; } = new();

    public GrypeExplainSettings AddVulnerability(string id) { VulnerabilityIds.Add(id); return this; }
    public GrypeExplainSettings AddVulnerabilities(params string[] ids) { VulnerabilityIds.AddRange(ids); return this; }
    public GrypeExplainSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeExplainSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public GrypeExplainSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }

    protected override IEnumerable<string> Verb => new[] { "explain" };

    protected override void AppendArguments(List<string> args)
    {
        if (VulnerabilityIds.Count == 0)
            throw new InvalidOperationException(
                "At least one vulnerability ID is required for `grype explain` — use AddVulnerability(id).");
        foreach (var id in VulnerabilityIds) args.Add(id);
    }
}

/// <summary>Settings for <c>grype config</c> — print the resolved configuration.</summary>
public sealed class GrypeConfigSettings : GrypeSettingsBase
{
    public GrypeConfigSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeConfigSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public GrypeConfigSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override IEnumerable<string> Verb => new[] { "config" };
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype version</c>.</summary>
public sealed class GrypeVersionSettings : GrypeSettingsBase
{
    public GrypeVersionSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeVersionSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override IEnumerable<string> Verb => new[] { "version" };
    protected override void AppendArguments(List<string> args) { }
}

// ────────────────────────────────────────────────────────────────────────────
//  grype db — vulnerability database management
// ────────────────────────────────────────────────────────────────────────────

/// <summary>Base for the <c>grype db</c> subcommands. Each derived class supplies its own third token.</summary>
public abstract class GrypeDbSettingsBase : GrypeSettingsBase
{
    protected abstract string Verb2 { get; }
    protected override IEnumerable<string> Verb => new[] { "db", Verb2 };
}

/// <summary>Settings for <c>grype db update</c> — download/install the latest vuln database.</summary>
public sealed class GrypeDbUpdateSettings : GrypeDbSettingsBase
{
    public GrypeDbUpdateSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbUpdateSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public GrypeDbUpdateSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "update";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db check</c> — check whether an update is available without downloading.</summary>
public sealed class GrypeDbCheckSettings : GrypeDbSettingsBase
{
    public GrypeDbCheckSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbCheckSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "check";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db status</c> — current database age, location, sha256.</summary>
public sealed class GrypeDbStatusSettings : GrypeDbSettingsBase
{
    public GrypeDbStatusSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbStatusSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "status";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db list</c> — DBs available per the listing URL.</summary>
public sealed class GrypeDbListSettings : GrypeDbSettingsBase
{
    public GrypeDbListSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbListSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "list";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db providers</c> — list vuln data providers in the DB (NVD, GHSA, distro feeds, etc.).</summary>
public sealed class GrypeDbProvidersSettings : GrypeDbSettingsBase
{
    public GrypeDbProvidersSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbProvidersSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "providers";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db delete</c> — wipe the local DB.</summary>
public sealed class GrypeDbDeleteSettings : GrypeDbSettingsBase
{
    public GrypeDbDeleteSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public GrypeDbDeleteSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override string Verb2 => "delete";
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>grype db import &lt;file-or-url&gt;</c> — air-gapped install of a vuln DB.</summary>
public sealed class GrypeDbImportSettings : GrypeDbSettingsBase
{
    public string? Source { get; set; }
    public GrypeDbImportSettings SetSource(string fileOrUrl) { Source = fileOrUrl; return this; }
    public GrypeDbImportSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    protected override string Verb2 => "import";
    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(Source))
            throw new InvalidOperationException(
                "Source is required for `grype db import` — set via SetSource(fileOrUrl).");
        args.Add(Source!);
    }
}

/// <summary>Settings for <c>grype db search</c> — search the local DB by package or vuln ID.</summary>
public sealed class GrypeDbSearchSettings : GrypeDbSettingsBase
{
    /// <summary>Search terms (positional args). Typically a package name or CVE ID.</summary>
    public List<string> Terms { get; } = new();
    public GrypeDbSearchSettings AddTerm(string term) { Terms.Add(term); return this; }
    public GrypeDbSearchSettings AddTerms(params string[] terms) { Terms.AddRange(terms); return this; }
    public GrypeDbSearchSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    protected override string Verb2 => "search";
    protected override void AppendArguments(List<string> args)
    {
        if (Terms.Count == 0)
            throw new InvalidOperationException(
                "At least one search term is required for `grype db search` — use AddTerm(...).");
        foreach (var t in Terms) args.Add(t);
    }
}

/// <summary>Settings for <c>grype db diff &lt;a&gt; &lt;b&gt;</c> — diff two vuln databases.</summary>
public sealed class GrypeDbDiffSettings : GrypeDbSettingsBase
{
    public string? BaseDb { get; set; }
    public string? TargetDb { get; set; }
    public GrypeDbDiffSettings SetBaseDb(string path) { BaseDb = path; return this; }
    public GrypeDbDiffSettings SetTargetDb(string path) { TargetDb = path; return this; }
    public GrypeDbDiffSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    protected override string Verb2 => "diff";
    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(BaseDb) || string.IsNullOrEmpty(TargetDb))
            throw new InvalidOperationException(
                "Both BaseDb and TargetDb are required for `grype db diff` — set both via SetBaseDb(...) and SetTargetDb(...).");
        args.Add(BaseDb!);
        args.Add(TargetDb!);
    }
}
