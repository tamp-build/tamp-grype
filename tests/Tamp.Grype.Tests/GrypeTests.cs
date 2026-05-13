using System;
using System.Collections.Generic;
using System.Linq;
using Tamp;
using Tamp.Grype;
using Xunit;

namespace Tamp.Grype.Tests;

public sealed class GrypeTests
{
    private static Tool FakeTool() => new(AbsolutePath.Create("/fake/grype"));

    private static int IndexOf(IReadOnlyList<string> args, string token)
    {
        for (var i = 0; i < args.Count; i++) if (args[i] == token) return i;
        return -1;
    }

    // ─── scan: source modes ───────────────────────────────────────────────

    [Fact]
    public void Scan_From_Sbom_Is_The_Canonical_Chain()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("artifacts/sbom.cdx.json")
            .AddOutputJson());
        // Source comes first (positional) — there's no subcommand for the primary verb.
        Assert.Equal("sbom:artifacts/sbom.cdx.json", plan.Arguments[0]);
        Assert.Equal("json", plan.Arguments[IndexOf(plan.Arguments, "-o") + 1]);
    }

    [Fact]
    public void Scan_From_Directory()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetDirectorySource(".").AddOutputTable());
        Assert.Equal("dir:.", plan.Arguments[0]);
        Assert.Equal("table", plan.Arguments[IndexOf(plan.Arguments, "-o") + 1]);
    }

    [Fact]
    public void Scan_From_File()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetFileSource("DasBook.msix").AddOutputJson());
        Assert.Equal("file:DasBook.msix", plan.Arguments[0]);
    }

    [Fact]
    public void Scan_From_Bare_Image_Ref()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetImageSource("alpine:latest").AddOutputJson());
        Assert.Equal("alpine:latest", plan.Arguments[0]);
    }

    [Fact]
    public void Scan_From_Registry()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetRegistrySource("ghcr.io/foo/bar:1.0").AddOutputJson());
        Assert.Equal("registry:ghcr.io/foo/bar:1.0", plan.Arguments[0]);
    }

    [Fact]
    public void Scan_From_Purl_File()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetPurlFileSource("purls.txt").AddOutputJson());
        Assert.Equal("purl:purls.txt", plan.Arguments[0]);
    }

    [Fact]
    public void Scan_Source_Required()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s.AddOutputJson()).Arguments.ToList());
    }

    // ─── outputs ──────────────────────────────────────────────────────────

    [Fact]
    public void Scan_Multiple_Outputs()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json")
            .AddOutputJson()
            .AddOutputSarif()
            .AddOutputCycloneDxJson());
        var outputs = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "-o")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(new[] { "json", "sarif", "cyclonedx-json" }, outputs);
    }

    [Fact]
    public void Scan_Output_File_Flag()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json")
            .AddOutputJson()
            .SetOutputFile("vulns.json"));
        Assert.Equal("vulns.json", plan.Arguments[IndexOf(plan.Arguments, "--file") + 1]);
    }

    [Fact]
    public void Scan_Template_Output_Requires_Template_Path()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetSbomSource("sbom.cdx.json")
                .AddOutputTemplate()).Arguments.ToList());

        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json")
            .AddOutputTemplate()
            .SetTemplatePath("vulns.tmpl"));
        Assert.Equal("vulns.tmpl", plan.Arguments[IndexOf(plan.Arguments, "-t") + 1]);
    }

    // ─── CI gating: --fail-on ─────────────────────────────────────────────

    [Theory]
    [InlineData("negligible")]
    [InlineData("low")]
    [InlineData("medium")]
    [InlineData("high")]
    [InlineData("critical")]
    public void Scan_FailOn_Valid_Severities(string severity)
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson().SetFailOn(severity));
        Assert.Equal(severity, plan.Arguments[IndexOf(plan.Arguments, "-f") + 1]);
    }

    [Theory]
    [InlineData("important")]
    [InlineData("CRITICAL")]
    [InlineData("Critical")]
    public void Scan_FailOn_Rejects_Invalid_Severity(string severity)
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetSbomSource("sbom.cdx.json").AddOutputJson().SetFailOn(severity))
            .Arguments.ToList());
    }

    // ─── only-fixed / only-notfixed mutual exclusion ──────────────────────

    [Fact]
    public void Scan_OnlyFixed_OnlyNotFixed_Mutually_Exclusive()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetSbomSource("sbom.cdx.json")
                .AddOutputJson()
                .SetOnlyFixed().SetOnlyNotFixed()).Arguments.ToList());
    }

    [Fact]
    public void Scan_OnlyFixed_Standalone()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson().SetOnlyFixed());
        Assert.Contains("--only-fixed", plan.Arguments);
    }

    [Fact]
    public void Scan_OnlyNotFixed_Standalone()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson().SetOnlyNotFixed());
        Assert.Contains("--only-notfixed", plan.Arguments);
    }

    [Fact]
    public void Scan_IgnoreStates_Pass_Through()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson()
            .SetIgnoreStates("wont-fix,unknown"));
        Assert.Equal("wont-fix,unknown", plan.Arguments[IndexOf(plan.Arguments, "--ignore-states") + 1]);
    }

    // ─── sort-by validation ───────────────────────────────────────────────

    [Theory]
    [InlineData("package")]
    [InlineData("severity")]
    [InlineData("epss")]
    [InlineData("risk")]
    [InlineData("kev")]
    [InlineData("vulnerability")]
    public void Scan_SortBy_Valid_Strategies(string strategy)
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson().SetSortBy(strategy));
        Assert.Equal(strategy, plan.Arguments[IndexOf(plan.Arguments, "--sort-by") + 1]);
    }

    [Fact]
    public void Scan_SortBy_Rejects_Unknown()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetSbomSource("sbom.cdx.json").AddOutputJson().SetSortBy("date"))
            .Arguments.ToList());
    }

    // ─── scope validation (image scans) ───────────────────────────────────

    [Theory]
    [InlineData("squashed")]
    [InlineData("all-layers")]
    [InlineData("deep-squashed")]
    public void Scan_Scope_Valid(string scope)
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetImageSource("alpine:latest").AddOutputJson().SetScope(scope));
        Assert.Equal(scope, plan.Arguments[IndexOf(plan.Arguments, "-s") + 1]);
    }

    [Fact]
    public void Scan_Scope_Rejected()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetImageSource("alpine:latest").AddOutputJson().SetScope("just-recent"))
            .Arguments.ToList());
    }

    // ─── misc scan knobs ──────────────────────────────────────────────────

    [Fact]
    public void Scan_ByCve_And_AddCpes_Flags()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson()
            .SetByCve().SetAddCpesIfNone());
        Assert.Contains("--by-cve", plan.Arguments);
        Assert.Contains("--add-cpes-if-none", plan.Arguments);
    }

    [Fact]
    public void Scan_Distro_Override_For_Purl_Sources()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSource("pkg:apk/openssl@3.2.1?distro=alpine-3.20.3")
            .AddOutputJson()
            .SetDistro("alpine@3.20"));
        Assert.Equal("alpine@3.20", plan.Arguments[IndexOf(plan.Arguments, "--distro") + 1]);
    }

    [Fact]
    public void Scan_Excludes()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetDirectorySource(".").AddOutputJson()
            .AddExcludes("**/node_modules/**", "**/target/**"));
        var ex = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "--exclude")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(new[] { "**/node_modules/**", "**/target/**" }, ex);
    }

    [Fact]
    public void Scan_Name_Override_For_Output_Identity()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson().SetName("dasbook-1.0.6"));
        Assert.Equal("dasbook-1.0.6", plan.Arguments[IndexOf(plan.Arguments, "--name") + 1]);
    }

    [Fact]
    public void Scan_Platform_For_Image_Targets()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetImageSource("alpine:latest").AddOutputJson().SetPlatform("linux/arm64"));
        Assert.Equal("linux/arm64", plan.Arguments[IndexOf(plan.Arguments, "--platform") + 1]);
    }

    [Fact]
    public void Scan_ShowSuppressed_Flag()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputTable().SetShowSuppressed());
        Assert.Contains("--show-suppressed", plan.Arguments);
    }

    [Fact]
    public void Scan_Vex_Documents()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("sbom.cdx.json").AddOutputJson()
            .AddVexDocument("vex/assessed-cves.json")
            .AddVexDocument("vex/team-overrides.json"));
        var vex = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "--vex")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(2, vex.Count);
    }

    // ─── explain ──────────────────────────────────────────────────────────

    [Fact]
    public void Explain_Requires_Vulnerability_Id()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Explain(FakeTool(), s => { }).Arguments.ToList());
    }

    [Fact]
    public void Explain_Multiple_Ids()
    {
        var plan = Grype.Explain(FakeTool(), s => s.AddVulnerabilities("CVE-2024-12345", "GHSA-aaaa-bbbb-cccc"));
        Assert.Equal(new[] { "explain", "CVE-2024-12345", "GHSA-aaaa-bbbb-cccc" }, plan.Arguments);
    }

    // ─── config / version ─────────────────────────────────────────────────

    [Fact]
    public void Config_Verb()
    {
        var plan = Grype.Config(FakeTool());
        Assert.Equal(new[] { "config" }, plan.Arguments);
    }

    [Fact]
    public void Version_Verb()
    {
        var plan = Grype.Version(FakeTool());
        Assert.Equal(new[] { "version" }, plan.Arguments);
    }

    // ─── db subcommands ───────────────────────────────────────────────────

    [Fact]
    public void Db_Update_Verb()
    {
        var plan = Grype.Db.Update(FakeTool());
        Assert.Equal(new[] { "db", "update" }, plan.Arguments);
    }

    [Fact]
    public void Db_Check_Status_List_Providers_Delete()
    {
        Assert.Equal(new[] { "db", "check" }, Grype.Db.Check(FakeTool()).Arguments);
        Assert.Equal(new[] { "db", "status" }, Grype.Db.Status(FakeTool()).Arguments);
        Assert.Equal(new[] { "db", "list" }, Grype.Db.List(FakeTool()).Arguments);
        Assert.Equal(new[] { "db", "providers" }, Grype.Db.Providers(FakeTool()).Arguments);
        Assert.Equal(new[] { "db", "delete" }, Grype.Db.Delete(FakeTool()).Arguments);
    }

    [Fact]
    public void Db_Import_Requires_Source()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Db.Import(FakeTool(), s => { }).Arguments.ToList());
        var plan = Grype.Db.Import(FakeTool(), s => s.SetSource("./db.tar.gz"));
        Assert.Equal(new[] { "db", "import", "./db.tar.gz" }, plan.Arguments);
    }

    [Fact]
    public void Db_Search_Requires_Term()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Db.Search(FakeTool(), s => { }).Arguments.ToList());
        var plan = Grype.Db.Search(FakeTool(), s => s.AddTerms("openssl", "CVE-2024-12345"));
        Assert.Equal(new[] { "db", "search", "openssl", "CVE-2024-12345" }, plan.Arguments);
    }

    [Fact]
    public void Db_Diff_Requires_Both_Dbs()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Db.Diff(FakeTool(), s => s.SetBaseDb("a.tar.gz")).Arguments.ToList());
        var plan = Grype.Db.Diff(FakeTool(), s => s.SetBaseDb("a.tar.gz").SetTargetDb("b.tar.gz"));
        Assert.Equal(new[] { "db", "diff", "a.tar.gz", "b.tar.gz" }, plan.Arguments);
    }

    // ─── raw / shared knobs ───────────────────────────────────────────────

    [Fact]
    public void Raw_Allows_Arbitrary()
    {
        var plan = Grype.Raw(FakeTool(), "completion", "bash");
        Assert.Equal(new[] { "completion", "bash" }, plan.Arguments);
    }

    [Fact]
    public void Raw_Rejects_Empty()
    {
        Assert.Throws<ArgumentException>(() => Grype.Raw(FakeTool()));
    }

    [Fact]
    public void Verbosity_Levels()
    {
        var v1 = Grype.Scan(FakeTool(), s => s.SetSbomSource("s.json").AddOutputJson().SetVerbosity(1));
        var v2 = Grype.Scan(FakeTool(), s => s.SetSbomSource("s.json").AddOutputJson().SetVerbosity(2));
        Assert.Contains("-v", v1.Arguments);
        Assert.Contains("-vv", v2.Arguments);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(3)]
    public void Verbosity_Out_Of_Range(int level)
    {
        Assert.Throws<InvalidOperationException>(() =>
            Grype.Scan(FakeTool(), s => s
                .SetSbomSource("s.json").AddOutputJson().SetVerbosity(level)).Arguments.ToList());
    }

    [Fact]
    public void Quiet_Flag()
    {
        var plan = Grype.Scan(FakeTool(), s => s.SetSbomSource("s.json").AddOutputJson().SetQuiet());
        Assert.Contains("-q", plan.Arguments);
    }

    [Fact]
    public void Config_And_Profile_Pass_Through()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("s.json").AddOutputJson()
            .AddConfigFile(".grype.yaml")
            .AddProfile("ci"));
        Assert.Equal(".grype.yaml", plan.Arguments[IndexOf(plan.Arguments, "-c") + 1]);
        Assert.Equal("ci", plan.Arguments[IndexOf(plan.Arguments, "--profile") + 1]);
    }

    [Fact]
    public void WorkingDirectory_Propagates()
    {
        var plan = Grype.Scan(FakeTool(), s => s
            .SetSbomSource("s.json").AddOutputJson().SetWorkingDirectory("/repo"));
        Assert.Equal("/repo", plan.WorkingDirectory);
    }
}
