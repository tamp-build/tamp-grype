using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Tamp.Grype;
using Tamp.Sarif;
using Xunit;

namespace Tamp.Grype.Tests;

/// <summary>
/// #6 — three defects in grype's own SARIF survive into GitLab's UI and misrepresent the scan, and a
/// fourth makes repairing that SARIF unsound. All four were reproduced on grype 0.112.0 over a real
/// 299-match scan; the fixtures below are the minimal shapes that exhibit them.
/// </summary>
public sealed class GrypeSarifTests
{
    private const string Root = "/src/repo";
    private const string LockFile = "/src/repo/frontend/pnpm-lock.yaml";

    private static string Report(params string[] matches) => $$"""
        {
          "matches": [ {{string.Join(",", matches)}} ],
          "source": { "type": "file", "target": "sbom.json" },
          "distro": {},
          "descriptor": { "name": "grype", "version": "0.112.0" }
        }
        """;

    private static string Match(
        string advisory = "GHSA-587h-7wmj-h5pm",
        string package = "vite",
        string version = "5.4.21",
        string severity = "High",
        string packageType = "npm",
        string? location = LockFile,
        double? cvss = 7.5,
        string cvssType = "Primary",
        string cvssVersion = "3.1",
        string fixState = "fixed",
        string? fixVersion = "7.3.2")
    {
        var cvssJson = cvss is null
            ? "[]"
            : $$"""[ { "type": "{{cvssType}}", "version": "{{cvssVersion}}", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "metrics": { "baseScore": {{cvss.Value.ToString("0.0", CultureInfo.InvariantCulture)}} } } ]""";
        var locations = location is null ? "[]" : $$"""[ { "path": "{{location.Replace("\\", "\\\\")}}", "accessPath": "" } ]""";
        var fixJson = fixVersion is null
            ? $$"""{ "versions": [], "state": "{{fixState}}" }"""
            : $$"""{ "versions": [ "{{fixVersion}}" ], "state": "{{fixState}}" }""";

        return $$"""
            {
              "vulnerability": {
                "id": "{{advisory}}",
                "dataSource": "https://github.com/advisories/{{advisory}}",
                "namespace": "github:language:javascript",
                "severity": "{{severity}}",
                "description": "A vulnerability in {{package}}.",
                "cvss": {{cvssJson}},
                "fix": {{fixJson}}
              },
              "relatedVulnerabilities": [],
              "matchDetails": [ { "type": "exact-direct-match", "matcher": "javascript-matcher" } ],
              "artifact": {
                "name": "{{package}}",
                "version": "{{version}}",
                "type": "{{packageType}}",
                "locations": {{locations}},
                "language": "javascript",
                "purl": "pkg:{{packageType}}/{{package}}@{{version}}"
              }
            }
            """;
    }

    private static GrypeSarifResult Convert(string json, GrypeSarifOptions? options = null)
        => GrypeSarif.FromJson(json, options ?? new GrypeSarifOptions { SourceRoot = Root });

    private static GrypeSarifOptions Lenient(string? root = Root)
        => new() { SourceRoot = root, ThrowOnUnrootedPaths = false };

    private static IReadOnlyList<SarifResult> Results(GrypeSarifResult result) => result.Log.Runs[0].Results!;

    private static SarifRule RuleFor(GrypeSarifResult result, SarifResult sarifResult)
        => result.Log.Runs[0].Tool.Driver.Rules!.First(r => r.Id == sarifResult.RuleId);

    private static string? Property(SarifRule rule, string name)
        => rule.Properties?.AdditionalProperties?.TryGetValue(name, out var value) == true ? value.GetString() : null;

    private static string? Property(SarifResult result, string name)
        => result.Properties?.AdditionalProperties?.TryGetValue(name, out var value) == true ? value.GetString() : null;

    // ─── defect 1: distinct versions must stay distinct ───────────────────

    [Fact]
    public void Two_Affected_Versions_Of_One_Package_Stay_Two_Findings()
    {
        // The reproduced case: GHSA-587h-7wmj-h5pm against vite 5.4.21 and vite 7.3.1, both recorded
        // at the same lock file. grype's own SARIF gave them one rule id and one location, so a
        // consumer deduplicating on that pair displayed one finding.
        var result = Convert(Report(Match(version: "5.4.21"), Match(version: "7.3.1")));

        Assert.Equal(2, result.Results);
        Assert.Equal(2, result.DistinctRuleLocationKeys);
        Assert.Equal(2, result.DistinctFingerprints);
        Assert.False(result.Collapses);
        Assert.Equal(
            ["GHSA-587h-7wmj-h5pm/vite@5.4.21", "GHSA-587h-7wmj-h5pm/vite@7.3.1"],
            Results(result).Select(r => r.RuleId).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_Collapse_Is_Detected_And_Reported_When_The_Scope_Allows_It()
    {
        var result = Convert(Report(Match(version: "5.4.21"), Match(version: "7.3.1")),
            new GrypeSarifOptions { SourceRoot = Root, RuleIdScope = GrypeRuleIdScope.AdvisoryPackage });

        // grype's own shape, reproduced deliberately: two results, one displayed. The counters exist
        // because this failure is invisible in the output — a collapsed list looks like a correct one.
        Assert.Equal(2, result.Results);
        Assert.Equal(1, result.DistinctRuleLocationKeys);
        Assert.True(result.Collapses);
        Assert.Contains("WOULD COLLAPSE", result.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(GrypeRuleIdScope.AdvisoryPackageVersion, "GHSA-1/vite@5.4.21")]
    [InlineData(GrypeRuleIdScope.AdvisoryPackage, "GHSA-1/vite")]
    [InlineData(GrypeRuleIdScope.Advisory, "GHSA-1")]
    public void Rule_Id_Scope_Controls_Identity(GrypeRuleIdScope scope, string expected)
        => Assert.Equal(expected, GrypeSarif.RuleIdFor(scope, "GHSA-1", "vite", "5.4.21"));

    // ─── defect 4: a fingerprint must identify the finding ────────────────

    [Fact]
    public void Two_Advisories_Against_One_Package_Version_Get_Different_Fingerprints()
    {
        // grype's primaryLocationLineHash was shared by 35 different advisories against hono 4.12.3,
        // so a consumer deduplicating on fingerprints — their whole purpose — collapsed 299 results
        // to 62.
        var result = Convert(Report(
            Match(advisory: "GHSA-aaaa", package: "hono", version: "4.12.3"),
            Match(advisory: "GHSA-bbbb", package: "hono", version: "4.12.3")));

        Assert.Equal(2, result.DistinctFingerprints);
        var fingerprints = Results(result).Select(r => r.PartialFingerprints![GrypeSarif.FingerprintAlgorithm]).ToArray();
        Assert.NotEqual(fingerprints[0], fingerprints[1]);
        Assert.All(fingerprints, f => Assert.Matches("^[0-9a-f]{64}$", f));
    }

    [Fact]
    public void A_Fingerprint_Is_Stable_Across_Runs()
    {
        var first = Convert(Report(Match())).Log.Runs[0].Results![0].PartialFingerprints![GrypeSarif.FingerprintAlgorithm];
        var second = Convert(Report(Match())).Log.Runs[0].Results![0].PartialFingerprints![GrypeSarif.FingerprintAlgorithm];

        Assert.Equal(first, second);
    }

    [Fact]
    public void The_Same_Package_Version_In_Two_Lock_Files_Stays_Two_Findings()
    {
        // Two ecosystems vendoring the same package is two things to fix, in two files.
        var result = Convert(Report(
            Match(location: "/src/repo/frontend/pnpm-lock.yaml"),
            Match(location: "/src/repo/api/package-lock.json")));

        Assert.Equal(2, result.DistinctFingerprints);
        Assert.Equal(2, result.DistinctRuleLocationKeys);
        // One rule, because it is the same advisory against the same package version.
        Assert.Single(result.Log.Runs[0].Tool.Driver.Rules!);
    }

    // ─── defect 3: repository-relative locations ──────────────────────────

    [Fact]
    public void Locations_Are_Repository_Relative()
    {
        var result = Convert(Report(Match()));

        var location = Results(result)[0].Locations![0].PhysicalLocation!.ArtifactLocation!;
        Assert.Equal("frontend/pnpm-lock.yaml", location.Uri);
        Assert.Null(location.UriBaseId);
        Assert.Empty(result.UnrootedLocations);
    }

    // Path relativization itself now lives in Tamp.Core's RepositoryPath and is tested there
    // (tamp-grype#9); these cover the policy this converter applies on top of it.

    [Theory]
    // syft records locations against the scan's virtual filesystem, so a lockfile at the root of the
    // scanned tree is "/pnpm-lock.yaml" and "/" is the root that describes it. That was the one
    // SourceRoot value that did not work (#9).
    [InlineData("/pnpm-lock.yaml", "/", "pnpm-lock.yaml")]
    [InlineData("/frontend/pnpm-lock.yaml", "/", "frontend/pnpm-lock.yaml")]
    [InlineData("/src/repo/go.mod", "/src/repo", "go.mod")]
    public void A_Location_Becomes_Repository_Relative(string location, string root, string expected)
    {
        var result = Convert(Report(Match(location: location)), new GrypeSarifOptions { SourceRoot = root });

        Assert.Equal(expected, Results(result)[0].Locations![0].PhysicalLocation!.ArtifactLocation!.Uri);
        Assert.Empty(result.UnrootedLocations);
    }

    [Fact]
    public void A_Virtual_Root_Converts_Every_Location()
    {
        var result = Convert(Report(
            Match(location: "/frontend/pnpm-lock.yaml"),
            Match(advisory: "GHSA-zzzz", location: "/api/package-lock.json")),
            new GrypeSarifOptions { SourceRoot = "/" });

        Assert.Empty(result.UnrootedLocations);
        Assert.Equal(
            ["api/package-lock.json", "frontend/pnpm-lock.yaml"],
            Results(result).Select(r => r.Locations![0].PhysicalLocation!.ArtifactLocation!.Uri).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void An_Unrooted_Location_Fails_By_Default()
    {
        // Emitting it absolute means the SARIF ingests and anchors nothing, and the only way a
        // caller learned of it before was by inspecting UnrootedLocations afterwards (#9).
        var ex = Assert.Throws<InvalidOperationException>(
            () => Convert(Report(Match(location: "/pnpm-lock.yaml")), new GrypeSarifOptions { SourceRoot = "/src/repo" }));

        Assert.Contains("same space", ex.Message, StringComparison.Ordinal);
        Assert.Contains("anchor to nothing", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_Unrooted_Location_Can_Be_Emitted_As_Reported()
    {
        // Lenient mode keeps the awkward absolute path: losing the only location a human has for a
        // vulnerability is worse than an ugly one. It is still listed.
        var result = Convert(Report(Match(location: "/elsewhere/go.mod")), Lenient());

        Assert.Equal("/elsewhere/go.mod", Results(result)[0].Locations![0].PhysicalLocation!.ArtifactLocation!.Uri);
        Assert.Equal(["/elsewhere/go.mod"], result.UnrootedLocations);
    }

    [Fact]
    public void A_Location_Outside_The_Source_Root_Is_Reported()
    {
        var result = Convert(Report(Match(location: "/opt/cache/node_modules/.pnpm-lock.yaml")), Lenient());

        Assert.Single(result.UnrootedLocations);
        Assert.Contains("1 unrooted location(s)", result.ToString(), StringComparison.Ordinal);
        // Not a collapse — one result, one key. The two problems are counted separately.
        Assert.False(result.Collapses);
    }

    [Fact]
    public void A_Uri_Base_Id_Is_Opt_In()
    {
        var result = Convert(Report(Match()), new GrypeSarifOptions { SourceRoot = Root, EmitUriBaseId = true });

        Assert.Equal(GrypeSarif.UriBaseId, Results(result)[0].Locations![0].PhysicalLocation!.ArtifactLocation!.UriBaseId);
    }

    [Fact]
    public void The_Purl_Travels_As_A_Logical_Location()
    {
        // The machine-readable identity of the affected component, so a consumer that only reads
        // locations still sees which version is affected.
        var logical = Results(Convert(Report(Match())))[0].Locations![0].LogicalLocations![0];

        Assert.Equal("pkg:npm/vite@5.4.21", logical.FullyQualifiedName);
        Assert.Equal("vite@5.4.21", logical.Name);
        Assert.Equal("package", logical.Kind);
    }

    [Fact]
    public void A_Match_With_No_Location_Still_Becomes_A_Result()
    {
        var result = Convert(Report(Match(location: null)));

        Assert.Single(Results(result));
        Assert.Null(Results(result)[0].Locations);
        Assert.Empty(result.Dropped);
    }

    // ─── defect 2: severity semantics, stated ─────────────────────────────

    [Fact]
    public void Under_Cvss_Governance_The_Level_And_The_Number_Cannot_Disagree()
    {
        // The reproduced disagreement: grype labelled this Medium while carrying CVSS 7.5, which a
        // consumer bucketing the number displays as High. Both come from the number here, so the
        // displayed severity is the one the level encodes.
        var result = Convert(Report(Match(severity: "Medium", cvss: 7.5)));

        var sarifResult = Results(result)[0];
        Assert.Equal(SarifLevel.Error, sarifResult.Level);
        Assert.Equal("7.5", Property(RuleFor(result, sarifResult), "security-severity"));
        // Nothing is lost: grype's own label is still recorded.
        Assert.Equal("Medium", Property(sarifResult, "grype.severity"));
    }

    [Fact]
    public void Under_Scanner_Label_Governance_The_Number_Is_Omitted_Not_Rewritten()
    {
        var result = Convert(Report(Match(severity: "Medium", cvss: 7.5)),
            new GrypeSarifOptions { SourceRoot = Root, Severity = GrypeSeverityGovernance.ScannerLabel });

        var sarifResult = Results(result)[0];
        // The label governs, so the level is the label's. A fabricated score to match it would be the
        // silent threshold change the issue forbids; omitting the field is honest.
        Assert.Equal(SarifLevel.Warning, sarifResult.Level);
        Assert.Null(Property(RuleFor(result, sarifResult), "security-severity"));
        // The real CVSS score is still available for reference.
        Assert.Equal("7.5", Property(sarifResult, "grype.cvssBaseScore"));
    }

    [Theory]
    // The CVSS specification's own bands, not a Tamp invention.
    [InlineData(9.8, SarifLevel.Error)]
    [InlineData(7.0, SarifLevel.Error)]
    [InlineData(6.9, SarifLevel.Warning)]
    [InlineData(4.0, SarifLevel.Warning)]
    [InlineData(3.9, SarifLevel.Note)]
    [InlineData(0.1, SarifLevel.Note)]
    [InlineData(0.0, SarifLevel.None)]
    public void Cvss_Scores_Map_To_The_Specified_Bands(double score, SarifLevel expected)
        => Assert.Equal(expected, GrypeSarif.LevelFromScore(score));

    [Theory]
    [InlineData("Critical", SarifLevel.Error)]
    [InlineData("High", SarifLevel.Error)]
    [InlineData("Medium", SarifLevel.Warning)]
    [InlineData("Low", SarifLevel.Note)]
    [InlineData("Negligible", SarifLevel.Note)]
    // Unknown is reported rather than silently dropped to none.
    [InlineData("Unknown", SarifLevel.Warning)]
    [InlineData(null, SarifLevel.Warning)]
    public void Labels_Map_The_Way_Grype_Maps_Them(string? label, SarifLevel expected)
        => Assert.Equal(expected, GrypeSarif.LevelFromLabel(label));

    [Fact]
    public void With_No_Cvss_Score_Cvss_Governance_Falls_Back_To_The_Label()
    {
        var result = Convert(Report(Match(severity: "Low", cvss: null)));

        var sarifResult = Results(result)[0];
        Assert.Equal(SarifLevel.Note, sarifResult.Level);
        Assert.Null(Property(RuleFor(result, sarifResult), "security-severity"));
    }

    [Fact]
    public void A_Primary_Cvss_Entry_Wins_Over_A_Secondary_One()
    {
        var json = Report(Match()).Replace(
            """[ { "type": "Primary", "version": "3.1",""",
            """[ { "type": "Secondary", "version": "4.0", "vector": "CVSS:4.0/AV:N", "metrics": { "baseScore": 2.0 } }, { "type": "Primary", "version": "3.1",""",
            StringComparison.Ordinal);

        var result = Convert(json);
        Assert.Equal("7.5", Property(Results(result)[0], "grype.cvssBaseScore"));
    }

    // ─── nothing is filtered or invented ──────────────────────────────────

    [Fact]
    public void Every_Match_Becomes_Exactly_One_Result()
    {
        var result = Convert(Report(Match(version: "1.0.0"), Match(version: "2.0.0"), Match(advisory: "GHSA-zzzz")));

        // grype decides what is a finding; this decides how a finding is described.
        Assert.Equal(3, result.Matches);
        Assert.Equal(3, result.Results);
        Assert.Empty(result.Dropped);
    }

    [Fact]
    public void The_Facts_Grype_Reported_Travel_With_The_Result()
    {
        var sarifResult = Results(Convert(Report(Match())))[0];

        Assert.Equal("vite", Property(sarifResult, "grype.package"));
        Assert.Equal("5.4.21", Property(sarifResult, "grype.version"));
        Assert.Equal("npm", Property(sarifResult, "grype.packageType"));
        Assert.Equal("pkg:npm/vite@5.4.21", Property(sarifResult, "grype.purl"));
        Assert.Equal("fixed", Property(sarifResult, "grype.fixState"));
        Assert.Equal("7.3.2", Property(sarifResult, "grype.fixVersions"));
        Assert.Equal("javascript-matcher", Property(sarifResult, "grype.matcher"));
        Assert.Equal("GHSA-587h-7wmj-h5pm", Property(sarifResult, "grype.advisory"));
        Assert.Contains("severity:high", sarifResult.Properties!.Tags!);
        Assert.Contains("fix:fixed", sarifResult.Properties.Tags!);
    }

    [Fact]
    public void The_Message_Names_The_Version_And_The_Fix()
    {
        var text = Results(Convert(Report(Match())))[0].Message.Text!;

        Assert.Contains("GHSA-587h-7wmj-h5pm", text, StringComparison.Ordinal);
        Assert.Contains("vite 5.4.21", text, StringComparison.Ordinal);
        Assert.Contains("frontend/pnpm-lock.yaml", text, StringComparison.Ordinal);
        Assert.Contains("Fixed in 7.3.2", text, StringComparison.Ordinal);
        // The absolute path grype reported must not survive into the prose either.
        Assert.DoesNotContain("/src/repo/frontend", text, StringComparison.Ordinal);
    }

    [Fact]
    public void An_Unfixed_Vulnerability_Says_So()
    {
        var text = Results(Convert(Report(Match(fixState: "not-fixed", fixVersion: null))))[0].Message.Text!;

        Assert.Contains("No fix available", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_Driver_Identifies_Grype_And_Its_Version()
    {
        var driver = Convert(Report(Match())).Log.Runs[0].Tool.Driver;

        Assert.Equal("grype", driver.Name);
        Assert.Equal("0.112.0", driver.Version);
        Assert.Equal("0.112.0", Convert(Report(Match())).GrypeVersion);
    }

    [Fact]
    public void A_Rule_Carries_The_Advisory_Link_And_Description()
    {
        var result = Convert(Report(Match()));
        var rule = RuleFor(result, Results(result)[0]);

        Assert.Equal("https://github.com/advisories/GHSA-587h-7wmj-h5pm", rule.HelpUri);
        Assert.Contains("vite 5.4.21", rule.ShortDescription!.Text, StringComparison.Ordinal);
        Assert.Equal("A vulnerability in vite.", rule.FullDescription!.Text);
        // Identifier-like, as SARIF wants rule names to be.
        Assert.Matches("^[A-Za-z0-9_]+$", rule.Name);
    }

    [Fact]
    public void An_Empty_Scan_Is_An_Empty_Run_Not_A_Missing_File()
    {
        var result = Convert(Report());

        Assert.Equal(0, result.Matches);
        Assert.Empty(Results(result));
        Assert.Null(result.Log.Runs[0].Tool.Driver.Rules);
    }

    // ─── refusing the wrong input ─────────────────────────────────────────

    [Fact]
    public void Grypes_Own_Sarif_Is_Refused_As_Input()
    {
        // The likeliest mistake: capturing `-o sarif` and feeding it here. It has no `matches`, and
        // repairing it is exactly what this conversion exists to avoid.
        var sarif = """{ "version": "2.1.0", "runs": [ { "tool": { "driver": { "name": "grype" } }, "results": [] } ] }""";

        var ex = Assert.Throws<InvalidDataException>(() => Convert(sarif));
        Assert.Contains("-o json", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invalid_Json_Says_So()
        => Assert.Throws<InvalidDataException>(() => Convert("{ not json"));

    [Fact]
    public void A_Match_With_No_Advisory_Id_Is_Dropped_And_Counted()
    {
        var json = Report(Match()).Replace("\"id\": \"GHSA-587h-7wmj-h5pm\"", "\"id\": \"\"", StringComparison.Ordinal);

        var result = Convert(json);
        Assert.Equal(1, result.Matches);
        Assert.Equal(0, result.Results);
        Assert.Single(result.Dropped);
    }

    [Fact]
    public void Null_Input_Is_Refused()
        => Assert.Throws<ArgumentNullException>(() => GrypeSarif.FromJson(null!));

    [Fact]
    public void Without_A_Source_Root_The_Default_Fails_Loudly()
    {
        // Previously this silently emitted the absolute path with nothing added to UnrootedLocations
        // — the quietest form of the #9 failure: a report that ingests and anchors nothing, with no
        // diagnostic at all.
        var ex = Assert.Throws<InvalidOperationException>(() => GrypeSarif.FromJson(Report(Match())));
        Assert.Contains("SourceRoot", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_Are_Optional_When_Strictness_Is_Off()
    {
        var result = GrypeSarif.FromJson(Report(Match()), new GrypeSarifOptions { ThrowOnUnrootedPaths = false });

        Assert.Equal("/src/repo/frontend/pnpm-lock.yaml", Results(result)[0].Locations![0].PhysicalLocation!.ArtifactLocation!.Uri);
        Assert.Single(result.UnrootedLocations);
    }
}
