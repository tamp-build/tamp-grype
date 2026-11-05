using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tamp.Sarif;

namespace Tamp.Grype;

/// <summary>
/// Builds SARIF 2.1.0 from grype's <b>JSON</b> output, so distinct affected package versions survive
/// into a consumer's UI, locations anchor to files in the repository, and the governing severity is
/// stated rather than left to whichever of grype's two severities a consumer happens to read.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why not post-process grype's own SARIF.</b> Three defects in it survive into GitLab and
/// misrepresent the scan, and the third makes patching unsound. Measured on grype 0.112.0 over 299
/// matches:
/// </para>
/// <list type="number">
/// <item>
/// <b>Distinct versions collapse.</b> <c>GHSA-587h-7wmj-h5pm-vite</c> carried two results — vite
/// 5.4.21 and vite 7.3.1 — under one rule id at one location. 299 results reduce to 268 distinct
/// <c>(ruleId, location)</c> keys, so 31 affected package-versions disappear in any consumer that
/// deduplicates on that pair. One displayed finding is not one affected version.
/// </item>
/// <item>
/// <b>Fingerprints identify the package, not the finding.</b> grype's
/// <c>partialFingerprints.primaryLocationLineHash</c> was shared by 35 different advisories against
/// <c>hono 4.12.3</c>. 278 of 299 results carried a fingerprint duplicated by another result, so a
/// consumer deduplicating on fingerprints — their whole purpose — collapses 299 findings to 62.
/// </item>
/// <item>
/// <b>The version is only in the message text.</b> A result's rule listed
/// <c>purls: ["pkg:npm/vite@5.4.21"]</c> while one of its two results was vite <b>7.3.1</b>, so the
/// rule's own metadata is wrong for that result and the only per-result carrier of the version is the
/// English message string. Repairing identity from a prose sentence would make correctness depend on
/// grype's message wording.
/// </item>
/// </list>
/// <para>
/// grype's JSON carries all of it structurally — <c>artifact.name</c>, <c>artifact.version</c>,
/// <c>artifact.purl</c>, <c>artifact.locations[].path</c>, <c>vulnerability.severity</c>,
/// <c>vulnerability.cvss[].metrics.baseScore</c>, <c>fix</c> — and yields the same 299 matches. So the
/// SARIF is built from that, and nothing is recovered by parsing prose.
/// </para>
/// <para>
/// <b>What is not changed.</b> No severity threshold is moved, no score is invented, and no match is
/// filtered. grype decides what is a finding; this decides how a finding is described.
/// </para>
/// </remarks>
public static class GrypeSarif
{
    /// <summary>The fingerprint algorithm name emitted in <c>partialFingerprints</c>.</summary>
    public const string FingerprintAlgorithm = "tamp-grype-match-v1";

    /// <summary>The <c>originalUriBaseIds</c> symbol used when <see cref="GrypeSarifOptions.EmitUriBaseId"/> is set.</summary>
    public const string UriBaseId = "SRCROOT";

    /// <summary>
    /// Convert grype's JSON report to SARIF.
    /// </summary>
    /// <param name="grypeJson">The output of <c>grype … -o json</c>.</param>
    /// <param name="options">Source root, severity governance, rule-id scope.</param>
    /// <exception cref="InvalidDataException">
    /// The input is not a grype JSON report — most often SARIF or a table was captured instead.
    /// </exception>
    public static GrypeSarifResult FromJson(string grypeJson, GrypeSarifOptions? options = null)
    {
        if (grypeJson is null) throw new ArgumentNullException(nameof(grypeJson));
        options ??= new GrypeSarifOptions();

        JsonNode? parsed;
        try { parsed = JsonNode.Parse(grypeJson); }
        catch (JsonException ex) { throw new InvalidDataException($"Not valid JSON, so not a grype report: {ex.Message}", ex); }

        if (parsed is not JsonObject report)
            throw new InvalidDataException("A grype JSON report must be a JSON object.");
        if (report["matches"] is not JsonArray matches)
            throw new InvalidDataException(
                "No 'matches' array: this is not a grype JSON report. Capture the scan with `-o json` — "
                + "grype's own SARIF cannot be used as input, which is the point of this conversion.");

        var grypeVersion = (string?)report["descriptor"]?["version"];
        var root = RepositoryPath.NormalizeRoot(options.SourceRoot);

        var rules = new Dictionary<string, SarifRule>(StringComparer.Ordinal);
        var results = new List<SarifResult>();
        var unrooted = new SortedSet<string>(StringComparer.Ordinal);
        var dropped = new List<string>();
        var ruleLocationKeys = new HashSet<string>(StringComparer.Ordinal);
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        var matchCount = 0;

        foreach (var match in matches.OfType<JsonObject>())
        {
            matchCount++;
            var vulnerability = match["vulnerability"] as JsonObject;
            var artifact = match["artifact"] as JsonObject;

            if ((string?)vulnerability?["id"] is not { Length: > 0 } advisory)
            {
                dropped.Add($"match {matchCount}: no vulnerability.id");
                continue;
            }

            var package = (string?)artifact?["name"] ?? "(unknown package)";
            var version = (string?)artifact?["version"] ?? "(unknown version)";
            var purl = (string?)artifact?["purl"];
            var packageType = (string?)artifact?["type"];
            var language = (string?)artifact?["language"];
            var label = (string?)vulnerability["severity"];
            var description = (string?)vulnerability["description"];
            var dataSource = (string?)vulnerability["dataSource"];
            var namespaceName = (string?)vulnerability["namespace"];
            var (cvssScore, cvssVector, cvssVersion) = BestCvss(vulnerability["cvss"] as JsonArray);
            var fix = vulnerability["fix"] as JsonObject;
            var fixState = (string?)fix?["state"];
            var fixVersions = (fix?["versions"] as JsonArray)
                ?.Select(v => (string?)v)
                .Where(v => !string.IsNullOrEmpty(v))
                .Select(v => v!)
                .ToArray() ?? [];
            var matcher = (string?)(match["matchDetails"] as JsonArray)?.FirstOrDefault()?["matcher"];

            var rawLocation = ((artifact?["locations"] as JsonArray)?.FirstOrDefault() as JsonObject) is { } location
                ? (string?)location["path"]
                : null;
            string? file = null;
            if (rawLocation is { Length: > 0 })
            {
                // Core returns null for "not under this root". The policy here differs from the SBOM
                // profiler's on purpose: keep the awkward absolute path rather than drop the only
                // location a human has for a vulnerability — but record it, so a caller can tell.
                file = RepositoryPath.Relativize(rawLocation, root)
                    ?? rawLocation.Replace('\\', '/');
                if (RepositoryPath.IsAbsolute(file)) unrooted.Add(rawLocation);
            }

            var ruleId = RuleIdFor(options.RuleIdScope, advisory, package, version);

            // The level and the numeric severity come from the same source, so they cannot disagree.
            var level = options.Severity == GrypeSeverityGovernance.Cvss && cvssScore is { } score
                ? LevelFromScore(score)
                : LevelFromLabel(label);

            if (!rules.ContainsKey(ruleId))
                rules[ruleId] = BuildRule(ruleId, advisory, package, version, label, description, dataSource, level, cvssScore, options);

            // Identity over everything that makes this finding this finding: the advisory, the exact
            // package version (via purl where grype gave one), and where it was found. Distinguishes
            // both axes grype's own fingerprint collapses.
            var fingerprint = Fingerprint(advisory, purl ?? $"{packageType}/{package}@{version}", file ?? "");
            fingerprints.Add(fingerprint);
            ruleLocationKeys.Add($"{ruleId}\u001f{file ?? ""}");

            var properties = new SarifPropertyBag
            {
                Tags = BuildTags(label, fixState),
                AdditionalProperties = BuildProperties(
                    label, cvssScore, cvssVector, cvssVersion, purl, package, version,
                    packageType, language, fixState, fixVersions, matcher, namespaceName, advisory),
            };

            results.Add(new SarifResult
            {
                RuleId = ruleId,
                Level = level,
                Message = new SarifMessage { Text = BuildMessage(advisory, label, package, version, packageType, file, fixState, fixVersions) },
                Locations = file is null ? null :
                [
                    new SarifLocation
                    {
                        PhysicalLocation = new SarifPhysicalLocation
                        {
                            ArtifactLocation = new SarifArtifactLocation
                            {
                                Uri = file,
                                UriBaseId = options.EmitUriBaseId ? UriBaseId : null,
                            },
                        },
                        // The purl is the machine-readable identity of the affected component, and it
                        // is what carries the version when a consumer only looks at locations.
                        LogicalLocations = purl is null ? null :
                        [
                            new SarifLogicalLocation
                            {
                                Name = $"{package}@{version}",
                                FullyQualifiedName = purl,
                                Kind = "package",
                            },
                        ],
                    },
                ],
                PartialFingerprints = new Dictionary<string, string> { [FingerprintAlgorithm] = fingerprint },
                Properties = properties,
            });
        }

        if (options.ThrowOnUnrootedPaths && unrooted.Count > 0)
            throw new InvalidOperationException(
                $"{unrooted.Count} location(s) are not under SourceRoot '{options.SourceRoot}', so the SARIF would "
                + "carry absolute paths and the findings would anchor to nothing in the repository. "
                + $"First: '{unrooted.First()}'. SourceRoot has to be expressed in the same space as the locations "
                + "grype reported: a virtual path like '/pnpm-lock.yaml' needs SourceRoot = \"/\", and no filesystem "
                + "directory will ever contain it. Set ThrowOnUnrootedPaths = false to emit them as-is instead.");

        var log = new SarifLog
        {
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifToolComponent
                        {
                            Name = "grype",
                            Version = grypeVersion,
                            InformationUri = "https://github.com/anchore/grype",
                            Rules = rules.Count > 0 ? [.. rules.Values.OrderBy(x => x.Id, StringComparer.Ordinal)] : null,
                        },
                    },
                    Results = results,
                },
            ],
        };

        return new GrypeSarifResult
        {
            Log = log,
            GrypeVersion = grypeVersion,
            Matches = matchCount,
            Results = results.Count,
            DistinctRuleLocationKeys = ruleLocationKeys.Count,
            DistinctFingerprints = fingerprints.Count,
            UnrootedLocations = [.. unrooted],
            Dropped = dropped,
        };
    }

    /// <summary>
    /// <see cref="FromJson"/> over files: read grype's JSON from <paramref name="input"/> and write the
    /// SARIF to <paramref name="output"/>. grype's JSON is left in place — it is the richer artifact
    /// and worth keeping alongside.
    /// </summary>
    public static GrypeSarifResult ConvertFile(AbsolutePath input, AbsolutePath output, GrypeSarifOptions? options = null)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));

        var result = FromJson(File.ReadAllText(input.Value), options);
        var directory = Path.GetDirectoryName(output.Value);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory!);
        SarifWriter.WriteToFile(result.Log, output);
        return result;
    }

    /// <summary>The rule id for a finding, at the configured scope.</summary>
    internal static string RuleIdFor(GrypeRuleIdScope scope, string advisory, string package, string version) => scope switch
    {
        GrypeRuleIdScope.Advisory => advisory,
        GrypeRuleIdScope.AdvisoryPackage => $"{advisory}/{package}",
        GrypeRuleIdScope.AdvisoryPackageVersion => $"{advisory}/{package}@{version}",
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown rule-id scope."),
    };

    private static SarifRule BuildRule(
        string ruleId, string advisory, string package, string version, string? label,
        string? description, string? dataSource, SarifLevel level, double? cvssScore, GrypeSarifOptions options)
    {
        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        // Under ScannerLabel governance the numeric field is omitted rather than rewritten: a consumer
        // then falls back to `level`, which is the label. Inventing a score to match the label would be
        // exactly the silent threshold change this is meant to avoid.
        if (options.Severity == GrypeSeverityGovernance.Cvss && cvssScore is { } score)
            properties["security-severity"] = Json(score.ToString("0.0", CultureInfo.InvariantCulture));

        properties["grype.advisory"] = Json(advisory);
        if (label is not null) properties["grype.severity"] = Json(label);

        return new SarifRule
        {
            Id = ruleId,
            Name = SanitizeRuleName(advisory),
            ShortDescription = new SarifMultiformatMessage
            {
                Text = $"{advisory} affects {package} {version}"
                    + (label is not null ? $" ({label.ToLowerInvariant()})" : ""),
            },
            FullDescription = description is { Length: > 0 }
                ? new SarifMultiformatMessage { Text = description }
                : null,
            HelpUri = dataSource,
            DefaultConfiguration = new SarifReportingConfiguration { Level = level },
            Properties = new SarifPropertyBag { AdditionalProperties = properties },
        };
    }

    private static string BuildMessage(
        string advisory, string? label, string package, string version, string? packageType,
        string? file, string? fixState, string[] fixVersions)
    {
        var builder = new StringBuilder();
        builder.Append(advisory);
        if (label is not null) builder.Append(" (").Append(label.ToLowerInvariant()).Append(')');
        builder.Append(" in ");
        if (packageType is { Length: > 0 }) builder.Append(packageType).Append(' ');
        builder.Append("package ").Append(package).Append(' ').Append(version);
        if (file is { Length: > 0 }) builder.Append(", from ").Append(file);
        builder.Append('.');

        if (fixVersions.Length > 0)
            builder.Append(" Fixed in ").Append(string.Join(", ", fixVersions)).Append('.');
        else if (string.Equals(fixState, "not-fixed", StringComparison.OrdinalIgnoreCase))
            builder.Append(" No fix available.");
        else if (string.Equals(fixState, "wont-fix", StringComparison.OrdinalIgnoreCase))
            builder.Append(" Upstream will not fix this.");

        return builder.ToString();
    }

    private static IReadOnlyList<string> BuildTags(string? label, string? fixState)
    {
        var tags = new List<string> { "security", "vulnerability" };
        if (label is { Length: > 0 }) tags.Add($"severity:{label.ToLowerInvariant()}");
        if (fixState is { Length: > 0 }) tags.Add($"fix:{fixState.ToLowerInvariant()}");
        return tags;
    }

    private static Dictionary<string, JsonElement> BuildProperties(
        string? label, double? cvssScore, string? cvssVector, string? cvssVersion, string? purl,
        string package, string version, string? packageType, string? language, string? fixState,
        string[] fixVersions, string? matcher, string? namespaceName, string advisory)
    {
        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            // Both severities travel with every result, whichever one governs, so a consumer or a
            // triage script can see the disagreement instead of inheriting it silently.
            ["grype.advisory"] = Json(advisory),
            ["grype.package"] = Json(package),
            ["grype.version"] = Json(version),
        };
        if (label is not null) properties["grype.severity"] = Json(label);
        if (cvssScore is { } score) properties["grype.cvssBaseScore"] = Json(score.ToString("0.0", CultureInfo.InvariantCulture));
        if (cvssVector is not null) properties["grype.cvssVector"] = Json(cvssVector);
        if (cvssVersion is not null) properties["grype.cvssVersion"] = Json(cvssVersion);
        if (purl is not null) properties["grype.purl"] = Json(purl);
        if (packageType is not null) properties["grype.packageType"] = Json(packageType);
        if (language is { Length: > 0 }) properties["grype.language"] = Json(language);
        if (fixState is not null) properties["grype.fixState"] = Json(fixState);
        if (fixVersions.Length > 0) properties["grype.fixVersions"] = Json(string.Join(", ", fixVersions));
        if (matcher is not null) properties["grype.matcher"] = Json(matcher);
        if (namespaceName is not null) properties["grype.namespace"] = Json(namespaceName);
        return properties;
    }

    /// <summary>
    /// The CVSS entry that should govern: a <c>Primary</c> entry before a secondary one, and the
    /// highest spec version within that, which is how grype itself orders its own precedence.
    /// </summary>
    internal static (double? Score, string? Vector, string? Version) BestCvss(JsonArray? cvss)
    {
        if (cvss is null) return (null, null, null);

        JsonObject? best = null;
        var bestRank = (-1, 0.0);
        foreach (var entry in cvss.OfType<JsonObject>())
        {
            if ((double?)entry["metrics"]?["baseScore"] is null) continue;
            var primary = string.Equals((string?)entry["type"], "Primary", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            _ = double.TryParse((string?)entry["version"], NumberStyles.Float, CultureInfo.InvariantCulture, out var specVersion);
            var rank = (primary, specVersion);
            if (rank.CompareTo(bestRank) <= 0) continue;
            bestRank = rank;
            best = entry;
        }

        return best is null
            ? (null, null, null)
            : ((double?)best["metrics"]!["baseScore"], (string?)best["vector"], (string?)best["version"]);
    }

    /// <summary>
    /// CVSS v3/v4 qualitative bands, as the specification defines them: 9.0+ critical, 7.0+ high,
    /// 4.0+ medium, 0.1+ low. Not a Tamp invention and not a threshold change — the bands are what a
    /// consumer bucketing <c>security-severity</c> already applies.
    /// </summary>
    internal static SarifLevel LevelFromScore(double score) => score switch
    {
        >= 7.0 => SarifLevel.Error,
        >= 4.0 => SarifLevel.Warning,
        > 0.0 => SarifLevel.Note,
        _ => SarifLevel.None,
    };

    /// <summary>grype's own severity label, mapped the way grype's own SARIF maps it.</summary>
    internal static SarifLevel LevelFromLabel(string? label) => label?.ToLowerInvariant() switch
    {
        "critical" or "high" => SarifLevel.Error,
        "medium" => SarifLevel.Warning,
        "low" or "negligible" => SarifLevel.Note,
        _ => SarifLevel.Warning,      // Unknown: reported, not silently dropped to none
    };

    /// <summary>
    /// A stable identity for one finding: advisory + exact component + location. Distinguishes two
    /// versions of one package under one advisory, and two advisories against one package version —
    /// the two axes grype's own <c>primaryLocationLineHash</c> collapses.
    /// </summary>
    internal static string Fingerprint(string advisory, string component, string file)
    {
        var material = string.Join('\u001f', FingerprintAlgorithm, advisory, component, file);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    /// <summary>SARIF rule names must be identifier-like; advisory ids carry hyphens.</summary>
    private static string SanitizeRuleName(string advisory)
    {
        var builder = new StringBuilder(advisory.Length);
        foreach (var c in advisory) builder.Append(char.IsLetterOrDigit(c) ? c : '_');
        return builder.ToString();
    }

    private static JsonElement Json(string value) => JsonSerializer.SerializeToElement(value);

}
