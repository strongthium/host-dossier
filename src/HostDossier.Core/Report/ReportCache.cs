namespace Strongthium.HostDossier;

/// <summary>A report kept from an earlier lookup.</summary>
public sealed record CachedReport(string Target, DateTimeOffset LookedUp, long Bytes);

/// <summary>
/// The last report of each thing looked up, one JSON file a target, so that looking it up again is instant and earlier
/// lookups can be gone back to. Each file's name is its target, and its time is when the lookup finished, so the list
/// can be shown without reading every report.
/// </summary>
public sealed class ReportCache(string directory, int keep = 500)
{
    public static string DefaultDirectory => Path.Combine(Settings.DefaultDirectory, "reports");

    private string FileOf(string target) => Path.Combine(directory, Uri.EscapeDataString(target) + ".json");

    public void Save(Dossier dossier)
    {
        Directory.CreateDirectory(directory);
        var file = FileOf(dossier.Target.Name);
        var part = file + ".part";
        File.WriteAllText(part, Export.ToJson(dossier));
        File.SetLastWriteTimeUtc(part, (dossier.Finished ?? DateTimeOffset.UtcNow).UtcDateTime);
        File.Move(part, file, overwrite: true);
        foreach (var old in List().Skip(keep)) Remove(old.Target);
    }

    /// <summary>The report of a target, if there's one no older than <paramref name="maxAge"/>.</summary>
    public CachedReport? Find(string target, TimeSpan? maxAge = null)
    {
        var file = new FileInfo(FileOf(target));
        if (!file.Exists) return null;
        var lookedUp = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);
        if (maxAge is { } age && DateTimeOffset.UtcNow - lookedUp > age) return null;
        return new CachedReport(target, lookedUp, file.Length);
    }

    /// <summary>A kept report. Null when there's none or it can't be read: then it's only not in the cache.</summary>
    public Dossier? Load(string target)
    {
        try
        {
            return Export.FromJson(File.ReadAllText(FileOf(target)));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>What's kept, the latest first.</summary>
    public List<CachedReport> List()
    {
        if (!Directory.Exists(directory)) return [];
        return new DirectoryInfo(directory).EnumerateFiles("*.json")
            .Select(f => new CachedReport(Uri.UnescapeDataString(Path.GetFileNameWithoutExtension(f.Name)), new DateTimeOffset(f.LastWriteTimeUtc, TimeSpan.Zero), f.Length))
            .OrderByDescending(r => r.LookedUp)
            .ToList();
    }

    public void Remove(string target) => File.Delete(FileOf(target));

    public void Clear()
    {
        foreach (var report in List()) Remove(report.Target);
    }
}
