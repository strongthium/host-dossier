namespace Strongthium.HostDossier;

/// <summary>
/// One piece of a table or a list of facts. What the piece means travels with it, so that the window can draw a link
/// or a flag and a text report can write the plain words.
/// </summary>
public sealed record Cell(string Text)
{
    /// <summary>A domain or address that can be looked up in turn.</summary>
    public string? Lookup { get; init; }
    public string? Url { get; init; }
    /// <summary>Two letters, for a flag beside the text.</summary>
    public string? Country { get; init; }
    public Level? Level { get; init; }
    public int Indent { get; init; }
    public bool Mono { get; init; }

    public static implicit operator Cell(string? text) => new(text ?? "");

    public static Cell Name(string? name) => string.IsNullOrEmpty(name) ? new Cell("") : new Cell(name) { Lookup = name, Mono = true };
    public static Cell Status(Level level, string text) => new(text) { Level = level };
    public static Cell Code(string? text) => new(text ?? "") { Mono = true };
    public static Cell Link(string url) => new(url) { Url = url };

    public static Cell Place(string? country) => string.IsNullOrEmpty(country) ? new Cell("") : new Cell(Countries.Name(country)) { Country = country };
}

public abstract record Block;

public sealed record HeadingBlock(string Text, string? Caption = null) : Block;

public sealed record FindingsBlock(IReadOnlyList<Finding> Findings) : Block;

public sealed record FactsBlock(IReadOnlyList<(string Label, Cell Value)> Facts) : Block;

public sealed record TableBlock(IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<Cell>> Rows, string? Empty = null) : Block;

/// <summary>Text as it came, shut until it's asked for: a WHOIS answer, a record.</summary>
public sealed record RawBlock(string Title, string Text) : Block;

public sealed record NoteBlock(string Text) : Block;

/// <summary>One page of the report.</summary>
public sealed record ReportPage(string Key, string Title, string Icon, Level? Worst, string? Badge, IReadOnlyList<Block> Blocks);

public static class Countries
{
    public static string Name(string code)
    {
        try
        {
            return new System.Globalization.RegionInfo(code).EnglishName;
        }
        catch (ArgumentException)
        {
            return code;
        }
    }
}
