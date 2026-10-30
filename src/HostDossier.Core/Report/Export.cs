using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Strongthium.HostDossier;

/// <summary>A dossier as a file: JSON with everything in it, or Markdown laid out like the window.</summary>
public static class Export
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>The model's lists have no setters, so reading fills the ones each new object already has.</summary>
    private static readonly JsonSerializerOptions ReadOptions = new(Options)
    {
        PreferredObjectCreationHandling = JsonObjectCreationHandling.Populate,
        PropertyNameCaseInsensitive = true,
    };

    public static string ToJson(Dossier dossier)
    {
        lock (dossier.Sync) return JsonSerializer.Serialize(dossier, Options);
    }

    /// <summary>Reads back a report saved as JSON. A file that isn't one, whatever it holds, gives an
    /// <see cref="InvalidDataException"/> with something to tell the person.</summary>
    public static Dossier FromJson(string json)
    {
        try
        {
            var dossier = JsonSerializer.Deserialize<Dossier>(json, ReadOptions) ?? throw new InvalidDataException("This file isn't a host-dossier report.");
            // A report saved in the middle of a lookup isn't still looking.
            dossier.Finished ??= dossier.Started;
            return dossier;
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or FormatException or ArgumentException)
        {
            throw new InvalidDataException("This file isn't a host-dossier report saved as JSON.", exception);
        }
    }

    public static string ToMarkdown(Dossier dossier)
    {
        var text = new StringBuilder();
        text.Append("# ").Append(dossier.Target.Name).Append("\n\n");
        text.Append("Looked up ").Append(dossier.Started.ToString("yyyy-MM-dd HH:mm 'UTC'", System.Globalization.CultureInfo.InvariantCulture)).Append(" by host-dossier.\n\n");
        foreach (var page in ReportBuilder.Build(dossier))
        {
            text.Append("## ").Append(page.Title).Append("\n\n");
            Write(text, page.Blocks);
        }
        return text.ToString();
    }

    private static void Write(StringBuilder text, IReadOnlyList<Block> blocks)
    {
        foreach (var block in blocks)
        {
            switch (block)
            {
                case HeadingBlock heading:
                    text.Append("### ").Append(heading.Text).Append("\n\n");
                    if (heading.Caption is { } caption) text.Append(caption).Append("\n\n");
                    break;
                case NoteBlock note:
                    text.Append(note.Text).Append("\n\n");
                    break;
                case FindingsBlock findings:
                    foreach (var finding in findings.Findings)
                    {
                        text.Append("- **").Append(LevelName(finding.Level)).Append("** ").Append(finding.Text).Append('\n');
                    }
                    text.Append('\n');
                    break;
                case FactsBlock facts:
                    foreach (var (label, value) in facts.Facts)
                    {
                        text.Append("- ").Append(label).Append(": ").Append(Plain(value)).Append('\n');
                    }
                    text.Append('\n');
                    break;
                case TableBlock table:
                    if (table.Rows.Count == 0)
                    {
                        if (table.Empty is { } empty) text.Append(empty).Append("\n\n");
                        break;
                    }
                    text.Append("| ").AppendJoin(" | ", table.Columns).Append(" |\n|");
                    foreach (var _ in table.Columns) text.Append("---|");
                    text.Append('\n');
                    foreach (var row in table.Rows)
                    {
                        text.Append("| ").AppendJoin(" | ", row.Select(c => Plain(c).Replace("|", "\\|"))).Append(" |\n");
                    }
                    text.Append('\n');
                    break;
                case RawBlock raw:
                    text.Append("<details><summary>").Append(raw.Title).Append("</summary>\n\n```\n").Append(raw.Text).Append("\n```\n\n</details>\n\n");
                    break;
            }
        }
    }

    private static string Plain(Cell cell) => new string(' ', cell.Indent * 2).Replace(" ", "&nbsp;") + cell.Text.Replace('\n', ' ');

    public static string LevelName(Level level) => level switch
    {
        Level.Good => "Good",
        Level.Info => "Info",
        Level.Notice => "Notice",
        Level.Warning => "Warning",
        _ => "Problem",
    };
}
