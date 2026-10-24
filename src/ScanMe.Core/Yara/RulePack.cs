using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace ScanMe.Core.Yara;

/// <summary>
/// Verpacktes YARA-Regelpaket (Data\yara\rules.bin, erzeugt von tools/update-yara.ps1).
/// gzip + fester Schluesselstrom: kein Schutz vor dem Lesen (der Code ist offen), sondern damit Defender die Datei
/// nicht selbst fuer Malware haelt – die Regeln enthalten zwangslaeufig Zeichenfolgen aus echter Schadsoftware.
/// Entpackt wird nur im Arbeitsspeicher.
/// </summary>
public sealed class RulePack
{
    public sealed record RuleInfo(string Name, int Score, string Source, string Author, string Description);

    private static readonly byte[] Magic = "SMYR1"u8.ToArray();
    private static readonly byte[] Key = "ScanMe rule pack v1"u8.ToArray();

    public string ForgeRelease { get; private init; } = "";
    public string YaraXVersion { get; private init; } = "";
    public string Source { get; private init; } = "";
    public IReadOnlyDictionary<string, RuleInfo> Rules { get; private init; } = new Dictionary<string, RuleInfo>();

    public static RulePack Decode(byte[] file)
    {
        if (file.Length < Magic.Length || !file.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Kein ScanMe-Regelpaket.");
        byte[] data = file[Magic.Length..];
        Transform(data);
        using var gz = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
        using var reader = new StreamReader(gz, Encoding.UTF8);
        return Parse(reader.ReadToEnd());
    }

    /// <summary>Gegenstueck zu tools/update-yara.ps1 (fuer Tests).</summary>
    public static byte[] Encode(string payload)
    {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(Encoding.UTF8.GetBytes(payload));
        byte[] data = ms.ToArray();
        Transform(data);
        return [.. Magic, .. data];
    }

    /// <summary>XOR mit SHA256(Schluessel || Blocknummer) – symmetrisch, gleiche Funktion zum Ver- und Entpacken.</summary>
    public static void Transform(Span<byte> data)
    {
        Span<byte> block = stackalloc byte[Key.Length + 8];
        Key.CopyTo(block);
        Span<byte> stream = stackalloc byte[32];
        for (long i = 0; i * 32 < data.Length; i++)
        {
            BitConverter.TryWriteBytes(block[Key.Length..], i);
            SHA256.HashData(block, stream);
            var chunk = data.Slice((int)(i * 32), (int)Math.Min(32, data.Length - i * 32));
            for (int j = 0; j < chunk.Length; j++) chunk[j] ^= stream[j];
        }
    }

    /// <summary>
    /// Format: "SCANME-YARA-PACK 1", Schluessel=Wert-Zeilen, je Regel "Name\tScore\tQuelle\tAutor\tBeschreibung",
    /// dann "---" und der YARA-Quelltext.
    /// </summary>
    internal static RulePack Parse(string payload)
    {
        int sep = payload.IndexOf("\n---\n", StringComparison.Ordinal);
        if (!payload.StartsWith("SCANME-YARA-PACK 1\n", StringComparison.Ordinal) || sep < 0)
            throw new InvalidDataException("Unbekanntes Format des Regelpakets.");

        var header = new Dictionary<string, string>();
        var rules = new Dictionary<string, RuleInfo>(StringComparer.Ordinal);
        foreach (var line in payload[..sep].Split('\n').Skip(1))
        {
            var cols = line.Split('\t');
            if (cols.Length >= 5)
                rules[cols[0]] = new RuleInfo(cols[0], int.TryParse(cols[1], out int s) ? s : 0, cols[2], cols[3], cols[4]);
            else if (line.IndexOf('=') is > 0 and var eq)
                header[line[..eq]] = line[(eq + 1)..];
        }
        return new RulePack
        {
            ForgeRelease = header.GetValueOrDefault("forge", ""),
            YaraXVersion = header.GetValueOrDefault("yarax", ""),
            Source = payload[(sep + 5)..],
            Rules = rules,
        };
    }
}
