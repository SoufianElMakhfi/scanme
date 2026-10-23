using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;

namespace ScanMe.Core.Engine;

/// <summary>Statische Inhaltsanalyse einer Datei, ohne sie auszufuehren.</summary>
public static class StaticAnalyzer
{
    private const long MaxBytes = 32L * 1024 * 1024;

    public static void Analyze(Finding f, string path)
    {
        if (f.Details.ContainsKey("Inhaltsanalyse")) return;
        byte[] data;
        long length;
        try
        {
            var fi = new FileInfo(path);
            length = fi.Length;
            if (length == 0) return;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            data = new byte[(int)Math.Min(length, MaxBytes)];
            int read = 0;
            while (read < data.Length)
            {
                int n = fs.Read(data, read, data.Length - read);
                if (n == 0) break;
                read += n;
            }
        }
        catch
        {
            return;
        }

        var notes = new List<string>();

        var pe = PeFile.TryParse(data, length);
        if (pe != null)
        {
            var packer = pe.Sections.Select(s => ContentSignatures.PackerSections.GetValueOrDefault(s.Name)).FirstOrDefault(p => p != null);
            if (packer != null)
            {
                f.AddIndicator("PACKER", $"Mit {packer} gepackt/geschuetzt – erschwert die Analyse", packer == "UPX" ? 10 : 20);
                notes.Add("Packer: " + packer);
            }

            var hot = pe.Sections.Where(s => s.Executable && s.Entropy > 7.2 && s.RawSize > 4096).ToList();
            // .NET-Assemblies speichern Ressourcen in .text – hohe Entropie ist dort normal.
            if (hot.Count > 0 && packer == null && !pe.IsDotNet)
            {
                f.AddIndicator("HIGH_ENTROPY", $"Ausfuehrbarer Code ist verschluesselt/komprimiert (Entropie {hot.Max(s => s.Entropy):0.00}) – typisch fuer gepackte Malware", 15);
                notes.Add($"Entropie {hot.Max(s => s.Entropy):0.00}");
            }

            if (pe.Sections.Any(s => s.Executable && s.Writable))
                f.AddIndicator("RWX_SECTION", "Sektion ist gleichzeitig beschreibbar und ausfuehrbar (selbstmodifizierender Code)", 10);

            if (pe.Timestamp is { } ts && ts > DateTime.Now.AddDays(2) && ts.Year < 2100)
                f.AddIndicator("FUTURE_TIMESTAMP", $"Kompilierzeitpunkt liegt in der Zukunft ({ts:d}) – gefaelscht", 10);

            notes.Add((pe.IsDll ? "DLL" : "EXE") + (pe.Is64Bit ? " 64-Bit" : " 32-Bit") + (pe.IsDotNet ? " .NET" : ""));
            if (pe.Timestamp is { } t) notes.Add($"kompiliert {t:d}");
        }

        // Grosse Text-/Skriptdateien sind fast immer gebuendelter Programmcode (Webpack, Electron) – zu viele Zufallstreffer.
        if (pe == null && length > 1024 * 1024)
        {
            f.Detail("Inhaltsanalyse", "uebersprungen (grosse Textdatei)");
            return;
        }

        foreach (var (sig, hits) in ContentSignatures.Scan(data, pe != null ? ContentSignatures.Target.Pe : ContentSignatures.Target.Script))
        {
            f.AddIndicator("CONTENT_" + new string(sig.Name.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant(),
                $"Inhalt passt zu: {sig.Name} ({sig.Family}) – Treffer: {string.Join(", ", hits.Take(4))}", sig.Weight);
            notes.Add($"{sig.Name}: {sig.Explanation}");
        }

        f.Detail("Inhaltsanalyse", notes.Count > 0 ? string.Join(" | ", notes) : "unauffaellig");
    }
}
