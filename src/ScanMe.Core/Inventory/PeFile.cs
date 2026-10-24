using ScanMe.Core.Util;

namespace ScanMe.Core.Inventory;

/// <summary>Minimaler PE-Parser: Sektionen, Entropie, Zeitstempel, .NET-Erkennung.</summary>
public sealed class PeFile
{
    public sealed record Section(string Name, uint RawSize, double Entropy, bool Executable, bool Writable);

    public bool Is64Bit { get; private set; }
    public bool IsDll { get; private set; }
    public bool IsDotNet { get; private set; }
    public DateTime? Timestamp { get; private set; }
    public List<Section> Sections { get; } = new();

    /// <summary>Daten hinter der letzten Sektion (nur aussagekraeftig, wenn die ganze Datei gelesen wurde).</summary>
    public long OverlaySize { get; private set; }

    /// <summary>
    /// Authenticode-Hash (SHA256): Hash der Datei ohne Pruefsumme, Zertifikatsverzeichnis und Signaturblock.
    /// Bleibt gleich, wenn eine Datei umbenannt oder neu signiert wird – so fuehren z. B. LOLDrivers und die
    /// Microsoft-Treibersperrliste ihre Eintraege.
    /// </summary>
    public static string? AuthenticodeSha256(string path, long maxSize = 64 * 1024 * 1024)
    {
        try
        {
            if (new FileInfo(path).Length > maxSize) return null;
            return AuthenticodeSha256(File.ReadAllBytes(path));
        }
        catch { return null; }
    }

    public static string? AuthenticodeSha256(byte[] d)
    {
        if (d.Length < 0x100 || d[0] != 'M' || d[1] != 'Z') return null;
        int pe = BitConverter.ToInt32(d, 0x3C);
        if (pe <= 0 || pe + 0x108 > d.Length || d[pe] != 'P' || d[pe + 1] != 'E') return null;
        int opt = pe + 24;
        bool is64 = BitConverter.ToUInt16(d, opt) == 0x20B;
        int checksum = opt + 64;
        int certDir = opt + (is64 ? 144 : 128); // Data Directory 4 = Sicherheitsverzeichnis (Signatur)
        if (certDir + 8 > d.Length) return null;

        uint certOff = BitConverter.ToUInt32(d, certDir);
        uint certSize = BitConverter.ToUInt32(d, certDir + 4);
        bool signed = certOff > certDir && certSize > 0 && (long)certOff + certSize <= d.Length;
        int end = signed ? (int)certOff : d.Length;

        using var h = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        h.AppendData(d, 0, checksum);
        h.AppendData(d, checksum + 4, certDir - checksum - 4);
        h.AppendData(d, certDir + 8, end - certDir - 8);
        // Daten hinter dem Signaturblock (selten) zaehlen ebenfalls
        int after = signed ? (int)(certOff + certSize) : d.Length;
        if (after < d.Length) h.AppendData(d, after, d.Length - after);
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
    }

    public static PeFile? TryParse(byte[] data, long fileLength)
    {
        try
        {
            if (data.Length < 0x100 || data[0] != 'M' || data[1] != 'Z') return null;
            int peOff = BitConverter.ToInt32(data, 0x3C);
            if (peOff <= 0 || peOff + 0x108 > data.Length || data[peOff] != 'P' || data[peOff + 1] != 'E') return null;

            int coff = peOff + 4;
            ushort numSections = BitConverter.ToUInt16(data, coff + 2);
            uint ts = BitConverter.ToUInt32(data, coff + 4);
            ushort optSize = BitConverter.ToUInt16(data, coff + 16);
            ushort characteristics = BitConverter.ToUInt16(data, coff + 18);
            int opt = coff + 20;
            bool is64 = BitConverter.ToUInt16(data, opt) == 0x20B;

            // Data Directory 14 = CLR-Header (.NET)
            int ddOffset = opt + (is64 ? 112 : 96);
            bool dotnet = ddOffset + 15 * 8 <= data.Length && BitConverter.ToUInt32(data, ddOffset + 14 * 8) != 0;

            var pe = new PeFile
            {
                Is64Bit = is64,
                IsDll = (characteristics & 0x2000) != 0,
                IsDotNet = dotnet,
                Timestamp = ts > 0 ? DateTimeOffset.FromUnixTimeSeconds(ts).LocalDateTime : null,
            };

            int secTable = opt + optSize;
            long maxEnd = 0;
            for (int i = 0; i < numSections && secTable + (i + 1) * 40 <= data.Length; i++)
            {
                int s = secTable + i * 40;
                string name = System.Text.Encoding.ASCII.GetString(data, s, 8).TrimEnd('\0');
                uint rawSize = BitConverter.ToUInt32(data, s + 16);
                uint rawPtr = BitConverter.ToUInt32(data, s + 20);
                uint chars = BitConverter.ToUInt32(data, s + 36);
                double entropy = 0;
                if (rawPtr < data.Length && rawSize > 0)
                {
                    int len = (int)Math.Min(rawSize, data.Length - rawPtr);
                    entropy = TextUtil.Entropy(data.AsSpan((int)rawPtr, len));
                }
                maxEnd = Math.Max(maxEnd, (long)rawPtr + rawSize);
                pe.Sections.Add(new Section(name, rawSize, entropy, (chars & 0x20000000) != 0, (chars & 0x80000000) != 0));
            }
            pe.OverlaySize = Math.Max(0, fileLength - maxEnd);
            return pe;
        }
        catch
        {
            return null;
        }
    }
}
