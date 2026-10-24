namespace ScanMe.Core.Util;

public static class TextUtil
{
    public static int Levenshtein(string a, string b)
    {
        a = a.ToLowerInvariant();
        b = b.ToLowerInvariant();
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        return d[a.Length, b.Length];
    }

    /// <summary>
    /// Damerau-Levenshtein (OSA): wie Levenshtein, aber zwei vertauschte Nachbarbuchstaben zaehlen als EIN Fehler
    /// ("scvhost" vs. "svchost" = 1). Typische Tippfehler-Tarnungen werden so erkannt, ohne entfernt aehnliche
    /// Namen ("airhost" vs. "sihost") zu verdaechtigen.
    /// </summary>
    public static int OsaDistance(string a, string b)
    {
        a = a.ToLowerInvariant();
        b = b.ToLowerInvariant();
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        return d[a.Length, b.Length];
    }

    public static string Truncate(string? s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s ?? "" : s[..(max - 1)] + "…";

    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return $"{v:0.#} {units[u]}";
    }

    /// <summary>Shannon-Entropie in Bit pro Byte (0..8). Werte &gt; 7.2 deuten auf Verschluesselung/Packer hin.</summary>
    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double e = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / data.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
