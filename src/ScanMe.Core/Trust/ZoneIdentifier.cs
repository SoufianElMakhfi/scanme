namespace ScanMe.Core.Trust;

/// <summary>
/// Liest den "Mark of the Web" (ADS Zone.Identifier). Darueber laesst sich nachvollziehen,
/// von welcher URL eine Datei heruntergeladen wurde – sehr wertvoll bei Phishing-Spuren.
/// </summary>
public static class ZoneIdentifier
{
    public readonly record struct Info(int ZoneId, string? HostUrl, string? ReferrerUrl);

    public static Info Read(string path)
    {
        try
        {
            string ads = path + ":Zone.Identifier";
            if (!File.Exists(ads)) return new Info(-1, null, null);
            int zone = -1;
            string? host = null, referrer = null;
            foreach (var raw in File.ReadLines(ads))
            {
                var line = raw.Trim();
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase) && int.TryParse(line[7..], out var z)) zone = z;
                else if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase)) host = line[8..];
                else if (line.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase)) referrer = line[12..];
            }
            return new Info(zone, host, referrer);
        }
        catch
        {
            return new Info(-1, null, null);
        }
    }
}
