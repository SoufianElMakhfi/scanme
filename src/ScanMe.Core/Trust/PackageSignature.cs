using System.Collections.Concurrent;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ScanMe.Core.Util;

namespace ScanMe.Core.Trust;

/// <summary>
/// Store-/MSIX-Apps sind nicht pro Datei, sondern als Paket signiert (AppxSignature.p7x).
/// Der Ordner WindowsApps ist nur fuer TrustedInstaller beschreibbar; Windows prueft die
/// Paketsignatur bei der Installation.
/// </summary>
internal static class PackageSignature
{
    private static readonly string[] PackageRoots =
    [
        Path.Combine(PathUtil.ProgramFiles, "WindowsApps"),
        Path.Combine(PathUtil.WindowsDir, "SystemApps"),
    ];

    private static readonly ConcurrentDictionary<string, (string? Signer, string? Org)?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static bool TryGet(string filePath, out string? signer, out string? organization)
    {
        signer = organization = null;
        string? packageDir = FindPackageDir(filePath);
        if (packageDir == null) return false;

        var result = Cache.GetOrAdd(packageDir, Read);
        if (result == null) return false;
        (signer, organization) = result.Value;
        return true;
    }

    private static string? FindPackageDir(string filePath)
    {
        foreach (var root in PackageRoots)
        {
            if (!PathUtil.IsUnder(filePath, root)) continue;
            string rel = filePath[(root.TrimEnd('\\').Length + 1)..];
            int slash = rel.IndexOf('\\');
            return slash > 0 ? Path.Combine(root, rel[..slash]) : null;
        }
        return null;
    }

    private static (string?, string?)? Read(string packageDir)
    {
        try
        {
            string p7x = Path.Combine(packageDir, "AppxSignature.p7x");
            if (!File.Exists(p7x))
            {
                // Systempakete ohne p7x (z. B. SystemApps) sind Teil des Windows-Images.
                return PathUtil.IsUnderWindowsDirectory(packageDir) ? ("Microsoft Windows", "Microsoft Corporation") : null;
            }

            byte[] raw = File.ReadAllBytes(p7x);
            // Format: "PKCX" + PKCS#7 SignedData
            if (raw.Length < 8 || raw[0] != 'P' || raw[1] != 'K' || raw[2] != 'C' || raw[3] != 'X') return null;
            var cms = new SignedCms();
            cms.Decode(raw.AsSpan(4).ToArray());
            cms.CheckSignature(verifySignatureOnly: true);
            var cert = cms.SignerInfos[0].Certificate;
            if (cert == null) return null;
            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            string? org = cert.Subject.Split(',').Select(s => s.Trim())
                .FirstOrDefault(s => s.StartsWith("O=", StringComparison.OrdinalIgnoreCase))?[2..].Trim('"');
            return (cn, org);
        }
        catch
        {
            return null;
        }
    }
}
