using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ScanMe.Core.Native;
using ScanMe.Core.Util;

namespace ScanMe.Core.Trust;

/// <summary>
/// Ermittelt (und cached) Signatur, Hash, Versionsinfo und Download-Herkunft von Dateien.
/// Threadsicher; wird von allen Scannern gemeinsam genutzt.
/// </summary>
public sealed class FileTrustService
{
    private const long MaxHashSize = 512L * 1024 * 1024;

    private readonly ConcurrentDictionary<string, FileTrustInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public static FileTrustService Shared { get; } = new();

    public FileTrustInfo Get(string path)
    {
        path = PathUtil.Normalize(path);
        DateTime stamp = DateTime.MinValue;
        try { stamp = File.GetLastWriteTimeUtc(path); } catch { }

        if (_cache.TryGetValue(path, out var cached) && cached.Modified?.ToUniversalTime() == stamp)
            return cached;

        var info = Compute(path);
        _cache[path] = info;
        return info;
    }

    public void Invalidate(string path) => _cache.TryRemove(PathUtil.Normalize(path), out _);

    private static FileTrustInfo Compute(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new FileTrustInfo { Path = path, Exists = false, Signature = SignatureState.Unknown, SignatureStatusText = "Datei nicht gefunden" };

        var fi = new FileInfo(path);

        // --- Signatur: zuerst eingebettet, dann Windows-Katalog ---
        int hr;
        bool catalog = false;
        string? catalogFile = null;
        try { hr = WinTrust.VerifyEmbedded(path); }
        catch { hr = WinTrust.TRUST_E_NOSIGNATURE; }

        if (hr == WinTrust.TRUST_E_NOSIGNATURE || hr == WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN || hr == WinTrust.TRUST_E_PROVIDER_UNKNOWN)
        {
            try
            {
                int catHr = WinTrust.VerifyCatalog(path, out catalogFile);
                if (catHr == 0) { hr = 0; catalog = true; }
            }
            catch { }
        }

        SignatureState state = hr switch
        {
            0 => SignatureState.Valid,
            WinTrust.TRUST_E_NOSIGNATURE or WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN or WinTrust.TRUST_E_PROVIDER_UNKNOWN => SignatureState.NotSigned,
            _ => SignatureState.Invalid,
        };

        string? signer = null, org = null, issuer = null;
        if (state != SignatureState.NotSigned)
        {
            try
            {
                string certSource = catalog && catalogFile != null ? catalogFile : path;
#pragma warning disable SYSLIB0057
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(certSource));
#pragma warning restore SYSLIB0057
                signer = cert.GetNameInfo(X509NameType.SimpleName, false);
                issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
                org = ExtractRdn(cert.Subject, "O");
            }
            catch { }
        }

        string? statusText = null;
        if (state == SignatureState.NotSigned && PackageSignature.TryGet(path, out var pkgSigner, out var pkgOrg))
        {
            state = SignatureState.Valid;
            signer = pkgSigner;
            org = pkgOrg;
            issuer = pkgOrg != null && pkgOrg.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ? "Microsoft" : null;
            statusText = "Gueltig (signiertes App-Paket / Microsoft Store)";
        }

        bool isMicrosoft = state == SignatureState.Valid
            && signer != null
            && signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)
            && (org?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false)
            && (issuer?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false);

        bool isWindowsComponent = isMicrosoft && PathUtil.IsUnderWindowsDirectory(path);

        // --- Versionsressource ---
        FileVersionInfo? ver = null;
        try { ver = FileVersionInfo.GetVersionInfo(path); } catch { }

        // --- Download-Herkunft (Mark of the Web) ---
        var motw = ZoneIdentifier.Read(path);

        return new FileTrustInfo
        {
            Path = path,
            Exists = true,
            Signature = state,
            SignatureStatusText = statusText ?? (catalog ? "Gueltig (Windows-Katalog)" : WinTrust.Describe(hr)),
            IsCatalogSigned = catalog,
            Signer = signer,
            SignerOrganization = org,
            Issuer = issuer,
            IsMicrosoftSigned = isMicrosoft,
            IsWindowsComponent = isWindowsComponent,
            Sha256 = fi.Length <= MaxHashSize ? TryHash(path) : null,
            Size = fi.Length,
            Created = fi.CreationTime,
            Modified = fi.LastWriteTime,
            CompanyName = Clean(ver?.CompanyName),
            ProductName = Clean(ver?.ProductName),
            FileDescription = Clean(ver?.FileDescription),
            FileVersion = Clean(ver?.FileVersion),
            OriginalFilename = Clean(ver?.OriginalFilename),
            FromInternet = motw.ZoneId >= 3,
            DownloadUrl = motw.HostUrl,
            DownloadReferrer = motw.ReferrerUrl,
        };
    }

    public static string? TryHash(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            return Convert.ToHexString(SHA256.HashData(fs));
        }
        catch { return null; }
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string? ExtractRdn(string dn, string key)
    {
        foreach (var part in dn.Split(','))
        {
            var p = part.Trim();
            if (p.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                return p[(key.Length + 1)..].Trim('"');
        }
        return null;
    }
}
