namespace ScanMe.Core.Trust;

public enum SignatureState
{
    Unknown,
    NotSigned,
    Valid,
    Invalid,
}

/// <summary>Vertrauensinformationen zu einer ausfuehrbaren Datei.</summary>
public sealed class FileTrustInfo
{
    public required string Path { get; init; }
    public bool Exists { get; init; }

    public SignatureState Signature { get; init; }
    public string SignatureStatusText { get; init; } = "";
    public bool IsCatalogSigned { get; init; }
    public string? Signer { get; init; }
    public string? SignerOrganization { get; init; }
    public string? Issuer { get; init; }

    /// <summary>Gueltig von Microsoft signiert.</summary>
    public bool IsMicrosoftSigned { get; init; }

    /// <summary>Microsoft-signiert UND im Windows-Verzeichnis: echte Windows-Komponente.</summary>
    public bool IsWindowsComponent { get; init; }

    public string? Sha256 { get; init; }
    public long Size { get; init; }
    public DateTime? Created { get; init; }
    public DateTime? Modified { get; init; }

    public string? CompanyName { get; init; }
    public string? ProductName { get; init; }
    public string? FileDescription { get; init; }
    public string? FileVersion { get; init; }
    public string? OriginalFilename { get; init; }

    /// <summary>Aus dem Internet heruntergeladen (Zone.Identifier, ZoneId 3/4).</summary>
    public bool FromInternet { get; init; }
    public string? DownloadUrl { get; init; }
    public string? DownloadReferrer { get; init; }

    public bool IsTrustedVendor => Signature == SignatureState.Valid;

    public string Publisher => Signer ?? CompanyName ?? "Unbekannt";
}
