using System.Security.Cryptography;

namespace ScanMe.Core.Updates;

/// <summary>
/// ECDSA-P256-Signatur fuer Regelpakete. Der private Schluessel liegt ausschliesslich beim Maintainer
/// (nie im Repository); ScanMe enthaelt nur den oeffentlichen Schluessel und akzeptiert nur
/// korrekt signierte Regeln. So kann selbst ein kompromittiertes GitHub-Konto keine Regeln verteilen.
/// </summary>
public static class RuleSigning
{
    /// <summary>Oeffentlicher Schluessel (SubjectPublicKeyInfo, Base64) des offiziellen Regel-Signaturschluessels.</summary>
    public const string PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMh7CZpotZEQc50OrQIw8CTshm9NK/SgvaNkjGuxTpkPPS05xrEVmfXAbc2ISBilg/HLWPEbHKaNlSAW9oa70UA==";

    public static bool Verify(byte[] data, string signatureBase64, string publicKeyBase64 = PublicKey)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            return ecdsa.VerifyData(data, Convert.FromBase64String(signatureBase64.Trim()), HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    public static string Sign(byte[] data, string privateKeyPem)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        return Convert.ToBase64String(ecdsa.SignData(data, HashAlgorithmName.SHA256));
    }

    /// <summary>Erzeugt ein neues Schluesselpaar: (privater Schluessel als PEM, oeffentlicher Schluessel als Base64).</summary>
    public static (string PrivatePem, string PublicBase64) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ecdsa.ExportPkcs8PrivateKeyPem(), Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()));
    }
}
