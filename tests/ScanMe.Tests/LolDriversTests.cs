using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;

namespace ScanMe.Tests;

/// <summary>Treiber-Abgleich mit LOLDrivers: Der Authentihash muss exakt dem von Windows entsprechen, sonst findet er nichts.</summary>
public class LolDriversTests
{
    /// <summary>Eine Datei mit eingebetteter SHA256-Authenticode-Signatur (auf jedem Rechner mit .NET vorhanden).</summary>
    private static string SignedFile()
    {
        var candidates = new[]
        {
            Environment.ProcessPath,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe"),
        };
        var file = candidates.FirstOrDefault(p => p != null && File.Exists(p) && SignedDigest(File.ReadAllBytes(p)) != null);
        Assert.NotNull(file);
        return file!;
    }

    /// <summary>Der Hash, den der Signierer in die Signatur geschrieben hat (SpcIndirectDataContent → DigestInfo).</summary>
    private static byte[]? SignedDigest(byte[] pe)
    {
        int peOff = BitConverter.ToInt32(pe, 0x3C);
        int opt = peOff + 24;
        bool is64 = BitConverter.ToUInt16(pe, opt) == 0x20B;
        int certDir = opt + (is64 ? 144 : 128);
        int certOff = BitConverter.ToInt32(pe, certDir);
        if (certOff <= 0) return null;
        int length = BitConverter.ToInt32(pe, certOff); // WIN_CERTIFICATE: Laenge, Revision, Typ, PKCS#7
        var cms = new SignedCms();
        cms.Decode(pe.AsSpan(certOff + 8, length - 8).ToArray());

        var outer = new AsnReader(cms.ContentInfo.Content, AsnEncodingRules.DER).ReadSequence();
        outer.ReadEncodedValue(); // SpcAttributeTypeAndOptionalValue
        var digestInfo = outer.ReadSequence();
        string oid = digestInfo.ReadSequence().ReadObjectIdentifier();
        return oid == "2.16.840.1.101.3.4.2.1" ? digestInfo.ReadOctetString() : null; // nur SHA256
    }

    [Fact]
    public void Authentihash_MatchesDigestInsideSignature()
    {
        byte[] pe = File.ReadAllBytes(SignedFile());
        string expected = Convert.ToHexString(SignedDigest(pe)!).ToLowerInvariant();
        Assert.Equal(expected, PeFile.AuthenticodeSha256(pe));
    }

    [Fact]
    public void Authentihash_SurvivesRemovingTheSignature()
    {
        // So arbeiten Angreifer: verwundbaren Treiber nehmen, alte Signatur entfernen, neu signieren oder umbenennen.
        byte[] pe = File.ReadAllBytes(SignedFile());
        int opt = BitConverter.ToInt32(pe, 0x3C) + 24;
        int certDir = opt + (BitConverter.ToUInt16(pe, opt) == 0x20B ? 144 : 128);
        int certOff = BitConverter.ToInt32(pe, certDir);

        byte[] stripped = pe.AsSpan(0, certOff).ToArray();
        BitConverter.GetBytes(0L).CopyTo(stripped, certDir);       // Zertifikatsverzeichnis leeren
        BitConverter.GetBytes(0x12345678).CopyTo(stripped, opt + 64); // Pruefsumme aendern

        Assert.NotEqual(Convert.ToHexString(SHA256.HashData(pe)), Convert.ToHexString(SHA256.HashData(stripped)));
        Assert.Equal(PeFile.AuthenticodeSha256(pe), PeFile.AuthenticodeSha256(stripped));
    }

    [Fact]
    public void Authentihash_RejectsNonPe()
    {
        Assert.Null(PeFile.AuthenticodeSha256(new byte[1024]));
    }

    [Fact]
    public void Database_IsEmbedded_AndFindsKnownDriver()
    {
        Assert.True(LolDrivers.Count > 500, $"Nur {LolDrivers.Count} Treiber geladen");
        // RTCore64.sys (MSI Afterburner, CVE-2019-16098) – von Ransomware zum Abschalten von Virenscannern genutzt
        var e = LolDrivers.FindBySha256("01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD");
        Assert.NotNull(e);
        Assert.Contains("RTCore64.sys", e!.Names);
        Assert.False(e.IsMalicious);
        Assert.Null(LolDrivers.FindBySha256(new string('0', 64)));
    }

    [Fact]
    public void MaliciousDriver_IsAct_VulnerableDriver_IsCheck()
    {
        Finding Make(string code, int weight)
        {
            var f = new Finding { ScannerId = "drivers", Category = FindingCategory.Driver, Title = "Treiber: x.sys" };
            f.AddIndicator(code, code, weight);
            RiskScorer.Finalize(f);
            PlainLanguage.Apply(f);
            return f;
        }
        Assert.Equal(Verdict.Act, Make("DRV_MALICIOUS", 85).Verdict);
        // Verwundbar heisst nicht boesartig: oft gehoert der Treiber zu Lueftersteuerung oder RGB-Software.
        Assert.Equal(Verdict.Check, Make("DRV_VULNERABLE", 40).Verdict);
    }
}
