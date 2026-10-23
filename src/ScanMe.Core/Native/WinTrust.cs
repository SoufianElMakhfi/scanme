using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ScanMe.Core.Native;

/// <summary>
/// Authenticode-Pruefung via WinVerifyTrust – sowohl eingebettete Signaturen als auch
/// Katalogsignaturen (die meisten Windows-Systemdateien sind nur katalogsigniert).
/// </summary>
internal static class WinTrust
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly IntPtr InvalidHandle = new(-1);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    public const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    public const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    public const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    public const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    public const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    public const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    public const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    public const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    /// <summary>Prueft die eingebettete Authenticode-Signatur. Rueckgabe: HRESULT (0 = gueltig).</summary>
    public static int VerifyEmbedded(string path)
    {
        IntPtr pPath = Marshal.StringToCoTaskMemUni(path);
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = pPath,
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = NewData(WTD_CHOICE_FILE, pFile);
            return Run(ref data);
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeCoTaskMem(pPath);
        }
    }

    /// <summary>
    /// Sucht die Datei in den Windows-Systemkatalogen. Liefert HRESULT und (bei Treffer) den Katalogpfad.
    /// </summary>
    public static int VerifyCatalog(string path, out string? catalogFile)
    {
        catalogFile = null;
        int result = TRUST_E_NOSIGNATURE;
        // Neuere Kataloge nutzen SHA256, aeltere SHA1.
        foreach (var alg in new[] { "SHA256", "SHA1" })
        {
            result = VerifyCatalogWith(path, alg, out catalogFile);
            if (result == 0) return 0;
        }
        return result;
    }

    private static int VerifyCatalogWith(string path, string hashAlg, out string? catalogFile)
    {
        catalogFile = null;
        if (!CryptCATAdminAcquireContext2(out var hCatAdmin, IntPtr.Zero, hashAlg, IntPtr.Zero, 0))
            return TRUST_E_NOSIGNATURE;

        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            byte[] hash;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                uint cb = 0;
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref cb, null, 0);
                if (cb == 0) return TRUST_E_NOSIGNATURE;
                hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref cb, hash, 0))
                    return TRUST_E_NOSIGNATURE;
            }

            IntPtr prev = IntPtr.Zero;
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, (uint)hash.Length, 0, ref prev);
            if (hCatInfo == IntPtr.Zero) return TRUST_E_NOSIGNATURE;

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return TRUST_E_NOSIGNATURE;
            catalogFile = ci.wszCatalogFile;

            string memberTag = Convert.ToHexString(hash);
            IntPtr pCat = Marshal.StringToCoTaskMemUni(catalogFile);
            IntPtr pTag = Marshal.StringToCoTaskMemUni(memberTag);
            IntPtr pMember = Marshal.StringToCoTaskMemUni(path);
            IntPtr pHash = Marshal.AllocHGlobal(hash.Length);
            IntPtr pCatInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, pHash, hash.Length);
                var wci = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = pCat,
                    pcwszMemberTag = pTag,
                    pcwszMemberFilePath = pMember,
                    pbCalculatedFileHash = pHash,
                    cbCalculatedFileHash = (uint)hash.Length,
                    hCatAdmin = hCatAdmin,
                };
                Marshal.StructureToPtr(wci, pCatInfo, false);
                var data = NewData(WTD_CHOICE_CATALOG, pCatInfo);
                return Run(ref data);
            }
            finally
            {
                Marshal.FreeHGlobal(pCatInfo);
                Marshal.FreeHGlobal(pHash);
                Marshal.FreeCoTaskMem(pMember);
                Marshal.FreeCoTaskMem(pTag);
                Marshal.FreeCoTaskMem(pCat);
            }
        }
        catch (IOException) { return TRUST_E_NOSIGNATURE; }
        catch (UnauthorizedAccessException) { return TRUST_E_NOSIGNATURE; }
        finally
        {
            if (hCatInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static WINTRUST_DATA NewData(uint unionChoice, IntPtr pUnion) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_NONE,
        dwUnionChoice = unionChoice,
        pUnion = pUnion,
        dwStateAction = WTD_STATEACTION_VERIFY,
        // Offline-tauglich: keine Sperrlistenabfrage im Netz.
        dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
    };

    private static int Run(ref WINTRUST_DATA data)
    {
        var action = GenericVerifyV2;
        int result = WinVerifyTrust(InvalidHandle, ref action, ref data);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(InvalidHandle, ref action, ref data);
        return result;
    }

    public static string Describe(int hr) => hr switch
    {
        0 => "Gültig",
        TRUST_E_NOSIGNATURE => "Nicht signiert",
        TRUST_E_SUBJECT_FORM_UNKNOWN => "Dateiformat nicht signierbar",
        TRUST_E_PROVIDER_UNKNOWN => "Unbekannter Signaturtyp",
        CERT_E_EXPIRED => "Zertifikat abgelaufen",
        CERT_E_UNTRUSTEDROOT => "Nicht vertrauenswürdige Stammzertifizierungsstelle",
        TRUST_E_BAD_DIGEST => "Signatur passt nicht zur Datei (manipuliert!)",
        TRUST_E_EXPLICIT_DISTRUST => "Zertifikat explizit als nicht vertrauenswürdig markiert",
        CRYPT_E_SECURITY_SETTINGS => "Durch Sicherheitsrichtlinie blockiert",
        _ => $"Ungültig (0x{hr:X8})",
    };
}
