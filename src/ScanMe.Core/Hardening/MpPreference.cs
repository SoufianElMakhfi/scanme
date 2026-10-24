using System.Management;

namespace ScanMe.Core.Hardening;

/// <summary>Lesen und Schreiben von Microsoft-Defender-Einstellungen ueber WMI (MSFT_MpPreference) – ohne PowerShell.</summary>
internal static class MpPreference
{
    private const string Ns = @"root\Microsoft\Windows\Defender";

    public static ManagementBaseObject? Read()
    {
        try
        {
            using var s = new ManagementObjectSearcher(Ns, "SELECT * FROM MSFT_MpPreference");
            return s.Get().Cast<ManagementBaseObject>().FirstOrDefault();
        }
        catch { return null; }
    }

    public static byte? GetByte(string name) => Read()?[name] is { } v ? Convert.ToByte(v) : null;

    /// <summary>Aktuelle ASR-Regeln: GUID (klein geschrieben) -> Aktion (0 aus, 1 blockieren, 2 Testmodus, 6 warnen).</summary>
    public static Dictionary<string, byte> AsrRules()
    {
        var result = new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var o = Read();
        if (o?["AttackSurfaceReductionRules_Ids"] is not string[] ids || o["AttackSurfaceReductionRules_Actions"] is not byte[] actions) return result;
        for (int i = 0; i < Math.Min(ids.Length, actions.Length); i++) result[ids[i].ToLowerInvariant()] = actions[i];
        return result;
    }

    /// <summary>MSFT_MpPreference.Set mit einem Wert. Rueckgabe: Fehlermeldung oder null.</summary>
    public static string? Set(string name, object value) => Invoke("Set", input => input[name] = value);

    public static string? SetAsr(string id, byte action) => Invoke("Add", input =>
    {
        input["AttackSurfaceReductionRules_Ids"] = new[] { id };
        input["AttackSurfaceReductionRules_Actions"] = new[] { action };
    });

    private static string? Invoke(string method, Action<ManagementBaseObject> fill)
    {
        try
        {
            using var cls = new ManagementClass(Ns, "MSFT_MpPreference", null);
            using var input = cls.GetMethodParameters(method);
            fill(input);
            using var output = cls.InvokeMethod(method, input, null);
            uint rc = output?["ReturnValue"] is { } r ? Convert.ToUInt32(r) : 0;
            return rc == 0 ? null : $"Defender-Fehlercode {rc}";
        }
        catch (ManagementException ex) { return ex.Message; }
        catch (UnauthorizedAccessException) { return "Zugriff verweigert – Adminrechte erforderlich."; }
    }
}
