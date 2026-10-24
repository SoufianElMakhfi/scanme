using System.Management;

namespace ScanMe.Core.Actions;

/// <summary>
/// Microsoft Defender Offline-Scan: Der PC startet neu und wird geprueft, BEVOR Windows laedt.
/// Dort kann sich kein Rootkit verstecken – Prinzip "dem befallenen System nicht trauen".
/// </summary>
public static class OfflineScan
{
    public static ActionResult Start()
    {
        try
        {
            using var cls = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpWDOScan", null);
            using var output = cls.InvokeMethod("Start", cls.GetMethodParameters("Start"), null);
            uint rc = output?["ReturnValue"] is { } r ? Convert.ToUInt32(r) : 0;
            return rc == 0
                ? ActionResult.Ok("Offline-Prüfung geplant – der PC startet in Kürze neu. Die Prüfung dauert ca. 15 Minuten, danach startet Windows normal.")
                : ActionResult.Fail($"Offline-Prüfung konnte nicht gestartet werden (Fehlercode {rc}).");
        }
        catch (ManagementException ex) { return ActionResult.Fail("Offline-Prüfung nicht verfügbar: " + ex.Message); }
        catch (UnauthorizedAccessException) { return ActionResult.Fail("Dafür sind Adminrechte erforderlich."); }
    }
}
