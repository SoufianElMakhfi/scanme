namespace ScanMe.Core.Util;

/// <summary>Liest Ziel und Argumente von .lnk-Verknuepfungen ueber die Windows-Shell (COM).</summary>
public static class ShortcutReader
{
    public static (string? Target, string? Arguments) Read(string lnkPath)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) return (null, null);
            dynamic shell = Activator.CreateInstance(type)!;
            try
            {
                dynamic sc = shell.CreateShortcut(lnkPath);
                string? target = sc.TargetPath as string;
                string? args = sc.Arguments as string;
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sc);
                return (string.IsNullOrWhiteSpace(target) ? null : target, string.IsNullOrWhiteSpace(args) ? null : args);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
            }
        }
        catch
        {
            return (null, null);
        }
    }
}
