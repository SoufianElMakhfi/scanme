using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using ScanMe.Core.Util;

namespace ScanMe.Core.Actions;

public enum UndoKind
{
    RegistryValue,
    TaskEnable,
    ServiceStart,
    DefenderExclusion,
    HostsFile,
    Hardening,
}

/// <summary>Ein rueckgaengig machbarer Schritt mit dem vorherigen Zustand.</summary>
public sealed class UndoEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime When { get; set; } = DateTime.Now;
    public UndoKind Kind { get; set; }
    public string Description { get; set; } = "";

    public string Target { get; set; } = "";
    public string? Name { get; set; }

    /// <summary>Vorheriger Wert (Registry: Base64 fuer Binaerdaten), null = existierte nicht.</summary>
    public string? PreviousValue { get; set; }
    public RegistryValueKind? PreviousKind { get; set; }
    public bool Undone { get; set; }
}

public static class UndoJournal
{
    private static readonly object Sync = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static List<UndoEntry> Load()
    {
        lock (Sync)
        {
            try
            {
                return File.Exists(AppPaths.UndoJournal)
                    ? JsonSerializer.Deserialize<List<UndoEntry>>(File.ReadAllText(AppPaths.UndoJournal), Json) ?? new()
                    : new();
            }
            catch { return new(); }
        }
    }

    public static void Add(UndoEntry e)
    {
        lock (Sync)
        {
            var list = Load();
            list.Add(e);
            File.WriteAllText(AppPaths.UndoJournal, JsonSerializer.Serialize(list, Json));
        }
    }

    private static void MarkUndone(string id)
    {
        lock (Sync)
        {
            var list = Load();
            foreach (var e in list.Where(e => e.Id == id)) e.Undone = true;
            File.WriteAllText(AppPaths.UndoJournal, JsonSerializer.Serialize(list, Json));
        }
    }

    /// <summary>Sichert einen Registry-Wert, bevor er geaendert wird.</summary>
    public static UndoEntry BackupRegistryValue(string key, string name, string description)
    {
        var e = new UndoEntry { Kind = UndoKind.RegistryValue, Target = key, Name = name, Description = description };
        using var k = RegistryUtil.Open(key);
        if (k != null && k.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            var kind = k.GetValueKind(name);
            object? v = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            e.PreviousKind = kind;
            e.PreviousValue = v switch
            {
                byte[] b => Convert.ToBase64String(b),
                string[] arr => JsonSerializer.Serialize(arr),
                null => null,
                _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture),
            };
        }
        Add(e);
        return e;
    }

    public static ActionResult Undo(UndoEntry e)
    {
        try
        {
            switch (e.Kind)
            {
                case UndoKind.RegistryValue:
                    var (root, sub) = RegistryUtil.Split(e.Target);
                    using (var k = root!.CreateSubKey(sub, true))
                    {
                        if (e.PreviousValue == null || e.PreviousKind == null)
                            k.DeleteValue(e.Name!, false);
                        else
                            k.SetValue(e.Name!, e.PreviousKind switch
                            {
                                RegistryValueKind.Binary => Convert.FromBase64String(e.PreviousValue),
                                RegistryValueKind.DWord => int.Parse(e.PreviousValue, System.Globalization.CultureInfo.InvariantCulture),
                                RegistryValueKind.QWord => long.Parse(e.PreviousValue, System.Globalization.CultureInfo.InvariantCulture),
                                RegistryValueKind.MultiString => JsonSerializer.Deserialize<string[]>(e.PreviousValue)!,
                                _ => e.PreviousValue,
                            }, e.PreviousKind.Value);
                    }
                    break;
                case UndoKind.TaskEnable:
                    ActionExecutor.RunTool("schtasks.exe", $"/Change /TN \"{e.Target}\" /ENABLE");
                    break;
                case UndoKind.ServiceStart:
                    using (var k = RegistryUtil.Open($@"HKLM\SYSTEM\CurrentControlSet\Services\{e.Target}", writable: true))
                        k?.SetValue("Start", int.Parse(e.PreviousValue ?? "3"), RegistryValueKind.DWord);
                    break;
                case UndoKind.DefenderExclusion:
                    if (ActionExecutor.InvokeMpPreference("Add", e.Name!, e.Target) is { } error)
                        return ActionResult.Fail("Ausnahme konnte nicht wiederhergestellt werden: " + error);
                    break;
                case UndoKind.HostsFile:
                    File.Copy(e.PreviousValue!, e.Target, overwrite: true);
                    break;
                case UndoKind.Hardening:
                    if (Hardening.HardeningService.Restore(e.Target, e.PreviousValue) is { } hardeningError)
                        return ActionResult.Fail("Rückgängig fehlgeschlagen: " + hardeningError);
                    break;
            }
            MarkUndone(e.Id);
            return ActionResult.Ok("Rückgängig gemacht: " + e.Description);
        }
        catch (Exception ex)
        {
            return ActionResult.Fail("Rückgängig fehlgeschlagen: " + ex.Message);
        }
    }
}
