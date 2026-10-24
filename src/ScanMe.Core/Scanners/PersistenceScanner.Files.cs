using System.Management;
using System.Xml.Linq;
using ScanMe.Core.Engine;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

public sealed partial class PersistenceScanner
{
    // ------------------------------------------------------------------
    // Autostart-Ordner
    // ------------------------------------------------------------------

    private void ScanStartupFolders(ScanContext ctx)
    {
        var folders = new List<(string Dir, string Hive)>
        {
            (Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp"), "HKLM"),
        };
        foreach (var profile in SystemEnv.UserProfiles())
            folders.Add((Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), ""));

        foreach (var (dir, hive) in folders)
        {
            if (!Directory.Exists(dir)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir).ToList(); }
            catch { ctx.Note($"Kein Zugriff auf {dir}"); continue; }

            foreach (var file in files)
            {
                string name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                string command;
                if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    var (target, args) = ShortcutReader.Read(file);
                    command = target == null ? file : $"\"{target}\" {args}".Trim();
                }
                else
                {
                    command = $"\"{file}\"";
                }

                bool? enabled = hive.Length > 0 ? IsApproved(hive, "StartupFolder", name) ?? true : true;
                var f = Evaluate(ctx, new Entry("Autostart-Ordner", name, dir, command, Enabled: enabled), f =>
                {
                    // Skripte direkt im Autostart sind ungewoehnlich
                    string ext = Path.GetExtension(name).ToLowerInvariant();
                    if (ext is ".vbs" or ".vbe" or ".js" or ".jse" or ".bat" or ".cmd" or ".ps1" or ".hta" or ".wsf")
                    {
                        f.AddIndicator("SCRIPT_STARTUP", $"Skriptdatei ({ext}) direkt im Autostart-Ordner", 30);
                        ScanScriptContent(f, file);
                    }
                    f.Detail("Verknüpfung", file);
                });
                if (f != null && !f.Actions.Any(a => a.Kind == RemediationKind.QuarantineFile && a.Target == file))
                    f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "Autostart-Datei in Quarantäne", Target = file });
            }
        }
    }

    private static void ScanScriptContent(Finding f, string file)
    {
        try
        {
            var fi = new FileInfo(file);
            if (fi.Length > 2 * 1024 * 1024) return;
            string content = File.ReadAllText(file);
            foreach (var rule in CommandLineRules.Match(content))
                f.AddIndicator("SCRIPT_" + rule.Id, "Im Skript: " + rule.Text, rule.Weight);
            f.Detail("Skriptauszug", TextUtil.Truncate(content.Replace("\r\n", "\n").Trim(), 1500));
        }
        catch { }
    }

    // ------------------------------------------------------------------
    // Geplante Aufgaben
    // ------------------------------------------------------------------

    private static readonly XNamespace TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private void ScanScheduledTasks(ScanContext ctx)
    {
        string tasksDir = Path.Combine(PathUtil.System32, "Tasks");
        List<string> files;
        try
        {
            files = Directory.EnumerateFiles(tasksDir, "*", new System.IO.EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).ToList();
        }
        catch
        {
            ctx.Note("Aufgabenordner nicht lesbar – für geplante Tasks werden Adminrechte benötigt.");
            return;
        }
        if (!ctx.IsElevated) ctx.Note("Ohne Adminrechte sind viele geplante Aufgaben nicht lesbar.");

        foreach (var file in files)
        {
            ctx.ThrowIfCancelled();
            string taskPath = file[tasksDir.Length..];
            XDocument doc;
            try { doc = XDocument.Load(file); }
            catch { continue; }
            var root = doc.Root;
            if (root == null) continue;

            string? author = root.Element(TaskNs + "RegistrationInfo")?.Element(TaskNs + "Author")?.Value;
            string? description = root.Element(TaskNs + "RegistrationInfo")?.Element(TaskNs + "Description")?.Value;
            var settings = root.Element(TaskNs + "Settings");
            bool hidden = settings?.Element(TaskNs + "Hidden")?.Value == "true";
            bool enabled = settings?.Element(TaskNs + "Enabled")?.Value != "false";
            var principal = root.Element(TaskNs + "Principals")?.Element(TaskNs + "Principal");
            string? runAs = principal?.Element(TaskNs + "UserId")?.Value ?? principal?.Element(TaskNs + "GroupId")?.Value;
            bool highest = principal?.Element(TaskNs + "RunLevel")?.Value == "HighestAvailable";
            var triggers = root.Element(TaskNs + "Triggers")?.Elements().Select(t => TriggerText(t.Name.LocalName)).Distinct().ToList() ?? [];
            bool isMicrosoftTask = taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

            var actions = root.Element(TaskNs + "Actions")?.Elements() ?? [];
            foreach (var action in actions)
            {
                string? command = null;
                if (action.Name.LocalName == "Exec")
                {
                    string? exe = action.Element(TaskNs + "Command")?.Value;
                    string? args = action.Element(TaskNs + "Arguments")?.Value;
                    if (string.IsNullOrWhiteSpace(exe)) continue;
                    command = (exe.Contains(' ') && !exe.StartsWith('"') ? $"\"{exe}\"" : exe) + (string.IsNullOrWhiteSpace(args) ? "" : " " + args);
                }
                else if (action.Name.LocalName == "ComHandler")
                {
                    string? clsid = action.Element(TaskNs + "ClassId")?.Value;
                    string? dll = clsid != null ? RegistryUtil.GetString($@"HKLM\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32", "") : null;
                    if (dll == null) continue;
                    command = $"\"{Environment.ExpandEnvironmentVariables(dll)}\"";
                }
                else continue;

                var f = Evaluate(ctx, new Entry("Geplante Aufgabe", taskPath.TrimStart('\\'), @"\" + taskPath.TrimStart('\\'), command,
                    ReportThirdParty: !isMicrosoftTask, Enabled: enabled), f =>
                {
                    if (hidden && !isMicrosoftTask) f.AddIndicator("TASK_HIDDEN_FLAG", "Aufgabe ist als 'versteckt' markiert", 15);
                    if (isMicrosoftTask && !f.IsProtected && f.FilePath != null)
                        f.AddIndicator("TASK_MS_FOLDER", "Liegt im Microsoft-Aufgabenordner, startet aber keine Windows-Komponente (Tarnung?)", 15);
                    if (highest && runAs is "S-1-5-18" or "SYSTEM") f.AddIndicator("TASK_SYSTEM", "Läuft mit SYSTEM-Rechten", 5);
                    f.Detail("Auslöser", string.Join(", ", triggers))
                     .Detail("Ausführen als", runAs)
                     .Detail("Autor", author)
                     .Detail("Beschreibung", description)
                     .Detail("Aufgabendatei", file);
                });
                if (f != null && enabled)
                    f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.DisableScheduledTask, Label = "Aufgabe deaktivieren", Target = taskPath });
            }
        }

        ScanHiddenTasks(ctx, tasksDir);
    }

    private static string TriggerText(string t) => t switch
    {
        "LogonTrigger" => "bei Anmeldung",
        "BootTrigger" => "bei Systemstart",
        "TimeTrigger" => "einmalig zu einer Zeit",
        "CalendarTrigger" => "zeitgesteuert",
        "IdleTrigger" => "im Leerlauf",
        "EventTrigger" => "bei Ereignis",
        "RegistrationTrigger" => "bei Erstellung",
        "SessionStateChangeTrigger" => "bei Sitzungswechsel (z. B. Entsperren)",
        "WnfStateChangeTrigger" => "bei Systemzustand",
        _ => t,
    };

    /// <summary>
    /// Tarrask-Technik: Angreifer loeschen den Security-Descriptor (SD) einer Aufgabe in der Registry.
    /// Die Aufgabe laeuft weiter, ist aber in schtasks und der Aufgabenplanung unsichtbar.
    /// </summary>
    private void ScanHiddenTasks(ScanContext ctx, string tasksDir)
    {
        if (!ctx.IsElevated) return; // ohne Adminrechte fehlen Dateien/Werte scheinbar -> Fehlalarme
        const string treeRoot = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        var stack = new Stack<string>();
        stack.Push("");
        while (stack.Count > 0)
        {
            string rel = stack.Pop();
            string key = rel.Length == 0 ? treeRoot : $@"{treeRoot}\{rel}";
            foreach (var sub in RegistryUtil.SubKeys(key))
                stack.Push(rel.Length == 0 ? sub : $@"{rel}\{sub}");

            if (rel.Length == 0) continue;
            string? id = RegistryUtil.GetString(key, "Id");
            if (id == null) continue; // Ordner, keine Aufgabe

            bool hasSd = RegistryUtil.GetValue(key, "SD") is byte[] { Length: > 0 };
            bool hasFile = File.Exists(Path.Combine(tasksDir, rel));
            if (hasSd && hasFile) continue;
            if (hasSd && !ctx.IsElevated) continue;

            // Windows-eigene Aufgaben ohne Datei sind meist Reste von Updates (inaktiv, ohne Programm) – kein Angriffsindiz.
            bool orphanedWindowsTask = hasSd && rel.StartsWith(@"Microsoft\Windows\", StringComparison.OrdinalIgnoreCase);
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Persistence,
                Title = orphanedWindowsTask ? $"Verwaiste Windows-Aufgabe: {rel}" : $"Versteckte geplante Aufgabe: {rel}",
                Location = key,
                Description = !hasSd
                    ? $"Die Aufgabe \"{rel}\" existiert in der Registry, ihr Sicherheitsdeskriptor wurde jedoch entfernt. Sie ist dadurch in der Aufgabenplanung unsichtbar."
                    : $"Die Aufgabe \"{rel}\" ist in der Registry registriert, die zugehörige Aufgabendatei fehlt.",
                Explanation = orphanedWindowsTask
                    ? "Ein Überbleibsel einer Windows-eigenen Aufgabe, meist nach einem Windows-Update. Ohne Aufgabendatei wird nichts ausgeführt – harmlos."
                    : "Das gezielte Verstecken geplanter Aufgaben ist eine bekannte Technik staatlicher Angreifergruppen (z. B. 'Tarrask' der Gruppe HAFNIUM). " +
                      "Legitime Software macht das nicht.",
                Recommendation = orphanedWindowsTask
                    ? "Keine Aktion nötig. Bei Bedarf als 'Ignorieren' markieren."
                    : "Aufgabe untersuchen (Registry-Schlüssel TaskCache\\Tasks\\" + id + "), zugehörige Programme in Quarantäne verschieben und den PC gründlich prüfen.",
            };
            f.AddIndicator(hasSd ? "TASK_NO_FILE" : "TASK_NO_SD",
                hasSd ? "Aufgabe ohne Aufgabendatei" : "Aufgabe ohne Sicherheitsdeskriptor (bewusst versteckt)", orphanedWindowsTask ? 5 : hasSd ? 25 : 80);
            f.Detail("Task-ID", id).Detail("Registry", key);
            ctx.Add(f);
        }
    }

    // ------------------------------------------------------------------
    // Dienste
    // ------------------------------------------------------------------

    private void ScanServices(ScanContext ctx)
    {
        const string services = @"HKLM\SYSTEM\CurrentControlSet\Services";
        foreach (var svc in RegistryUtil.SubKeys(services))
        {
            ctx.ThrowIfCancelled();
            string key = $@"{services}\{svc}";
            int type = RegistryUtil.GetInt(key, "Type") ?? 0;
            if ((type & 0x30) == 0) continue; // Treiber -> eigener Scanner
            int start = RegistryUtil.GetInt(key, "Start") ?? 3;
            string? imagePath = RegistryUtil.GetString(key, "ImagePath");
            if (string.IsNullOrWhiteSpace(imagePath)) continue;

            string? display = RegistryUtil.GetString(key, "DisplayName");
            if (display?.StartsWith('@') == true) display = null; // Ressourcenverweis
            string? account = RegistryUtil.GetString(key, "ObjectName");
            string? serviceDll = RegistryUtil.GetString($@"{key}\Parameters", "ServiceDll") ?? RegistryUtil.GetString(key, "ServiceDll");
            bool isSvchost = imagePath.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase);

            string command = isSvchost && serviceDll != null ? $"\"{Environment.ExpandEnvironmentVariables(serviceDll)}\"" : imagePath;
            string startText = start switch { 0 => "Boot", 1 => "System", 2 => "Automatisch", 3 => "Manuell", 4 => "Deaktiviert", _ => start.ToString() };

            var f = Evaluate(ctx, new Entry("Dienst", display != null ? $"{svc} ({display})" : svc, key, command,
                ReportThirdParty: false, Enabled: start == 4 ? false : null), f =>
            {
                // Shell-Befehle als Dienst: typisch fuer PsExec-artige Fernausfuehrung und Angreifer
                string exeName = Path.GetFileName(PathUtil.ResolveCommandLine(imagePath).Executable ?? "");
                if (exeName is "cmd.exe" or "powershell.exe" or "pwsh.exe" or "mshta.exe" or "rundll32.exe" or "wscript.exe" or "cscript.exe"
                    || imagePath.Contains("cmd.exe /c", StringComparison.OrdinalIgnoreCase) || imagePath.Contains("cmd /c", StringComparison.OrdinalIgnoreCase))
                    f.AddIndicator("SVC_SHELL", $"Dienst startet direkt eine Shell/Skript-Host ({exeName})", 55);

                if (IsUnquotedVulnerable(imagePath))
                    f.AddIndicator("SVC_UNQUOTED", "Unquotierter Dienstpfad mit Leerzeichen (Schwachstelle zur Rechteausweitung)", 15);

                if (isSvchost && serviceDll != null) f.Detail("ServiceDll", serviceDll);
                f.Detail("ImagePath", imagePath).Detail("Starttyp", startText).Detail("Konto", account).Detail("Dienstname", svc);
            });

            if (f != null && start != 4 && !f.IsProtected)
                f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.DisableService, Label = "Dienst deaktivieren", Target = svc });
        }
    }

    private static bool IsUnquotedVulnerable(string imagePath)
    {
        string p = imagePath.Trim();
        if (p.StartsWith('"')) return false;
        int exe = p.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe < 0) return false;
        string exePart = p[..(exe + 4)];
        if (!exePart.Contains(' ')) return false;
        string full = PathUtil.Normalize(exePart);
        return !PathUtil.IsUnderWindowsDirectory(full);
    }

    // ------------------------------------------------------------------
    // WMI-Ereignisabonnements
    // ------------------------------------------------------------------

    private void ScanWmiSubscriptions(ScanContext ctx)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, Query FROM __EventFilter")))
                foreach (ManagementObject mo in s.Get())
                    using (mo) filters[mo["Name"]?.ToString() ?? ""] = mo["Query"]?.ToString() ?? "";

            var bindings = new List<(string Filter, string Consumer)>();
            using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Filter, Consumer FROM __FilterToConsumerBinding")))
                foreach (ManagementObject mo in s.Get())
                    using (mo) bindings.Add((mo["Filter"]?.ToString() ?? "", mo["Consumer"]?.ToString() ?? ""));

            void Check(string cls, Func<ManagementObject, string?> commandOf)
            {
                using var s = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {cls}"));
                foreach (ManagementObject mo in s.Get())
                {
                    using (mo)
                    {
                        string name = mo["Name"]?.ToString() ?? "?";
                        if (name == "BVTConsumer") continue; // bekannter Microsoft-Testconsumer
                        string? command = commandOf(mo);
                        var binding = bindings.FirstOrDefault(b => b.Consumer.Contains($"\"{name}\"", StringComparison.OrdinalIgnoreCase));
                        string? filterName = binding.Filter.Split('"').Skip(1).FirstOrDefault();
                        string? query = filterName != null && filters.TryGetValue(filterName, out var q) ? q : null;

                        var f = Evaluate(ctx, new Entry("WMI-Abonnement", $"{cls}: {name}", @"root\subscription", command, 55,
                            "WMI-Ereignisabonnement führt Code aus (dateilose Persistenz)"), f =>
                        {
                            if (binding.Consumer.Length == 0) f.AddIndicator("WMI_UNBOUND", "Consumer ohne Bindung (inaktiv / Rest)", -20);
                            f.Detail("Auslöser (WQL)", query).Detail("Consumer-Klasse", cls);
                        });
                        f?.Actions.Insert(0, new RemediationAction
                        {
                            Kind = RemediationKind.RemoveWmiSubscription,
                            Label = "WMI-Abonnement entfernen",
                            Target = $"{cls}.Name=\"{name}\"",
                            Argument = filterName,
                        });
                    }
                }
            }

            Check("CommandLineEventConsumer", mo => mo["CommandLineTemplate"]?.ToString() ?? mo["ExecutablePath"]?.ToString());
            Check("ActiveScriptEventConsumer", mo =>
            {
                string? file = mo["ScriptFileName"]?.ToString();
                if (!string.IsNullOrWhiteSpace(file)) return $"\"{file}\"";
                return "Skript: " + TextUtil.Truncate(mo["ScriptText"]?.ToString(), 500);
            });
        }
        catch (ManagementException ex)
        {
            ctx.Note("WMI-Abonnements nicht lesbar: " + ex.Message);
        }
        catch (UnauthorizedAccessException)
        {
            ctx.Note("WMI-Abonnements nicht lesbar (Adminrechte erforderlich).");
        }
    }

    // ------------------------------------------------------------------
    // Bedienungshilfen-Hintertuer
    // ------------------------------------------------------------------

    private static readonly HashSet<string> ShellOriginalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.dll", "explorer.exe", "taskmgr.exe", "regedit.exe", "mmc.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    private static readonly Lazy<HashSet<string>> ShellHashes = new(() =>
        new[] { "cmd.exe", "WindowsPowerShell\\v1.0\\powershell.exe", "taskmgr.exe", "regedt32.exe" }
            .Select(n => Path.Combine(PathUtil.System32, n))
            .Append(Path.Combine(PathUtil.WindowsDir, "explorer.exe"))
            .Select(Trust.FileTrustService.TryHash)
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase));

    private void ScanAccessibilityBackdoors(ScanContext ctx)
    {
        foreach (var exe in AccessibilityBinaries)
        {
            string path = Path.Combine(PathUtil.System32, exe);
            if (!File.Exists(path)) continue;
            var info = ctx.Trust.Get(path);
            string? orig = info.OriginalFilename?.Replace(".mui", "", StringComparison.OrdinalIgnoreCase);
            // Hinweis: Originalnamen weichen teils legitim ab (magnify -> ScreenMagnifier.exe, narrator -> SR.exe).
            // Entscheidend ist, ob die Datei in Wahrheit eine Shell ist oder gar keine Windows-Komponente.
            bool isShell = (orig != null && ShellOriginalNames.Contains(orig))
                           || (info.Sha256 != null && ShellHashes.Value.Contains(info.Sha256));
            bool replaced = !info.IsWindowsComponent || isShell;
            if (!replaced) continue;

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Persistence,
                Title = $"Bedienungshilfe ersetzt: {exe}",
                FilePath = path,
                Description = $"{exe} ist nicht die originale Windows-Datei" + (orig != null ? $" (eigentlich: {orig})." : "."),
                Explanation = "Angreifer ersetzen Bedienungshilfen (z. B. Einrastfunktion via 5x Shift) durch cmd.exe. Dann erhält jeder am " +
                              "Anmeldebildschirm ohne Passwort eine Kommandozeile mit SYSTEM-Rechten.",
                Recommendation = "Datei sofort mit 'sfc /scannow' (als Administrator) wiederherstellen lassen. Den PC als kompromittiert betrachten.",
            };
            f.AddIndicator("ACCESSIBILITY_REPLACED", "Systemdatei der Bedienungshilfen wurde ausgetauscht", 90);
            ExecutableAssessor.AddDetails(f, info);
            ctx.Add(f);
        }
    }

    // ------------------------------------------------------------------
    // PowerShell-Profile
    // ------------------------------------------------------------------

    private void ScanPowerShellProfiles(ScanContext ctx)
    {
        var candidates = new List<string>
        {
            Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\profile.ps1"),
            Path.Combine(PathUtil.System32, @"WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"),
            Path.Combine(PathUtil.ProgramFiles, @"PowerShell\7\profile.ps1"),
        };
        foreach (var profile in SystemEnv.UserProfiles())
            foreach (var docs in new[] { "Documents", @"OneDrive\Documents", @"OneDrive\Dokumente" })
                foreach (var sub in new[] { "WindowsPowerShell", "PowerShell" })
                    foreach (var file in new[] { "profile.ps1", "Microsoft.PowerShell_profile.ps1" })
                        candidates.Add(Path.Combine(profile, docs, sub, file));

        foreach (var file in candidates.Where(File.Exists))
        {
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Persistence,
                Title = $"PowerShell-Profil: {Path.GetFileName(file)}",
                FilePath = file,
                Location = Path.GetDirectoryName(file),
                Description = $"Das PowerShell-Profil {file} wird bei jedem Start von PowerShell ausgeführt.",
                Explanation = "Profile sind für Anpassungen gedacht, werden aber auch als unauffälliger Persistenzort genutzt (MITRE T1546.013).",
                Recommendation = "Inhalt prüfen. Wenn Sie das Profil nicht selbst angelegt haben: Datei in Quarantäne verschieben.",
            };
            f.AddIndicator("PS_PROFILE", "PowerShell-Profil vorhanden", 5);
            ScanScriptContent(f, file);
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Speicherort öffnen", Target = file, RequiresConfirmation = false });
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "In Quarantäne verschieben", Target = file });
            ctx.Add(f);
        }
    }
}
