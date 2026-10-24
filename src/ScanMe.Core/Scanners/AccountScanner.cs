using System.Management;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Lokale Benutzerkonten: Angreifer legen nach einem Einbruch gern versteckte Admin-Konten an.
/// </summary>
public sealed class AccountScanner : IScanner
{
    public string Id => "accounts";
    public string Name => "Benutzerkonten";
    public string Description => "Versteckte, neue oder ungeschützte Konten und Mitglieder der Administratorgruppe.";
    public bool InQuickScan => true;

    private sealed record Account(string Name, string Sid, bool Disabled, bool PasswordRequired, bool Lockout);

    public Task ScanAsync(ScanContext ctx)
    {
        var accounts = new List<Account>();
        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name, SID, Disabled, PasswordRequired, Lockout FROM Win32_UserAccount WHERE LocalAccount = TRUE");
            foreach (ManagementObject mo in s.Get())
                using (mo)
                    accounts.Add(new Account(mo["Name"]?.ToString() ?? "", mo["SID"]?.ToString() ?? "",
                        mo["Disabled"] as bool? ?? false, mo["PasswordRequired"] as bool? ?? true, mo["Lockout"] as bool? ?? false));
        }
        catch (Exception ex)
        {
            ctx.Note("Benutzerkonten nicht lesbar: " + ex.Message);
            return Task.CompletedTask;
        }

        var admins = AdminMembers();
        var hiddenFromLogon = RegistryUtil.Values(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList")
            .Where(v => v.Value is int i && i == 0).Select(v => v.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var a in accounts)
        {
            bool builtin = a.Sid.EndsWith("-500") || a.Sid.EndsWith("-501") || a.Sid.EndsWith("-503") || a.Sid.EndsWith("-504")
                           || a.Name is "WDAGUtilityAccount" or "DefaultAccount";
            bool isAdmin = admins.Contains(a.Name);
            // Profilordner ueber die SID ermitteln – der Ordnername muss nicht dem Kontonamen entsprechen.
            string? profileDir = RegistryUtil.GetString($@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{a.Sid}", "ProfileImagePath");
            profileDir = profileDir != null ? Environment.ExpandEnvironmentVariables(profileDir) : null;
            DateTime? created = profileDir != null && Directory.Exists(profileDir) ? Directory.GetCreationTime(profileDir) : null;

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Account,
                Title = $"Benutzerkonto: {a.Name}",
                Location = a.Sid,
            };
            f.Detail("SID", a.Sid).Detail("Administrator", isAdmin ? "ja" : "nein").Detail("Status", a.Disabled ? "deaktiviert" : "aktiv")
             .Detail("Profilordner", profileDir).Detail("Profil angelegt", created?.ToString("g"));
            f.At(created, "Erste Anmeldung (Profil angelegt)");

            if (a.Disabled)
            {
                if (!builtin && hiddenFromLogon.Contains(a.Name)) f.AddIndicator("HIDDEN_DISABLED", "Deaktiviertes, vom Anmeldebildschirm verstecktes Konto", 10);
            }
            else
            {
                if (a.Name.EndsWith('$'))
                    f.AddIndicator("DOLLAR_NAME", "Kontoname endet auf '$' – wird in vielen Ansichten ausgeblendet (Tarnung)", 60);
                if (hiddenFromLogon.Contains(a.Name) && !builtin)
                    f.AddIndicator("HIDDEN_LOGON", "Konto ist vom Anmeldebildschirm ausgeblendet", 45);
                if (a.Sid.EndsWith("-501"))
                    f.AddIndicator("GUEST_ON", "Gastkonto ist aktiviert", 35);
                if (a.Sid.EndsWith("-500"))
                    f.AddIndicator("BUILTIN_ADMIN_ON", "Eingebautes Administratorkonto ist aktiviert (beliebtes Ziel für Passwortraten)", 25);
                // Das Flag ist bei Microsoft-Konten/PIN-Anmeldung haeufig gesetzt und allein wenig aussagekraeftig.
                if (!a.PasswordRequired)
                    f.AddIndicator("NO_PASSWORD", "Konto-Flag 'kein Passwort erforderlich' gesetzt (bei Microsoft-Konten häufig normal)", isAdmin && !builtin ? 5 : 10);
                if (isAdmin && !builtin && created is { } c && (DateTime.Now - c).TotalDays < 14)
                    f.AddIndicator("NEW_ADMIN", $"Neues Administratorkonto (Profil angelegt am {c:d})", 25);
                if (isAdmin && created == null && !builtin)
                    f.AddIndicator("ADMIN_NO_PROFILE", "Administratorkonto, mit dem sich noch nie jemand angemeldet hat", 15);
            }

            if (f.Indicators.Sum(i => i.Weight) < 15) continue;
            f.Description = $"Lokales Konto '{a.Name}'{(isAdmin ? " (Administrator)" : "")}, {(a.Disabled ? "deaktiviert" : "aktiv")}.";
            f.Explanation = "Nach einem Einbruch legen Angreifer häufig eigene, möglichst unauffällige Konten an, um jederzeit zurückzukommen (MITRE T1136).";
            f.Recommendation = "Kennen Sie dieses Konto? Falls nicht: In 'Computerverwaltung → Lokale Benutzer und Gruppen' deaktivieren, danach alle Passwörter ändern.";
            ctx.Add(f);
        }

        int activeAdmins = accounts.Count(a => !a.Disabled && admins.Contains(a.Name));
        if (activeAdmins > 2)
        {
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Account,
                Title = "Viele Administratorkonten",
                Description = $"{activeAdmins} aktive Konten haben Administratorrechte: {string.Join(", ", accounts.Where(a => !a.Disabled && admins.Contains(a.Name)).Select(a => a.Name))}.",
                Explanation = "Jedes Admin-Konto ist ein mögliches Einfallstor. Für den Alltag empfiehlt sich ein Standardkonto.",
                Recommendation = "Nicht benötigte Admin-Konten zu Standardbenutzern herabstufen.",
            };
            f.AddIndicator("MANY_ADMINS", "Mehr als zwei aktive Administratoren", 15);
            ctx.Add(f);
        }
        return Task.CompletedTask;
    }

    private static HashSet<string> AdminMembers()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var s = new ManagementObjectSearcher("SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='" +
                                                       Environment.MachineName + "',Name='" + AdminGroupName() + "'\"");
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    string part = mo["PartComponent"]?.ToString() ?? "";
                    int idx = part.IndexOf("Name=\"", StringComparison.Ordinal);
                    if (idx >= 0) set.Add(part[(idx + 6)..].TrimEnd('"'));
                }
            }
        }
        catch { }
        return set;
    }

    private static string AdminGroupName()
    {
        try
        {
            return new System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
                .Translate(typeof(System.Security.Principal.NTAccount)).Value.Split('\\').Last();
        }
        catch { return "Administrators"; }
    }
}
