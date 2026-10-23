using System.Windows;
using ScanMe.App.ViewModels;
using Forms = System.Windows.Forms;

namespace ScanMe.App;

/// <summary>Symbol im Infobereich: Benachrichtigungen bei Warnungen der Echtzeitueberwachung.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Window _window;
    private readonly MainViewModel _vm;
    private FindingItemViewModel? _lastAlert;

    public TrayIcon(Window window, MainViewModel vm)
    {
        _window = window;
        _vm = vm;
        _icon = new Forms.NotifyIcon
        {
            Text = "ScanMe – Blue Team",
            Icon = LoadIcon(),
            Visible = true,
            ContextMenuStrip = BuildMenu(),
        };
        _icon.DoubleClick += (_, _) => ShowWindow();
        _icon.BalloonTipClicked += (_, _) =>
        {
            ShowWindow();
            if (_lastAlert != null) _vm.ShowMonitorEvent(_lastAlert);
        };
        vm.Monitor.Alert += OnAlert;
    }

    private static System.Drawing.Icon LoadIcon()
    {
        try
        {
            var res = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/scanme.ico"));
            if (res != null) return new System.Drawing.Icon(res.Stream, 16, 16);
        }
        catch { }
        return System.Drawing.SystemIcons.Shield;
    }

    private Forms.ContextMenuStrip BuildMenu()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("ScanMe öffnen", null, (_, _) => ShowWindow());
        var toggle = new Forms.ToolStripMenuItem("Überwachung aktiv");
        toggle.Click += (_, _) => _vm.Monitor.Toggle();
        menu.Opening += (_, _) => toggle.Checked = _vm.Monitor.IsRunning;
        menu.Items.Add(toggle);
        menu.Items.Add("Schnellscan starten", null, (_, _) =>
        {
            ShowWindow();
            if (_vm.StartQuickScanCommand.CanExecute(null)) _vm.StartQuickScanCommand.Execute(null);
        });
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Beenden", null, (_, _) => ((MainWindow)_window).ExitApplication());
        return menu;
    }

    private void OnAlert(FindingItemViewModel item)
    {
        _lastAlert = item;
        var icon = item.Severity >= Core.Models.Severity.High ? Forms.ToolTipIcon.Error : Forms.ToolTipIcon.Warning;
        string text = item.Description.Length > 200 ? item.Description[..199] + "…" : item.Description;
        _icon.ShowBalloonTip(8000, $"ScanMe: {item.Severity.ToString() switch { "Critical" => "Kritisch", "High" => "Hoch", _ => "Mittel" }} – {item.Title}", text, icon);
    }

    public void ShowWindow()
    {
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    public void ShowHint(string title, string text) => _icon.ShowBalloonTip(5000, title, text, Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _vm.Monitor.Alert -= OnAlert;
        _icon.Visible = false;
        _icon.Dispose();
    }
}
