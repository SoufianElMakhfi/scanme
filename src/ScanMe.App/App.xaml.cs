using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using ScanMe.App.ViewModels;
using ScanMe.Core.Actions;

namespace ScanMe.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        try
        {
            _ = AppPaths.DataDir;
        }
        catch (Exception ex)
        {
            MessageBox.Show("ScanMe kann seinen Datenordner nicht absichern und startet deshalb nicht:\n\n" + ex.Message,
                "ScanMe", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }
        if (AppPaths.SetAside.Count > 0 && Array.IndexOf(e.Args, "--render") < 0)
            MessageBox.Show("Im Datenordner von ScanMe lagen Einträge, die nicht von einem Administrator angelegt wurden – " +
                            "etwa von einer früheren Version ohne Adminrechte, möglicherweise aber auch von Schadsoftware. " +
                            "Sie werden nicht verwendet und wurden beiseitegelegt:\n\n" + string.Join("\n", AppPaths.SetAside.Take(10)) +
                            (AppPaths.SetAside.Count > 10 ? $"\n… und {AppPaths.SetAside.Count - 10} weitere" : ""),
                "ScanMe", MessageBoxButton.OK, MessageBoxImage.Warning);
        ScanMe.Core.Updates.AppUpdater.CleanupAfterUpdate();
        var window = new MainWindow();
        MainWindow = window;

        // Entwicklerhilfe: --render <png> [--scan quick|full] [--page Findings|Processes|...]
        int renderIdx = Array.IndexOf(e.Args, "--render");
        if (renderIdx >= 0 && renderIdx + 1 < e.Args.Length)
        {
            _ = RenderAndExit(window, e.Args[renderIdx + 1], Arg(e.Args, "--scan"), Arg(e.Args, "--page"));
            return;
        }
        window.Show();
    }

    private static string? Arg(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private async Task RenderAndExit(MainWindow window, string file, string? scan, string? page)
    {
        window.Headless = true;
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -10000;
        window.ShowInTaskbar = false;
        window.Show();
        var vm = (MainViewModel)window.DataContext;
        if (scan == "quick") await vm.StartQuickScanCommand.ExecuteAsync(null);
        else if (scan == "full") await vm.StartFullScanCommand.ExecuteAsync(null);
        if (page != null)
        {
            vm.NavigateCommand.Execute(page);
            if (page == "Processes")
                while (vm.Processes.IsLoading || vm.Processes.Rows.Count == 0) await Task.Delay(200);
            if (page == "Hardening")
                while (!vm.Hardening.Loaded) await Task.Delay(200);
        }
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(500);

        var root = (FrameworkElement)window.Content;
        var bmp = new RenderTargetBitmap((int)root.ActualWidth, (int)root.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using (var fs = File.Create(file)) enc.Save(fs);
        Shutdown();
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Unerwarteter Fehler:\n\n" + e.Exception.Message, "ScanMe", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
