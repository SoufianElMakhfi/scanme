using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Actions;

namespace ScanMe.App.ViewModels;

public sealed partial class QuarantineViewModel : ObservableObject
{
    public ObservableCollection<QuarantineItem> Items { get; } = new();
    public ObservableCollection<UndoEntry> History { get; } = new();

    [ObservableProperty] private string? _message;
    public string DataDir => AppPaths.DataDir;

    [RelayCommand]
    private void Refresh()
    {
        Items.Clear();
        foreach (var i in Quarantine.List()) Items.Add(i);
        History.Clear();
        foreach (var e in UndoJournal.Load().OrderByDescending(e => e.When)) History.Add(e);
    }

    [RelayCommand]
    private void Restore(QuarantineItem item)
    {
        if (MessageBox.Show($"Datei wiederherstellen?\n\n{item.OriginalPath}\n\nNur tun, wenn Sie sicher sind, dass sie harmlos ist.",
                "ScanMe", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        Show(Quarantine.Restore(item.Id));
        Refresh();
    }

    [RelayCommand]
    private void Delete(QuarantineItem item)
    {
        if (MessageBox.Show($"Datei endgültig löschen?\n\n{item.OriginalPath}", "ScanMe", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        Show(Quarantine.Delete(item.Id));
        Refresh();
    }

    [RelayCommand]
    private void Undo(UndoEntry entry)
    {
        if (entry.Undone) return;
        if (MessageBox.Show($"Änderung rückgängig machen?\n\n{entry.Description}", "ScanMe", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        Show(UndoJournal.Undo(entry));
        Refresh();
    }

    [RelayCommand]
    private void OpenDataDir() => Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppPaths.DataDir}\"") { UseShellExecute = true });

    private void Show(ActionResult r) => Message = (r.Success ? "✔ " : "✖ ") + r.Message;
}
