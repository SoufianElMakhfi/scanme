using System.ComponentModel;
using System.Windows;
using ScanMe.App.ViewModels;

namespace ScanMe.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        // Navigationsmarkierung synchron halten, wenn aus dem Code heraus navigiert wird (z. B. Klick auf Fund im Dashboard)
        _vm.PropertyChanged += OnViewModelChanged;
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(MainViewModel.CurrentPage)) return;
        if (_vm.CurrentPage == _vm.Findings) NavFindings.IsChecked = true;
        else if (_vm.CurrentPage == _vm.Dashboard) NavDashboard.IsChecked = true;
    }
}
