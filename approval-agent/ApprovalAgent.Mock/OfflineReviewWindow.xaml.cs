using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using ApprovalAgent.Mock.ViewModels;

namespace ApprovalAgent.Mock;

public partial class OfflineReviewWindow : Window
{
    private readonly OfflineReviewViewModel _review = new();
    private readonly DispatcherTimer _timer;
    public OfflineReviewWindow(MainWindow owner)
    {
        Resources = owner.Resources;
        InitializeComponent(); Owner = owner; DataContext = _review;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => _review.RefreshExpiry(); _timer.Start();
        Closed += (_, _) => { _timer.Stop(); _review.DecideCurrent(OfflineMockState.Cancelled); };
    }
    private void SelectFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select untrusted offline synthetic review data", Filter = "Offline review (*.review.json)|*.review.json", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) == true) _review.LoadFile(dialog.FileName);
    }
    private void Reject_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.Rejected);
    private void Cancel_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.Cancelled);
    private void ApproveMock_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.ApprovedMock);
    private void Window_KeyDown(object sender, KeyEventArgs e)
    { if (e.Key == Key.Escape) { _review.DecideCurrent(OfflineMockState.Rejected); e.Handled = true; } }
}
