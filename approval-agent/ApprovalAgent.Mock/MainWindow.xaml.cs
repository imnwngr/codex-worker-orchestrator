using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

namespace ApprovalAgent.Mock;

public partial class MainWindow : Window
{
    private readonly ApprovalViewModel _viewModel;
    private readonly DispatcherTimer _expiryTimer;
    private readonly WebAuthnDiagnosticsViewModel _diagnosticsViewModel = new();
    private readonly WindowsWebAuthnCapabilityDiagnosticService _diagnosticsService =
        new(new WindowsWebAuthnNativeApi());

    public MainWindow()
    {
        InitializeComponent();

        var proposal = new MockProposalSource().GetProposal();
        _viewModel = new ApprovalViewModel(proposal);
        DataContext = _viewModel;
        WebAuthnDiagnosticsSection.DataContext = _diagnosticsViewModel;

        _expiryTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _expiryTimer.Tick += ExpiryTimer_Tick;
        _expiryTimer.Start();
        Closed += (_, _) => _expiryTimer.Stop();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var result = await Task.Run(_diagnosticsService.GetDiagnostics);
            _diagnosticsViewModel.Apply(result);
        }
        catch
        {
            // Diagnostics must never affect the mock approval workflow.
            _diagnosticsViewModel.ApplyFailure();
        }
    }

    private void ApproveMock_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.ApproveMock();
    }

    private void OpenOfflineReview_Click(object sender, RoutedEventArgs e)
    {
        new OfflineReviewWindow(this).Show();
    }

    private void Reject_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.Reject();
    }

    private void ExpiryTimer_Tick(object? sender, EventArgs e)
    {
        _viewModel.RefreshExpiry();
        if (!_viewModel.CanApprove) _expiryTimer.Stop();
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _viewModel.CanReject)
        {
            _viewModel.Reject();
            e.Handled = true;
        }
    }
}
