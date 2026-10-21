using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using System.IO;
using System.Text;
using Microsoft.Win32;
using ApprovalAgent.Mock.ViewModels;
using ApprovalAgent.Mock.Services;

namespace ApprovalAgent.Mock;

public partial class OfflineReviewWindow : Window
{
    private readonly OfflineReviewViewModel _review = new();
    private readonly DispatcherTimer _timer;
    private readonly ApprovalMethodPreferences _preferences = new(ApprovalMethodPreferences.DefaultPath);
    private bool _offeredOnboarding;
    public OfflineReviewWindow(MainWindow owner)
    {
        Resources = new ResourceDictionary(); Resources.MergedDictionaries.Add(owner.Resources);
        // Use native system colors/styles when opened in Windows high contrast mode.
        if (SystemParameters.HighContrast) {
            foreach (var key in new[] { "CanvasBrush", "SurfaceBrush", "PaperBrush", "SurfaceMutedBrush" }) Resources[key] = SystemColors.WindowBrush;
            foreach (var key in new[] { "InkBrush", "SecondaryInkBrush", "LineBrush", "FocusBrush" }) Resources[key] = SystemColors.WindowTextBrush;
            Resources["HeaderSubtleBrush"] = SystemColors.WindowBrush;
            foreach (var key in new[] { "ActionButton", "PrimaryActionButton" }) Resources[key] = new Style(typeof(System.Windows.Controls.Button)) {
                Setters = { new Setter(MinHeightProperty, 40.0), new Setter(MarginProperty, new Thickness(4)) }
            };
            foreach (var key in new[] { "EyebrowText", "SectionTitle", "MutedText" }) Resources[key] = new Style(typeof(System.Windows.Controls.TextBlock)) {
                Setters = { new Setter(System.Windows.Controls.TextBlock.ForegroundProperty, SystemColors.WindowTextBrush), new Setter(System.Windows.Controls.TextBlock.TextWrappingProperty, TextWrapping.Wrap) }
            };
            Resources["ReviewCard"] = new Style(typeof(System.Windows.Controls.Border)) {
                Setters = { new Setter(System.Windows.Controls.Border.BackgroundProperty, SystemColors.WindowBrush), new Setter(System.Windows.Controls.Border.PaddingProperty, new Thickness(16)) }
            };
            Resources["ReviewTextBox"] = new Style(typeof(System.Windows.Controls.TextBox));
        }
        Resources["BoolVisibility"] = new System.Windows.Controls.BooleanToVisibilityConverter();
        InitializeComponent(); Owner = owner; DataContext = _review;
        var preference = _preferences.Read(); _review.SetPreference(preference.PreferredMethod);
        Loaded += (_, _) => { OfferOnboarding(); SelectFileButton.Focus(); };
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => _review.RefreshExpiry(); _timer.Start();
        Closed += (_, _) => { _timer.Stop(); _review.DecideCurrent(OfflineMockState.Cancelled); };
    }
    private void OfferOnboarding()
    {
        if (_offeredOnboarding || _review.PreferredMethod is not null) return;
        _offeredOnboarding = true;
        new ApprovalMethodWindow(this, _review, _preferences, false, true).ShowDialog();
    }
    private void MethodSettings_Click(object sender, RoutedEventArgs e) { new ApprovalMethodWindow(this, _review, _preferences, false, _review.PreferredMethod is null).ShowDialog(); SelectFileButton.Focus(); }
    private void ChangeMethod_Click(object sender, RoutedEventArgs e)
    { _review.RefreshExpiry(); if (_review.CanSwitch) new ApprovalMethodWindow(this, _review, _preferences, true, false).ShowDialog(); SelectFileButton.Focus(); }
    private void SelectFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select untrusted offline synthetic review data", Filter = "Offline review (*.review.json)|*.review.json", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) == true) _review.LoadFile(dialog.FileName);
    }
    private void CreateDemo_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "Create a new offline synthetic demo", Filter = "Offline review (*.review.json)|*.review.json" };
        if (dialog.ShowDialog(this) == true) {
            try {
                OfflineDemoFiles.WriteNew(dialog.FileName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                _review.LoadFile(dialog.FileName);
            } catch { _review.ReportOperationFailure("DEMO_CREATE_FAILED; choose a new filename on a local fixed volume."); }
        }
        SelectFileButton.Focus();
    }
    private void Simulate(string action)
    { if (_review.SimulationToken is { } token) _review.Simulate(action, token, _review.Simulation.FixtureId); else _review.ReportUnavailable(); }
    private void UnavailablePreview_Click(object sender, RoutedEventArgs e) => Simulate("UNAVAILABLE");
    private void FailurePreview_Click(object sender, RoutedEventArgs e) => Simulate("FAIL");
    private void StartPreview_Click(object sender, RoutedEventArgs e) => _review.StartInteractivePreview();
    private void ApprovePreview_Click(object sender, RoutedEventArgs e) => _review.RespondInteractivePreview("GRANT");
    private void DenyPreview_Click(object sender, RoutedEventArgs e) => _review.RespondInteractivePreview("DENY");
    private void CancelPreview_Click(object sender, RoutedEventArgs e) => _review.RespondInteractivePreview("CANCEL");
    private void UnknownPreview_Click(object sender, RoutedEventArgs e) => _review.RespondInteractivePreview("UNKNOWN");
    private void CrashPreview_Click(object sender, RoutedEventArgs e) => _review.CrashInteractivePreview();
    private void RecoverPreview_Click(object sender, RoutedEventArgs e) => _review.RecoverInteractivePreview();
    private void ExportBrowser_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "Export untrusted offline browser preview", Filter = "Browser preview (*.browser.json)|*.browser.json" };
        if (dialog.ShowDialog(this) != true) return;
        var json = _review.ExportBrowserPackage();
        if (json is null) return;
        try { BrowserPreviewFiles.WritePackage(dialog.FileName, json); }
        catch { _review.ReportOperationFailure("Browser export failed; choose a new local filename."); }
    }
    private void ImportBrowser_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import untrusted browser response", Filter = "Synthetic response (*.response.json)|*.response.json", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try { _review.ImportBrowserResponse(BrowserPreviewFiles.ReadResponse(dialog.FileName)); }
        catch { _review.ReportOperationFailure("Browser response unreadable, nonlocal or oversized; current review retained."); }
    }
    private void StartSimulation_Click(object sender, RoutedEventArgs e) => Simulate("START");
    private void DeliverSimulation_Click(object sender, RoutedEventArgs e) => Simulate("DELIVER");
    private void CompleteSimulation_Click(object sender, RoutedEventArgs e) => Simulate("COMPLETE");
    private void UnknownSimulation_Click(object sender, RoutedEventArgs e) => Simulate("UNKNOWN");
    private void RecoverSimulation_Click(object sender, RoutedEventArgs e) => Simulate("RECOVER");
    private void Reject_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.Rejected);
    private void Abandon_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.Cancelled);
    private void Cancel_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.Cancelled);
    private void ApproveMock_Click(object sender, RoutedEventArgs e) => _review.DecideCurrent(OfflineMockState.ApprovedMock);
    private void Window_KeyDown(object sender, KeyEventArgs e)
    { if (e.Key == Key.Escape) { _review.DecideCurrent(OfflineMockState.Rejected); e.Handled = true; } }
}
