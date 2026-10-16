using System.Windows;
using System.Windows.Input;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

namespace ApprovalAgent.Mock;

public partial class ApprovalMethodWindow : Window
{
    private readonly ApprovalMethodSelection _selection;
    public ApprovalMethodWindow(OfflineReviewWindow owner, OfflineReviewViewModel review, ApprovalMethodPreferences preferences, bool switching, bool firstRun)
    {
        Resources = owner.Resources; InitializeComponent(); Owner = owner;
        _selection = new ApprovalMethodSelection(review, preferences, switching); DataContext = _selection;
        Heading.Text = switching ? "CHANGE METHOD / SAME EFFECTIVE ACTION" : firstRun ? "WELCOME / CHOOSE AN OFFLINE METHOD" : "SETTINGS / APPROVAL METHOD";
        Explanation.Text = switching ? "Switch only this pending review. The action and expiry stay unchanged. Earlier method generations cannot decide this review."
            : "A works as a local offline preview. B and C are local simulations, not protected or remote channels. Save a default, change it later in Settings, or cancel and keep using the existing local preview.";
        SaveDefault.Visibility = switching ? Visibility.Visible : Visibility.Collapsed;
        ResetButton.Visibility = switching ? Visibility.Collapsed : Visibility.Visible;
        ApplyButton.Content = switching ? "_Apply method" : "_Save preference";
        // First use requires an explicit choice; no implicit B/C or default save.
        if (!firstRun) MethodPicker.SelectedItem = _selection.Options.SingleOrDefault(o => o.Method.Id == (switching ? review.SelectedMethod : review.PreferredMethod));
        Feedback.Text = _selection.Status;
    }
    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        var id = (MethodPicker.SelectedItem as MethodOption)?.Method.Id;
        if (_selection.Apply(id, SaveDefault.IsChecked == true)) DialogResult = true;
        else Feedback.Text = _selection.Status;
    }
    private void Reset_Click(object sender, RoutedEventArgs e)
    { if (_selection.Reset()) DialogResult = true; else Feedback.Text = _selection.Status; }
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void Window_KeyDown(object sender, KeyEventArgs e)
    { if (e.Key == Key.Escape) { DialogResult = false; e.Handled = true; } }
}
