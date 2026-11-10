using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;

namespace DesktopAgent.Fixture;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (!args.SequenceEqual(new[] { "--synthetic" })) return 2;
        var app = new Application();
        var window = new Window { Title = "Phase15 Synthetic Fixture", Width = 520, Height = 320,
            WindowStartupLocation = WindowStartupLocation.CenterScreen };
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = "Synthetic desktop automation fixture. No authorization or external effects.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) });
        var status = new TextBlock { Text = "Count: 0", Margin = new Thickness(0, 0, 0, 16) };
        AutomationProperties.SetAutomationId(status, "Counter");
        int count = 0;
        var increment = new Button { Content = "Increment synthetic counter", MinHeight = 44 };
        AutomationProperties.SetAutomationId(increment, "Increment");
        increment.Click += (_, _) => status.Text = "Count: " + (++count);
        var dialogButton = new Button { Content = "Open synthetic dialog", MinHeight = 44, Margin = new Thickness(0, 12, 0, 0) };
        AutomationProperties.SetAutomationId(dialogButton, "OpenDialog");
        dialogButton.Click += (_, _) => {
            var close = new Button { Content = "Close", IsCancel = true, MinHeight = 44, Margin = new Thickness(20) };
            AutomationProperties.SetAutomationId(close, "CloseDialog");
            var dialog = new Window { Title = "Phase15 Synthetic Dialog", Owner = window, Width = 300, Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = close };
            close.Click += (_, _) => dialog.Close();
            dialog.ShowDialog(); dialogButton.Focus();
        };
        panel.Children.Add(status); panel.Children.Add(increment); panel.Children.Add(dialogButton); window.Content = panel;
        window.Loaded += (_, _) => {
            increment.Focus();
            using var process = Process.GetCurrentProcess();
            using var file = File.OpenRead(process.MainModule!.FileName);
            Console.WriteLine(JsonSerializer.Serialize(new { processId = process.Id,
                startTicks = process.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
                executableSha256 = Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant() }));
            Console.Out.Flush();
        };
        var expiry = new DispatcherTimer { Interval = TimeSpan.FromMinutes(3) };
        expiry.Tick += (_, _) => app.Shutdown(); expiry.Start();
        return app.Run(window);
    }
}
