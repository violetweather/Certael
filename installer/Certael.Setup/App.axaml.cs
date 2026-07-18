using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace Certael.Setup;

public sealed partial class App : Application
{
    public override void Initialize()
    {
        SetupDiagnostics.Write("application-initialize");
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        SetupDiagnostics.Write($"framework-initialized:{ApplicationLifetime?.GetType().FullName ?? "none"}");
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            SetupDiagnostics.Write("creating-main-window");
            desktop.MainWindow = new MainWindow();
            desktop.MainWindow.Show();
            var handle = desktop.MainWindow.TryGetPlatformHandle();
            SetupDiagnostics.Write($"main-window-shown:visible={desktop.MainWindow.IsVisible}:handle={handle?.Handle ?? IntPtr.Zero}:kind={handle?.HandleDescriptor ?? "none"}");
        }
        base.OnFrameworkInitializationCompleted();
    }
}
