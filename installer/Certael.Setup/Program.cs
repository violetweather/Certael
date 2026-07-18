using Avalonia;

namespace Certael.Setup;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        if (args is ["--self-test"])
        {
            _ = MainWindow.DetectRuntimeIdentifier();
            return;
        }
        SetupDiagnostics.Write("program-main");
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
            SetupDiagnostics.Write("desktop-lifetime-stopped");
        }
        catch (Exception exception)
        {
            SetupDiagnostics.Write($"startup-failed:{exception.GetType().Name}:{exception.Message}");
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .WithInterFont()
        .LogToTrace();
}

internal static class SetupDiagnostics
{
    public static void Write(string value)
    {
        string? path = Environment.GetEnvironmentVariable("CERTAEL_SETUP_DIAGNOSTIC_PATH");
        if (string.IsNullOrWhiteSpace(path)) return;
        try { File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} {value}{Environment.NewLine}"); }
        catch (Exception) { }
    }
}
