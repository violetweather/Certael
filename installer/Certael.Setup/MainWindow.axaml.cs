using System.Runtime.InteropServices;
using System.Text;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Certael.Installer;

namespace Certael.Setup;

public sealed partial class MainWindow : Window
{
    private static readonly IBrush Accent = Brush.Parse("#58C7D4");
    private static readonly IBrush Secondary = Brush.Parse("#B7C3D0");
    private static readonly IBrush Muted = Brush.Parse("#8F9EAE");
    private static readonly IBrush Failure = Brush.Parse("#FFB4A9");

    private readonly StringBuilder log = new();
    private CancellationTokenSource? activeOperation;
    private byte[]? verifiedEnvelope;
    private SuiteVerificationKeyRing? verifiedKeys;
    private CertaelProjectConfiguration? verifiedConfiguration;
    private CertaelSuiteManifest? verifiedManifest;
    private InstalledSuiteState? verifiedInstalledState;
    private Guid verifiedRecoveryPlan;

    public MainWindow()
    {
        InitializeComponent();
        OperationBox.ItemsSource = OperationChoice.All;
        OperationBox.SelectedIndex = 0;
        RuntimeBox.ItemsSource = RuntimeChoice.All;
        string detected = DetectRuntimeIdentifier();
        RuntimeBox.SelectedItem = RuntimeChoice.All.First(value => value.Identifier == detected);
        RuntimeBadge.Text = detected;
        CacheRootBox.Text = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Certael", "cache");

        OperationBox.SelectionChanged += (_, _) => OperationChanged();
        RuntimeBox.SelectionChanged += (_, _) => InvalidateVerification();
        ManifestPathBox.TextChanged += (_, _) => InvalidateVerification();
        TrustStorePathBox.TextChanged += (_, _) => InvalidateVerification();
        ConfigurationPathBox.TextChanged += (_, _) => InvalidateVerification();
        InstallRootBox.TextChanged += (_, _) => InvalidateVerification();
        CacheRootBox.TextChanged += (_, _) => InvalidateVerification();
        RecoveryPlanBox.TextChanged += (_, _) => InvalidateVerification();

        BrowseManifestButton.Click += async (_, _) => await PickFile(
            ManifestPathBox, "Choose signed suite manifest", [JsonFiles]);
        BrowseTrustButton.Click += async (_, _) => await PickFile(
            TrustStorePathBox, "Choose release trust store", [JsonFiles]);
        BrowseConfigurationButton.Click += async (_, _) => await PickFile(
            ConfigurationPathBox, "Choose Certael project configuration", [YamlFiles]);
        BrowseInstallRootButton.Click += async (_, _) => await PickFolder(
            InstallRootBox, "Choose installation directory");
        BrowseCacheButton.Click += async (_, _) => await PickFolder(
            CacheRootBox, "Choose verified artifact cache");
        VerifyButton.Click += VerifyClicked;
        BackButton.Click += (_, _) => ShowChoose();
        ApplyButton.Click += ApplyClicked;
        CancelButton.Click += (_, _) => activeOperation?.Cancel();
        StartOverButton.Click += (_, _) => ResetForAnotherOperation();
        CloseButton.Click += (_, _) => Close();
        SaveLogButton.Click += SaveLogClicked;

        AppendLog("Certael Setup started. Technical output is redacted before display.");
        OperationChanged();
    }

    private SetupOperation SelectedOperation =>
        (OperationBox.SelectedItem as OperationChoice)?.Operation ?? SetupOperation.Install;

    private string SelectedRuntime =>
        (RuntimeBox.SelectedItem as RuntimeChoice)?.Identifier ?? DetectRuntimeIdentifier();

    private async void VerifyClicked(object? sender, RoutedEventArgs args)
    {
        VerifyButton.IsEnabled = false;
        InputMessageBorder.IsVisible = false;
        try
        {
            await VerifySelectionAsync();
            ShowReview();
        }
        catch (Exception exception)
        {
            string message = PublicError(exception);
            AppendLog($"Verification failed: {message}");
            InputMessageTitle.Text = "Could not verify this operation";
            InputMessageTitle.Foreground = Failure;
            InputMessageText.Text = message;
            InputMessageBorder.IsVisible = true;
            InputMessageBorder.BringIntoView();
        }
        finally { VerifyButton.IsEnabled = true; }
    }

    private async Task VerifySelectionAsync()
    {
        InvalidateVerification();
        string root = RequireInstallRoot();
        SetupOperation operation = SelectedOperation;
        AppendLog($"Verifying {operation.ToString().ToLowerInvariant()} request for {SelectedRuntime}.");

        if (operation is SetupOperation.Install or SetupOperation.Update or SetupOperation.Repair)
        {
            string manifestPath = RequireFile(ManifestPathBox.Text, "signed suite manifest");
            string trustPath = RequireFile(TrustStorePathBox.Text, "release trust store");
            string configurationPath = RequireFile(ConfigurationPathBox.Text, "project configuration");
            string cache = RequireDirectorySelection(CacheRootBox.Text, "download cache");
            Directory.CreateDirectory(cache);
            verifiedEnvelope = await File.ReadAllBytesAsync(manifestPath);
            verifiedKeys = await SuiteTrustStoreCodec.LoadAsync(trustPath, CancellationToken.None);
            verifiedManifest = SignedSuiteManifestCodec.Verify(
                verifiedEnvelope, verifiedKeys, DateTimeOffset.UtcNow);
            verifiedConfiguration = CertaelProjectConfigurationCodec.Decode(
                await File.ReadAllTextAsync(configurationPath));
            IReadOnlyList<CertaelResolvedComponent> components = CertaelSuiteResolver.Resolve(
                verifiedManifest, verifiedConfiguration.RequiredComponents(), SelectedRuntime);
            ComponentList.ItemsSource = components.Select(component =>
                $"{component.Id}  ·  {component.Version}").ToArray();
            VerifiedTitle.Text = $"Signed suite {verifiedManifest.SuiteVersion} verified";
            VerifiedDetail.Text = $"{components.Count} components resolve for {SelectedRuntime}. "
                + $"The destination is {root}.";
            ComponentReviewPanel.IsVisible = true;
        }
        else if (operation is SetupOperation.Inspect or SetupOperation.Uninstall)
        {
            verifiedInstalledState = await CertaelInstallationLifecycle.LoadStateAsync(
                root, CancellationToken.None);
            SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
                root, verifiedInstalledState, CancellationToken.None);
            ComponentList.ItemsSource = verifiedInstalledState.Components.Select(component =>
                $"{component.Id}  ·  {component.Version}").ToArray();
            int drift = inspection.Files.Count(value => value.Health != InstalledFileHealth.Healthy);
            VerifiedTitle.Text = $"Installed suite {verifiedInstalledState.SuiteVersion} inspected";
            VerifiedDetail.Text = inspection.Healthy
                ? $"All {inspection.Files.Count} managed files match their signed inventory."
                : $"{drift} of {inspection.Files.Count} managed files require attention.";
            ComponentReviewPanel.IsVisible = true;
        }
        else
        {
            if (!Guid.TryParse(RecoveryPlanBox.Text, out verifiedRecoveryPlan)
                || verifiedRecoveryPlan == Guid.Empty)
                throw new ConfigurationException("Enter the plan ID printed by the interrupted operation.");
            VerifiedTitle.Text = "Recovery journal located by plan ID";
            VerifiedDetail.Text = $"Setup will validate and roll back plan {verifiedRecoveryPlan}.";
            ComponentReviewPanel.IsVisible = false;
        }
        ApplyButton.Content = ActionLabel(operation);
        MutationNotice.Text = MutationCopy(operation);
        AppendLog("Verification completed. No installation files were changed.");
    }

    private async void ApplyClicked(object? sender, RoutedEventArgs args)
    {
        ShowProgress();
        activeOperation = new CancellationTokenSource();
        var observer = new UiInstallerObserver(AppendEvent);
        try
        {
            string root = RequireInstallRoot();
            string cache = Path.GetFullPath(CacheRootBox.Text ?? string.Empty);
            using var client = new HttpClient { Timeout = TimeSpan.FromHours(2) };
            var installer = new CertaelSuiteInstaller(client, TimeProvider.System);
            string result = SelectedOperation switch
            {
                SetupOperation.Install => Describe(await installer.InstallAsync(
                    verifiedEnvelope!, verifiedKeys!, verifiedConfiguration!, SelectedRuntime,
                    root, cache, observer, activeOperation.Token), "installed"),
                SetupOperation.Update => Describe(await installer.UpdateAsync(
                    verifiedEnvelope!, verifiedKeys!, verifiedConfiguration!, root, cache,
                    forceModified: false, observer, activeOperation.Token), "updated"),
                SetupOperation.Repair => Describe(await installer.RepairAsync(
                    verifiedEnvelope!, verifiedKeys!, verifiedConfiguration!, root, cache,
                    forceModified: false, observer, activeOperation.Token), "repaired"),
                SetupOperation.Inspect => await InspectResult(root, activeOperation.Token),
                SetupOperation.Uninstall => await UninstallResult(
                    root, observer, activeOperation.Token),
                SetupOperation.Recover => await RecoverResult(
                    root, observer, activeOperation.Token),
                _ => throw new InvalidOperationException("Unknown setup operation.")
            };
            ShowResult(true, ResultTitleFor(SelectedOperation), result);
        }
        catch (OperationCanceledException)
        {
            AppendLog("Operation cancelled. Any completed mutations were rolled back.");
            ShowResult(false, "Operation cancelled safely",
                "No further operations will run. If mutation had started, setup attempted rollback and retained the transaction journal for recovery.");
        }
        catch (Exception exception)
        {
            string message = PublicError(exception);
            AppendLog($"Operation failed: {message}");
            ShowResult(false, "Setup could not complete", message
                + " Review the redacted technical log. If a plan ID was created, use Recover after correcting the cause.");
            DetailsExpander.IsExpanded = true;
        }
        finally
        {
            activeOperation.Dispose();
            activeOperation = null;
        }
    }

    private async Task<string> InspectResult(string root, CancellationToken cancellationToken)
    {
        InstalledSuiteState state = verifiedInstalledState
            ?? await CertaelInstallationLifecycle.LoadStateAsync(root, cancellationToken);
        SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
            root, state, cancellationToken);
        foreach (InstalledFileInspection file in inspection.Files.Where(value =>
                     value.Health != InstalledFileHealth.Healthy))
            AppendLog($"{file.Health}: {file.File.Path}");
        return inspection.Healthy
            ? $"All {inspection.Files.Count} managed files match suite {state.SuiteVersion}."
            : $"{inspection.Files.Count(value => value.Health != InstalledFileHealth.Healthy)} "
                + "managed files differ from the installed inventory. No files were changed.";
    }

    private async Task<string> UninstallResult(string root, IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        InstalledSuiteState state = verifiedInstalledState
            ?? await CertaelInstallationLifecycle.LoadStateAsync(root, cancellationToken);
        InstallationPlan plan = CertaelInstallationLifecycle.CreateUninstallPlan(
            root, state, forceModified: false, DateTimeOffset.UtcNow);
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .ApplyAsync(plan, observer, cancellationToken);
        return $"Removed suite {state.SuiteVersion}. Operator-owned files were preserved. "
            + $"Recovery journal: {result.JournalPath}";
    }

    private async Task<string> RecoverResult(string root, IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .RecoverAsync(root, verifiedRecoveryPlan, observer, cancellationToken);
        return $"Plan {result.PlanId} was rolled back from its validated journal. "
            + $"Journal: {result.JournalPath}";
    }

    private static string Describe(SuiteInstallResult result, string verb) =>
        $"Suite {result.Manifest.SuiteVersion} was {verb}: "
        + $"{result.State.Components.Count} components and {result.State.Files.Count} managed files. "
        + $"Recovery journal: {result.Installation.JournalPath}";

    private void ShowChoose()
    {
        ChoosePanel.IsVisible = true;
        ReviewPanel.IsVisible = false;
        ProgressPanel.IsVisible = false;
        ResultPanel.IsVisible = false;
        PageTitle.Text = "Set up Certael";
        PageSubtitle.Text = "Choose an operation and the signed release inputs.";
        SetActions(SetupPhase.Choose);
        SetPhases(1);
    }

    private void ShowReview()
    {
        ChoosePanel.IsVisible = false;
        ReviewPanel.IsVisible = true;
        ProgressPanel.IsVisible = false;
        ResultPanel.IsVisible = false;
        PageTitle.Text = "Review the verified plan";
        PageSubtitle.Text = "Nothing has changed yet. Confirm the selected release and destination.";
        SetActions(SetupPhase.Review);
        SetPhases(2);
    }

    private void ShowProgress()
    {
        ChoosePanel.IsVisible = false;
        ReviewPanel.IsVisible = false;
        ProgressPanel.IsVisible = true;
        ResultPanel.IsVisible = false;
        ProgressTitle.Text = $"{ActionLabel(SelectedOperation)} in progress";
        ProgressMessage.Text = "The installer is reporting each verified operation below.";
        PageTitle.Text = "Applying the verified plan";
        PageSubtitle.Text = "Downloads, verification, mutation, and rollback remain visible.";
        SetActions(SetupPhase.Progress);
        SetPhases(3);
    }

    private void ShowResult(bool success, string title, string message)
    {
        ChoosePanel.IsVisible = false;
        ReviewPanel.IsVisible = false;
        ProgressPanel.IsVisible = false;
        ResultPanel.IsVisible = true;
        ResultSymbol.Text = success ? "✓" : "!";
        ResultSymbol.Foreground = success ? Accent : Failure;
        ResultTitle.Text = title;
        ResultMessage.Text = message;
        PageTitle.Text = success ? "Operation complete" : "Setup needs attention";
        PageSubtitle.Text = success
            ? "The final result and recovery evidence are recorded below."
            : "No hidden retry or weakened verification was used.";
        SetActions(SetupPhase.Result);
        SetPhases(3);
    }

    private void SetActions(SetupPhase phase)
    {
        ChooseActions.IsVisible = phase == SetupPhase.Choose;
        ReviewActions.IsVisible = phase == SetupPhase.Review;
        ProgressActions.IsVisible = phase == SetupPhase.Progress;
        ResultActions.IsVisible = phase == SetupPhase.Result;
    }

    private void SetPhases(int active)
    {
        SetPhase(PhaseChooseNumber, PhaseChooseText, active, 1);
        SetPhase(PhaseReviewNumber, PhaseReviewText, active, 2);
        SetPhase(PhaseApplyNumber, PhaseApplyText, active, 3);
    }

    private static void SetPhase(TextBlock number, TextBlock label, int active, int phase)
    {
        number.Text = phase < active ? "✓" : phase.ToString();
        number.Foreground = phase <= active ? Accent : Muted;
        label.Foreground = phase == active ? Brushes.White : phase < active ? Secondary : Muted;
        label.FontWeight = phase == active ? FontWeight.SemiBold : FontWeight.Normal;
    }

    private void OperationChanged()
    {
        InvalidateVerification();
        SetupOperation operation = SelectedOperation;
        bool signed = operation is SetupOperation.Install or SetupOperation.Update or SetupOperation.Repair;
        SignedInputPanel.IsVisible = signed;
        CachePanel.IsVisible = signed;
        RuntimePanel.IsVisible = operation == SetupOperation.Install;
        RecoveryPanel.IsVisible = operation == SetupOperation.Recover;
        VerifyButton.Content = operation switch
        {
            SetupOperation.Inspect => "Inspect installed suite",
            SetupOperation.Recover => "Review recovery",
            _ => "Verify and review"
        };
        ShowChoose();
    }

    private void ResetForAnotherOperation()
    {
        InvalidateVerification();
        InputMessageBorder.IsVisible = false;
        ShowChoose();
    }

    private void InvalidateVerification()
    {
        verifiedEnvelope = null;
        verifiedKeys = null;
        verifiedConfiguration = null;
        verifiedManifest = null;
        verifiedInstalledState = null;
        verifiedRecoveryPlan = Guid.Empty;
    }

    private void AppendEvent(InstallerEvent value)
    {
        Dispatcher.UIThread.Post(() =>
        {
            string details = string.Join(", ", InstallerSecretRedactor.Redact(value.Details)
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
            string line = $"[{value.OccurredAt:HH:mm:ss}] {value.Level} {value.Kind}: "
                + InstallerSecretRedactor.Redact(value.Message);
            if (details.Length > 0) line += $" ({details})";
            AppendLog(line);
            ProgressMessage.Text = InstallerSecretRedactor.Redact(value.Message);
        });
    }

    private void AppendLog(string value)
    {
        string safe = InstallerSecretRedactor.Redact(value);
        log.AppendLine(safe);
        LogBox.Text = log.ToString();
        LogBox.CaretIndex = LogBox.Text.Length;
    }

    private async void SaveLogClicked(object? sender, RoutedEventArgs args)
    {
        IStorageFile? file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save redacted Certael setup log",
            SuggestedFileName = $"certael-setup-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.log",
            FileTypeChoices = [LogFiles]
        });
        if (file is null) return;
        await using Stream stream = await file.OpenWriteAsync();
        stream.SetLength(0);
        await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        await writer.WriteAsync(log.ToString());
        AppendLog("Redacted log saved by operator.");
    }

    private async Task PickFile(TextBox target, string title, IReadOnlyList<FilePickerFileType> types)
    {
        IReadOnlyList<IStorageFile> files = await StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions { Title = title, AllowMultiple = false, FileTypeFilter = types });
        if (files.Count > 0) target.Text = files[0].Path.LocalPath;
    }

    private async Task PickFolder(TextBox target, string title)
    {
        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(
            new FolderPickerOpenOptions { Title = title, AllowMultiple = false });
        if (folders.Count > 0) target.Text = folders[0].Path.LocalPath;
    }

    private string RequireInstallRoot()
    {
        string root = RequireDirectorySelection(InstallRootBox.Text, "installation directory");
        string full = Path.GetFullPath(root);
        if (Path.GetPathRoot(full) == full)
            throw new ConfigurationException("Installation directory cannot be a filesystem root.");
        if (SelectedOperation != SetupOperation.Install && !Directory.Exists(full))
            throw new ConfigurationException("The selected installation directory does not exist.");
        return full;
    }

    private static string RequireFile(string? value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ConfigurationException($"Choose the {label}.");
        string path = Path.GetFullPath(value);
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null)
            throw new ConfigurationException($"The selected {label} is missing or is a link.");
        return path;
    }

    private static string RequireDirectorySelection(string? value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ConfigurationException($"Choose the {label}.");
        return Path.GetFullPath(value);
    }

    private static string PublicError(Exception exception)
    {
        string message = exception switch
        {
            ConfigurationException or IOException or HttpRequestException
                or System.Security.Cryptography.CryptographicException => exception.Message,
            _ => "An unexpected local error stopped setup."
        };
        return InstallerSecretRedactor.Redact(message);
    }

    private static string ActionLabel(SetupOperation operation) => operation switch
    {
        SetupOperation.Install => "Install Certael",
        SetupOperation.Update => "Update Certael",
        SetupOperation.Repair => "Repair Certael",
        SetupOperation.Inspect => "Run inspection",
        SetupOperation.Uninstall => "Uninstall Certael",
        SetupOperation.Recover => "Recover interrupted plan",
        _ => "Continue"
    };

    private static string MutationCopy(SetupOperation operation) => operation switch
    {
        SetupOperation.Install => "Certael will download only signed HTTPS artifacts, verify every digest, preflight archive paths, and apply one recoverable transaction.",
        SetupOperation.Update => "The update preserves operator-owned files and refuses modified managed files. No in-place mutation begins until the new release is verified.",
        SetupOperation.Repair => "Repair restores the exact installed release and refuses modified managed files. It does not silently replace operator changes.",
        SetupOperation.Inspect => "Inspection hashes managed files and reports drift. It does not change the installation.",
        SetupOperation.Uninstall => "Uninstall removes only healthy installer-owned files and preserves declared operator-owned files. Modified files stop the operation.",
        SetupOperation.Recover => "Recovery validates every journal and backup path before rolling an interrupted plan back.",
        _ => string.Empty
    };

    private static string ResultTitleFor(SetupOperation operation) => operation switch
    {
        SetupOperation.Install => "Certael is installed",
        SetupOperation.Update => "Certael is updated",
        SetupOperation.Repair => "Certael is repaired",
        SetupOperation.Inspect => "Inspection complete",
        SetupOperation.Uninstall => "Certael is uninstalled",
        SetupOperation.Recover => "Recovery complete",
        _ => "Operation complete"
    };

    internal static string DetectRuntimeIdentifier()
    {
        Architecture architecture = RuntimeInformation.OSArchitecture;
        if (OperatingSystem.IsWindows() && architecture == Architecture.X64) return "win-x64";
        if (OperatingSystem.IsLinux() && architecture == Architecture.X64) return "linux-x64";
        if (OperatingSystem.IsMacOS() && architecture == Architecture.Arm64) return "osx-arm64";
        if (OperatingSystem.IsMacOS() && architecture == Architecture.X64) return "osx-x64";
        throw new PlatformNotSupportedException(
            $"Certael Setup does not support {RuntimeInformation.OSDescription} {architecture}.");
    }

    private static readonly FilePickerFileType JsonFiles = new("JSON files")
    {
        Patterns = ["*.json"], MimeTypes = ["application/json"]
    };
    private static readonly FilePickerFileType YamlFiles = new("YAML files")
    {
        Patterns = ["*.yaml", "*.yml"], MimeTypes = ["application/yaml", "text/yaml"]
    };
    private static readonly FilePickerFileType LogFiles = new("Log files")
    {
        Patterns = ["*.log"], MimeTypes = ["text/plain"]
    };
}

internal enum SetupOperation { Install, Update, Repair, Inspect, Uninstall, Recover }
internal enum SetupPhase { Choose, Review, Progress, Result }

internal sealed record OperationChoice(SetupOperation Operation, string Label)
{
    public static IReadOnlyList<OperationChoice> All { get; } =
    [
        new(SetupOperation.Install, "Install a signed Certael suite"),
        new(SetupOperation.Update, "Update an existing installation"),
        new(SetupOperation.Repair, "Repair an existing installation"),
        new(SetupOperation.Inspect, "Inspect managed files"),
        new(SetupOperation.Uninstall, "Uninstall managed files"),
        new(SetupOperation.Recover, "Recover an interrupted operation")
    ];
    public override string ToString() => Label;
}

internal sealed record RuntimeChoice(string Identifier, string Label)
{
    public static IReadOnlyList<RuntimeChoice> All { get; } =
    [
        new("win-x64", "Windows x64"),
        new("linux-x64", "Linux x64"),
        new("osx-arm64", "macOS Apple silicon"),
        new("osx-x64", "macOS Intel")
    ];
    public override string ToString() => $"{Label} ({Identifier})";
}

internal sealed class UiInstallerObserver(Action<InstallerEvent> report) : IInstallerObserver
{
    public ValueTask ReportAsync(InstallerEvent value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        report(value);
        return ValueTask.CompletedTask;
    }
}
