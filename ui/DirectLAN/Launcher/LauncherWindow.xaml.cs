using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;

namespace DirectLAN.Launcher;

public partial class LauncherWindow : Window
{
    private static string SettingsPath => Path.Combine(LaunchConfig.DataRoot, "launcher-settings.json");
    private readonly LauncherSettings _settings;
    private EventWaitHandle? _stop;
    private Process? _worker;
    private LaunchConfig? _config;
    private string? _configPath;
    private MainWindow? _main;
    private bool _busy;
    private bool _closeAllowed;
    private readonly DispatcherTimer _monitor = new() { Interval = TimeSpan.FromSeconds(1) };

    public LauncherWindow(bool serverMode)
    {
        InitializeComponent();
        _settings = ReadSettings();
        ServerAddress.ItemsSource = LocalAddresses();
        ServerAddress.Text = !string.IsNullOrWhiteSpace(_settings.ServerAddress) ? _settings.ServerAddress : ((IEnumerable<string>)ServerAddress.ItemsSource).FirstOrDefault() ?? "";
        ServerPort.Text = _settings.Port.ToString();
        CoordinatorUrl.Text = _settings.CoordinatorUrl;
        CAPath.Text = _settings.CAPath;
        ServerMode.IsChecked = serverMode;
        UpdateMode();
        _monitor.Tick += (_, _) => CheckWorker();
        Closing += OnClosing;
        Loaded += async (_, _) =>
        {
            if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift)) return;
            var auto = serverMode
                ? _settings.AutoServer && LocalAddresses().Contains(_settings.ServerAddress) && CertificateUsable(_settings.ServerDirectory)
                : _settings.AutoClient && File.Exists(_settings.CAPath) && Uri.TryCreate(_settings.CoordinatorUrl, UriKind.Absolute, out _);
            if (auto) await StartAsync();
        };
    }

    private static LauncherSettings ReadSettings()
    {
        try { return JsonSerializer.Deserialize<LauncherSettings>(File.ReadAllText(SettingsPath)) ?? new(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return new(); }
    }

    private static string[] LocalAddresses()
    {
        var adapters = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211);
        return adapters.Select(n => n.GetIPProperties())
            .SelectMany(p => p.UnicastAddresses.Select(a => (Address: a.Address, Gateway: p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)))))
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address) && !a.Address.Equals(IPAddress.Any))
            .OrderByDescending(a => IsPrivateIPv4(a.Address)).ThenByDescending(a => a.Gateway)
            .Select(a => a.Address.ToString()).Distinct().ToArray();
    }

    private static bool IsPrivateIPv4(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168;
    }

    private void ModeChanged(object sender, RoutedEventArgs e) => UpdateMode();
    private void UpdateMode()
    {
        if (ServerPanel is null || ClientPanel is null) return;
        var server = ServerMode.IsChecked == true;
        ServerPanel.Visibility = server ? Visibility.Visible : Visibility.Collapsed;
        ClientPanel.Visibility = server ? Visibility.Collapsed : Visibility.Visible;
        if (_settings is null || Transport is null || AutoStart is null) return;
        ConfigureFirewall.IsChecked = server ? _settings.ServerFirewall : _settings.ClientFirewall;
        AutoStart.IsChecked = server ? string.IsNullOrEmpty(_settings.ServerAddress) || _settings.AutoServer : string.IsNullOrEmpty(_settings.CoordinatorUrl) || _settings.AutoClient;
        StartLocalClient.IsChecked = _settings.ServerWithClient;
        var mode = server ? _settings.ServerTransport : _settings.ClientTransport;
        Transport.SelectedItem = Transport.Items.OfType<ComboBoxItem>().FirstOrDefault(item => item.Tag?.ToString() == mode) ?? Transport.Items[0];
    }

    private void BrowseCA(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "CA с первого ПК", Filter = "PEM сертификат (*.pem)|*.pem|Все файлы|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) CAPath.Text = dialog.FileName;
    }

    private async void StartClicked(object sender, RoutedEventArgs e) => await StartAsync();

    private async Task StartAsync()
    {
        if (_busy || _worker is not null) return;
        SetBusy(true, "Подготовка запуска…");
        try
        {
            var config = new LaunchConfig
            {
                StartServer = ServerMode.IsChecked == true,
                ConfigureFirewall = ConfigureFirewall.IsChecked == true,
                Transport = (Transport.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "https"
            };
            config.StartClient = !config.StartServer || StartLocalClient.IsChecked == true;
            var runDir = Path.Combine(LaunchConfig.DataRoot, "launcher-runs");
            Directory.CreateDirectory(runDir);
            var configPath = Path.Combine(runDir, config.RunId + ".json");
            if (config.StartServer)
            {
                var address = ServerAddress.Text.Trim();
                if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || !LocalAddresses().Contains(ip.ToString())) throw new InvalidDataException("Выберите IPv4 этого ПК из списка сетевых адресов.");
                if (!int.TryParse(ServerPort.Text.Trim(), out var port) || port is < 1 or > 65535) throw new InvalidDataException("Укажите порт от 1 до 65535.");
                config.Port = port;
                config.CoordinatorUrl = $"https://{ip}:{port}";
                var baseDir = Path.Combine(LaunchConfig.DataRoot, "server", $"{ip}-{port}");
                var previous = _settings.ServerAddress == ip.ToString() && _settings.Port == port ? _settings.ServerDirectory : "";
                var usable = !string.IsNullOrEmpty(previous) && (previous == baseDir || previous.StartsWith(baseDir + "-", StringComparison.OrdinalIgnoreCase)) && CertificateUsable(previous);
                config.ServerDirectory = usable ? previous : CertificateUsable(baseDir) ? baseDir : Directory.Exists(baseDir) ? baseDir + "-" + config.RunId : baseDir;
                if (!CertificateUsable(config.ServerDirectory)) await PrepareCertificateAsync(ip.ToString(), config.ServerDirectory);
                config.CAPath = Path.Combine(config.ServerDirectory, "ca.pem");
                _settings.ServerAddress = ip.ToString(); _settings.ServerDirectory = config.ServerDirectory; _settings.Port = port;
            }
            else
            {
                config.CoordinatorUrl = CoordinatorUrl.Text.Trim();
                if (string.IsNullOrWhiteSpace(CAPath.Text)) throw new InvalidDataException("Выберите ca.pem, полученный с первого ПК.");
                config.CAPath = Path.GetFullPath(CAPath.Text.Trim());
                _settings.CoordinatorUrl = config.CoordinatorUrl; _settings.CAPath = config.CAPath;
            }
            config.Validate(configPath);
            File.WriteAllText(configPath, JsonSerializer.Serialize(config, LaunchConfig.JsonOptions));
            _configPath = configPath; _config = config;
            _stop = new EventWaitHandle(false, EventResetMode.ManualReset, config.StopEvent);
            var elevate = config.StartClient || config.ConfigureFirewall;
            var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = elevate, CreateNoWindow = !elevate, WorkingDirectory = LaunchConfig.Bundle };
            if (elevate) info.Verb = "runas";
            info.ArgumentList.Add("--worker"); info.ArgumentList.Add(configPath);
            StatusText.Text = elevate ? "Подтвердите запуск сетевой службы в окне Windows." : "Запуск локального сервера…";
            _worker = Process.Start(info) ?? throw new IOException("Не удалось запустить сетевые компоненты.");
            var state = await WaitForReadyAsync(_worker, configPath);
            if (state.Phase != "Ready") throw new IOException(state.Message);
            if (config.StartServer)
            {
                _settings.AutoServer = AutoStart.IsChecked == true; _settings.ServerWithClient = config.StartClient;
                _settings.ServerFirewall = config.ConfigureFirewall; _settings.ServerTransport = config.Transport;
            }
            else
            {
                _settings.AutoClient = AutoStart.IsChecked == true;
                _settings.ClientFirewall = config.ConfigureFirewall; _settings.ClientTransport = config.Transport;
            }
            StatusText.Text = state.Message;
            try { File.WriteAllText(SettingsPath, JsonSerializer.Serialize(_settings, LaunchConfig.JsonOptions)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { StatusText.Text += "\nНе удалось сохранить настройки: " + ex.Message; }
            if (config.StartServer)
            {
                ServerInfo.Text = $"Адрес для второго ПК: {config.CoordinatorUrl}\nПередайте второму участнику только ca.pem.";
                using var ca = X509CertificateLoader.LoadCertificateFromFile(config.CAPath);
                Fingerprint.Text = "SHA-256 CA: " + Convert.ToHexStringLower(SHA256.HashData(ca.RawData));
                ServerInfoPanel.Visibility = Visibility.Visible;
            }
            if (config.StartClient) ShowMain();
            _monitor.Start();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { await ResetFailedAsync("Запуск отменён в окне Windows."); }
        catch (Exception ex) { await ResetFailedAsync(ex.Message); }
        finally { SetBusy(false); }
    }

    private static bool CertificateUsable(string directory)
    {
        try
        {
            if (!File.Exists(Path.Combine(directory, "server-key.pem")) || !File.Exists(Path.Combine(directory, "ca.pem"))) return false;
            using var cert = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(directory, "server.pem"));
            return cert.NotAfter > DateTime.Now.AddHours(1);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException) { return false; }
    }

    internal static async Task PrepareCertificateAsync(string address, string directory)
    {
        var info = new ProcessStartInfo(LaunchConfig.Executable("directlan-cert.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-address", address, "-out", directory }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("Не запустилась подготовка сертификата.");
        var stderr = process.StandardError.ReadToEndAsync(); var stdout = process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
        await stdout;
        if (process.ExitCode != 0) throw new IOException("Не удалось подготовить сертификат: " + await stderr);
        await stderr;
    }

    private static async Task<RunState> WaitForReadyAsync(Process worker, string configPath)
    {
        for (var attempt = 0; attempt < 150; attempt++)
        {
            var state = ReadRunState(configPath);
            if (state?.Phase is "Ready" or "Error") return state;
            if (worker.HasExited) return state ?? new("Error", $"Компоненты не запустились (код {worker.ExitCode}).");
            await Task.Delay(200);
        }
        return new("Error", "Компоненты не ответили за 30 секунд.");
    }

    internal static RunState? ReadRunState(string configPath)
    {
        try { return JsonSerializer.Deserialize<RunState>(File.ReadAllText(LaunchConfig.StatePath(configPath))); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    private void OpenMain(object sender, RoutedEventArgs e) => ShowMain();
    private void ShowMain()
    {
        if (_main is null) { _main = new MainWindow(); _main.Closed += (_, _) => _main = null; _main.Show(); }
        else _main.Activate();
    }

    private void ExportCA(object sender, RoutedEventArgs e)
    {
        if (_config is null) return;
        var dialog = new SaveFileDialog { Title = "CA для второго ПК", FileName = "ca.pem", Filter = "PEM сертификат (*.pem)|*.pem", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (!Path.GetFullPath(dialog.FileName).Equals(Path.GetFullPath(_config.CAPath), StringComparison.OrdinalIgnoreCase)) File.Copy(_config.CAPath, dialog.FileName, true);
            StatusText.Text = "ca.pem сохранён. Передайте его и адрес сервера второму участнику.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { StatusText.Text = ex.Message; }
    }

    private async void StopClicked(object sender, RoutedEventArgs e) => await StopAsync();

    private async Task StopAsync()
    {
        SetBusy(true, "Штатная остановка…");
        try
        {
            _monitor.Stop(); _stop?.Set();
            if (_worker is not null && !_worker.HasExited) await _worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
            var state = _configPath is not null ? ReadRunState(_configPath) : null;
            StatusText.Text = state?.Phase is "Stopped" or "Error" ? state.Message : "Компоненты остановлены.";
            ClearRun();
        }
        catch (TimeoutException) { StatusText.Text = "Остановка ещё выполняется. Подождите и проверьте журнал запуска."; }
        finally { SetBusy(false); }
    }

    private async Task ResetFailedAsync(string message)
    {
        await StopAsync();
        StatusText.Text = message;
    }

    private void ClearRun()
    {
        _monitor.Stop(); _worker?.Dispose(); _worker = null; _stop?.Dispose(); _stop = null;
        _main?.Close(); _config = null; _configPath = null; ServerInfoPanel.Visibility = Visibility.Collapsed;
    }

    private void CheckWorker()
    {
        if (_worker?.HasExited != true) return;
        StatusText.Text = _configPath is not null ? ReadRunState(_configPath)?.Message ?? "Сетевые компоненты завершились." : "Сетевые компоненты завершились.";
        ClearRun(); SetBusy(false);
    }

    private void SetBusy(bool value, string? status = null)
    {
        _busy = value; Progress.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
        ConfigurationPanel.IsEnabled = !value && _worker is null; StartButton.IsEnabled = ConfigurationPanel.IsEnabled;
        StopButton.IsEnabled = !value && _worker is not null; OpenButton.IsEnabled = StopButton.IsEnabled && _config?.StartClient == true;
        if (status is not null) StatusText.Text = status;
    }

    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_closeAllowed) return;
        if (_busy) { e.Cancel = true; return; }
        if (_worker is null) return;
        e.Cancel = true;
        await StopAsync();
        if (_worker is null) { _closeAllowed = true; Close(); }
    }
}
