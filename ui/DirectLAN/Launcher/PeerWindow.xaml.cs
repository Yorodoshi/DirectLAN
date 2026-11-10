using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using DirectLAN.Dialogs;
using DirectLAN.Ipc;

namespace DirectLAN.Launcher;

public partial class PeerWindow : Window
{
    private readonly DirectLanClient _api = new("DirectLAN-Peer");
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(2) };
    private EventWaitHandle? _stop;
    private Process? _worker;
    private string? _runPath;
    private PeerState _state = new();
    private bool _busy;
    private bool _polling;
    private bool _closed;
    private bool _serviceUnavailable;
    private int _actionSequence;

    public PeerWindow()
    {
        InitializeComponent();
        _poll.Tick += async (_, _) => await RefreshAsync();
        Closing += CloseAsync;
        Loaded += async (_, _) =>
        {
            if (HasSavedPair()) await RunAsync(async () => { await StartWorkerAsync(); await ReadStatusAsync(); });
        };
    }

    private bool HasSavedPair()
    {
        try
        {
            var file = new FileInfo(LaunchConfig.PeerIdentity + ".pair.json");
            if (!file.Exists || file.Length > 8192) return false;
            using var json = JsonDocument.Parse(File.ReadAllText(file.FullName));
            if (json.RootElement.TryGetProperty("firewall", out var firewall) && firewall.ValueKind is JsonValueKind.True or JsonValueKind.False)
                Firewall.IsChecked = firewall.GetBoolean();
            if (json.RootElement.TryGetProperty("disable_stun", out var disableStun) && disableStun.ValueKind is JsonValueKind.True or JsonValueKind.False)
                StunDiscovery.IsChecked = !disableStun.GetBoolean();
            return json.RootElement.TryGetProperty("session", out var session) && session.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(session.GetString());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException) { return false; }
    }

    private async Task StartWorkerAsync()
    {
        if (_worker is { HasExited: false }) return;
        _worker?.Dispose(); _worker = null;
        _stop?.Dispose(); _stop = null;
        var config = new LaunchConfig { DirectPair = true, ConfigureFirewall = Firewall.IsChecked == true };
        var runs = Path.Combine(LaunchConfig.DataRoot, "launcher-runs");
        Directory.CreateDirectory(runs);
        _runPath = Path.Combine(runs, config.RunId + ".json");
        config.Validate(_runPath);
        File.WriteAllText(_runPath, JsonSerializer.Serialize(config, LaunchConfig.JsonOptions));
        _stop = new EventWaitHandle(false, EventResetMode.ManualReset, config.StopEvent);
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WorkingDirectory = LaunchConfig.Bundle };
        start.ArgumentList.Add("--worker"); start.ArgumentList.Add(_runPath);
        Notice.Text = "Подтвердите запуск в окне Windows.";
        _worker = Process.Start(start) ?? throw new IOException("Сетевая служба не запустилась.");
        for (var attempt = 0; attempt < 150; attempt++)
        {
            var result = LauncherWindow.ReadRunState(_runPath);
            if (result?.Phase == "Ready" && !_worker.HasExited)
            {
                _poll.Start(); Notice.Text = ""; return;
            }
            if (result?.Phase == "Error" || _worker.HasExited) throw new IOException(result?.Message ?? "Сетевая служба завершилась при запуске.");
            await Task.Delay(200);
        }
        _stop.Set();
        throw new TimeoutException("Сетевая служба не ответила за 30 секунд.");
    }

    private async void Create(object sender, RoutedEventArgs e) => await PairAsync("peer.create", "");

    private async void Join(object sender, RoutedEventArgs e)
    {
        var dialog = CodeDialog("Вставить приглашение", "Приглашение с первого ПК");
        if (dialog.ShowDialog() == true) await PairAsync("peer.join", dialog.Value);
    }

    private async Task PairAsync(string action, string code) => await RunAsync(async () =>
    {
        await StartWorkerAsync();
        Apply(await _api.CallAsync(action, new { code, router = Router.IsChecked == true, firewall = Firewall.IsChecked == true, disable_stun = StunDiscovery.IsChecked != true }));
    });

    private async void CopyCode(object sender, RoutedEventArgs e) => await RunAsync(async () =>
    {
        var result = await _api.CallAsync("peer.code");
        Clipboard.SetText(result.GetProperty("code").GetString()!);
        Notice.Text = _state.Role == "host" ? "Приглашение скопировано. Передайте его второму ПК." : "Ответ скопирован. На первом ПК нажмите «Вставить ответ» и вставьте его.";
    });

    private async void Accept(object sender, RoutedEventArgs e)
    {
        var title = _state.HasPeer ? "Обновить адрес по коду" : "Вставить ответ";
        var label = _state.Role == "host" ? "Ответ, скопированный на втором ПК" : "Свежее приглашение с первого ПК";
        var dialog = CodeDialog(title, label);
        if (dialog.ShowDialog() == true) await RunAsync(async () => Apply(await _api.CallAsync("peer.accept", new { code = dialog.Value })));
    }

    private TextPromptDialog CodeDialog(string title, string label)
    {
        var initialValue = "";
        try
        {
            var clipboard = Clipboard.GetText().Trim();
            if (clipboard.Length <= 4100 && clipboard.StartsWith("DL2.", StringComparison.Ordinal))
                initialValue = clipboard;
        }
        catch (ExternalException) { }
        return new TextPromptDialog(title, label, "Используйте полный код из доверенной переписки. Проверьте его и нажмите «Продолжить».", initialValue) { Owner = this };
    }

    private async void CheckConnection(object sender, RoutedEventArgs e) =>
        await RunAsync(async () => Apply(await _api.CallAsync("peer.check")));

    private async void Reset(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Забыть сохранённую пару и закрыть её туннель?", Title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            await RunAsync(async () => Apply(await _api.CallAsync("peer.reset")));
    }

    private async void CopyIP(object sender, RoutedEventArgs e) => await RunAsync(() =>
    {
        Clipboard.SetText(_state.PeerIP);
        Notice.Text = "Виртуальный IP второго ПК скопирован.";
        return Task.CompletedTask;
    });

    private async Task ReadStatusAsync() => Apply(await _api.CallAsync("peer.status"));

    private async Task RefreshAsync()
    {
        if (_busy || _polling || _closed) return;
        _polling = true;
        var actionSequence = _actionSequence;
        try
        {
            if (_worker?.HasExited == true)
            {
                _poll.Stop();
                Apply(default);
                Notice.Text = _runPath is null ? "Сетевая служба остановлена." : LauncherWindow.ReadRunState(_runPath)?.Message ?? "Сетевая служба остановлена.";
                return;
            }
            var response = await _api.CallAsync("peer.status");
            if (actionSequence != _actionSequence) return;
            Apply(response);
            if (_serviceUnavailable)
            {
                _serviceUnavailable = false;
                Notice.Text = "";
            }
        }
        catch (Exception ex)
        {
            if (actionSequence != _actionSequence) return;
            _serviceUnavailable = true;
            StateTitle.Text = "Служба не отвечает";
            StateDot.Fill = Brushes.SlateGray;
            Detail.Text = "Не удалось обновить состояние туннеля.";
            PingStatus.Text = "Пинг через туннель — нет данных";
            ProbeStatus.Text = "";
            CheckButton.IsEnabled = CopyIPButton.IsEnabled = false;
            Notice.Text = ex.Message;
        }
        finally { _polling = false; }
    }

    private async Task RunAsync(Func<Task> action)
    {
        if (_busy || _closed) return;
        _actionSequence++;
        _busy = true; Progress.Visibility = Visibility.Visible;
        SetupPanel.IsEnabled = PairPanel.IsEnabled = false; Notice.Text = "";
        try { await action(); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { Notice.Text = "Запуск отменён в окне Windows."; }
        catch (Exception ex) { Notice.Text = ex.Message; }
        finally { _busy = false; Progress.Visibility = Visibility.Collapsed; SetupPanel.IsEnabled = PairPanel.IsEnabled = true; }
    }

    private void Apply(JsonElement response)
    {
        _state = response.ValueKind == JsonValueKind.Object ? response.Deserialize<PeerState>() ?? new() : new();
        var active = _state.Role is "host" or "guest";
        var connected = _state.State == "connected";
        var waitingForAnswer = _state.Role == "host" && !_state.HasPeer;
        SetupPanel.Visibility = active ? Visibility.Collapsed : Visibility.Visible;
        PairPanel.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        StateTitle.Text = _state.State switch
        {
            "connected" => "Туннель работает",
            "unreachable" => "Внешние адреса не найдены",
            "connecting" when _state.LastProbe is not null => "Туннель пока не отвечает",
            "connecting" => "Проверяем соединение",
            "waiting" => "Ожидаем ответ второго ПК",
            _ => "Начните с одного ПК"
        };
        StateDot.Fill = connected ? Brushes.MediumSpringGreen
            : !active ? Brushes.SlateGray
            : _state.State == "unreachable" || _state.LastProbe is not null ? Brushes.Salmon
            : Brushes.Gold;
        Detail.Text = _state.Detail;
        Discovery.Text = string.IsNullOrEmpty(_state.Egress) ? _state.Discovery
            : $"{_state.Discovery}\nИсходящий адаптер — {_state.Egress}";
        Step.Text = connected ? "Используйте виртуальный IP второго ПК в игре или приложении."
            : _state.Role == "guest" ? "Передайте ответ первому ПК. На первом ПК нажмите «Вставить ответ»."
            : _state.HasPeer ? "Если связь пропала после смены адреса, обменяйтесь свежими кодами."
            : "Попросите владельца второго ПК нажать «Скопировать ответ» и прислать код. Вставьте его здесь.";
        CopyCodeButton.Content = _state.Role == "guest" ? "Скопировать ответ" : "Скопировать приглашение";
        CopyCodeButton.IsEnabled = _state.CodeReady;
        AcceptButton.Content = _state.HasPeer ? "Обновить адрес по коду" : "Вставить ответ";
        AcceptButton.Background = waitingForAnswer ? (Brush)FindResource("PrimaryActionBrush") : SystemColors.ControlBrush;
        AcceptButton.Foreground = waitingForAnswer ? Brushes.White : SystemColors.ControlTextBrush;
        HandshakeStatus.Text = !_state.HasPeer ? "WireGuard ждёт код ответа"
            : _state.LastHandshake is { } handshake ? $"Последнее рукопожатие WireGuard — {handshake.ToLocalTime():HH:mm:ss}"
            : _state.PeerAddresses == 0 ? "Код принят · Внешнего адреса в коде нет"
            : "Рукопожатие WireGuard пока не подтверждено";
        PingStatus.Text = connected ? $"Пинг через туннель — {_state.RTT:F1} мс"
            : _state.LastProbe is not null ? "Пинг через туннель — нет ответа"
            : "Пинг через туннель — ещё не измерен";
        ProbeStatus.Text = _state.LastProbe is { } probe
            ? $"Последняя проверка в {probe.ToLocalTime():HH:mm:ss}" + (_state.Checking ? " · Идёт новая проверка…" : "")
            : _state.Checking ? "Идёт первая проверка…"
            : !_state.HasPeer ? "Проверка начнётся после вставки ответа." : "Проверка запустится автоматически.";
        CheckButton.IsEnabled = _state.HasPeer && !_state.Checking;
        CopyIPButton.IsEnabled = connected;
        Addresses.Text = $"Мой виртуальный IP  {_state.LocalIP}\nIP второго ПК  {_state.PeerIP}";
    }

    private async void CloseAsync(object? sender, CancelEventArgs e)
    {
        if (_closed) return;
        if (_busy) { e.Cancel = true; return; }
        if (_worker is null) return;
        e.Cancel = true;
        await RunAsync(async () =>
        {
            _poll.Stop(); _stop?.Set();
            if (!_worker.HasExited) await _worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
            _worker.Dispose(); _stop?.Dispose();
            _closed = true; Close();
        });
    }

    private sealed class PeerState
    {
        [System.Text.Json.Serialization.JsonPropertyName("state")] public string State { get; set; } = "idle";
        [System.Text.Json.Serialization.JsonPropertyName("detail")] public string Detail { get; set; } = "Создайте соединение или вставьте приглашение с другого ПК.";
        [System.Text.Json.Serialization.JsonPropertyName("discovery")] public string Discovery { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("role")] public string Role { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("local_ip")] public string LocalIP { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("peer_ip")] public string PeerIP { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("code_ready")] public bool CodeReady { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("has_peer")] public bool HasPeer { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("peer_addresses")] public int PeerAddresses { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("egress")] public string Egress { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("checking")] public bool Checking { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("last_probe")] public DateTimeOffset? LastProbe { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("last_handshake")] public DateTimeOffset? LastHandshake { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("rtt_ms")] public double RTT { get; set; }
    }
}
