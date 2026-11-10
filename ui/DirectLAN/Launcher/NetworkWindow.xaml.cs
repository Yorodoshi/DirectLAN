using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using DirectLAN.Dialogs;
using DirectLAN.Ipc;

namespace DirectLAN.Launcher;

public partial class NetworkWindow : Window
{
    private readonly DirectLanClient _api = new("DirectLAN-Peer");
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(2) };
    private EventWaitHandle? _stop;
    private Process? _worker;
    private string? _runPath;
    private NetworkState _state = new();
    private bool _busy;
    private bool _polling;
    private bool _closed;
    private bool _serviceUnavailable;
    private bool _hasSavedNetwork;
    private int _actionSequence;
    private string? _helpMode;
    private bool _statusPulseActive;

    public NetworkWindow()
    {
        InitializeComponent();
        DeviceName.Text = Environment.MachineName;
        _poll.Tick += async (_, _) => await RefreshAsync();
        Closing += CloseAsync;
        IsVisibleChanged += (_, _) => UpdateStatusAnimation();
        StateChanged += (_, _) => UpdateStatusAnimation();
        Closed += (_, _) =>
        {
            _closed = true;
            _poll.Stop();
            StateDot.BeginAnimation(OpacityProperty, null);
        };
        Loaded += async (_, _) =>
        {
            AnimateEntrance();
            _hasSavedNetwork = HasSavedNetwork();
            UpdateLifecycle();
            if (_hasSavedNetwork) await RunAsync(async () => { await StartWorkerAsync(); Apply(await _api.CallAsync("mesh.status")); });
        };
    }

    private void AnimateEntrance()
    {
        if (!SystemParameters.ClientAreaAnimation || !IsVisible) return;
        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)) { FillBehavior = FillBehavior.Stop };
        var slide = new DoubleAnimation(8, 0, TimeSpan.FromMilliseconds(260))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.Stop
        };
        RootSurface.BeginAnimation(OpacityProperty, fade);
        ((TranslateTransform)RootSurface.RenderTransform).BeginAnimation(TranslateTransform.YProperty, slide);
    }

    private void UpdateStatusAnimation()
    {
        var shouldPulse = IsVisible && WindowState != WindowState.Minimized && !_closed &&
            SystemParameters.ClientAreaAnimation && !_serviceUnavailable && !_state.IsPaused && !_state.Pending &&
            _state.Members.Any(member => member.State != "local" && member.Checking);
        if (_statusPulseActive == shouldPulse) return;
        _statusPulseActive = shouldPulse;
        if (!shouldPulse)
        {
            StateDot.BeginAnimation(OpacityProperty, null);
            return;
        }
        var pulse = new DoubleAnimation(1, 0.35, TimeSpan.FromMilliseconds(700))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };
        Timeline.SetDesiredFrameRate(pulse, 24);
        StateDot.BeginAnimation(OpacityProperty, pulse);
    }

    private bool HasSavedNetwork()
    {
        try
        {
            var file = new FileInfo(LaunchConfig.PeerIdentity + ".mesh.json");
            if (!file.Exists || file.Length == 0 || file.Length > 256 * 1024) return false;
            using var document = JsonDocument.Parse(File.ReadAllText(file.FullName));
            var root = document.RootElement;
            if (root.TryGetProperty("firewall", out var firewall) && firewall.ValueKind is JsonValueKind.True or JsonValueKind.False)
                Firewall.IsChecked = firewall.GetBoolean();
            if (root.TryGetProperty("disable_stun", out var disableStun) && disableStun.ValueKind is JsonValueKind.True or JsonValueKind.False)
                StunDiscovery.IsChecked = !disableStun.GetBoolean();
            return root.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(code.GetString());
        }
        catch (JsonException) { return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
    }

    private async Task StartWorkerAsync()
    {
        if (_worker is { HasExited: false }) { _poll.Start(); return; }
        SessionController.ThrowIfBusy();
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
        SetNotice("Подтвердите запуск в окне Windows.");
        _worker = Process.Start(start) ?? throw new IOException("Сетевая служба не запустилась.");
        for (var attempt = 0; attempt < 150; attempt++)
        {
            var result = LauncherWindow.ReadRunState(_runPath);
            if (result?.Phase == "Ready" && !_worker.HasExited)
            {
                _poll.Start(); SetNotice(""); return;
            }
            if (result?.Phase == "Error" || _worker.HasExited)
                throw new IOException(result?.Message ?? "Сетевая служба завершилась при запуске.");
            await Task.Delay(200);
        }
        _stop.Set();
        throw new TimeoutException("Сетевая служба не ответила за 30 секунд.");
    }

    private async void Create(object sender, RoutedEventArgs e) => await EnterAsync("mesh.create", "");

    private async void Join(object sender, RoutedEventArgs e)
    {
        var dialog = CodeDialog("Присоединиться к сети", "Код сети от её владельца");
        if (dialog.ShowDialog() == true) await EnterAsync("mesh.join", dialog.Value);
    }

    private async Task EnterAsync(string action, string code) => await RunAsync(async () =>
    {
        await StartWorkerAsync();
        Apply(await _api.CallAsync(action, new
        {
            code, name = DeviceName.Text.Trim(), masked = MaskedTransport.IsChecked == true,
            router = Router.IsChecked == true, firewall = Firewall.IsChecked == true,
            disable_stun = StunDiscovery.IsChecked != true
        }));
    });

    private async void CopyCode(object sender, RoutedEventArgs e) => await RunAsync(async () =>
    {
        var result = await _api.CallAsync("mesh.code");
        Clipboard.SetText(result.GetProperty("code").GetString()!);
        SetNotice(_state.IsOwner
            ? "Код сети скопирован. Передайте его новому участнику или всем участникам после изменения состава сети."
            : "Код этого компьютера скопирован. Передайте его владельцу сети, затем вставьте обновлённый код сети от владельца.");
    });

    private async void ImportCode(object sender, RoutedEventArgs e)
    {
        var dialog = _state.IsOwner
            ? CodeDialog("Добавить или обновить участника", "Код компьютера, который вы разрешаете подключить")
            : CodeDialog("Обновить сеть", "Обновлённый код сети от владельца");
        if (dialog.ShowDialog() == true)
            await RunAsync(async () => Apply(await _api.CallAsync("mesh.accept", new { code = dialog.Value })));
    }

    private TextPromptDialog CodeDialog(string title, string label)
    {
        var initialValue = "";
        try
        {
            var clipboard = Clipboard.GetText().Trim();
            if (clipboard.Length <= 65536 && clipboard.StartsWith("DL3.", StringComparison.Ordinal)) initialValue = clipboard;
        }
        catch (ExternalException) { }
        return new TextPromptDialog(title, label, "Проверьте полный код из доверенной переписки и нажмите «Продолжить».", initialValue) { Owner = this };
    }

    private async void CheckAll(object sender, RoutedEventArgs e) => await CheckAsync("");
    private async void CheckSelected(object sender, RoutedEventArgs e)
    {
        if (MembersGrid.SelectedItem is MemberRow member) await CheckAsync(member.ID);
    }
    private async Task CheckAsync(string id) => await RunAsync(async () => Apply(await _api.CallAsync("mesh.check", new { id })));

    private async void CopyIP(object sender, RoutedEventArgs e)
    {
        if (MembersGrid.SelectedItem is not MemberRow member) return;
        await RunAsync(() =>
        {
            Clipboard.SetText(member.IP);
            SetNotice($"IP компьютера «{member.Name}» скопирован.");
            return Task.CompletedTask;
        });
    }

    private async void CopyLocalIP(object sender, RoutedEventArgs e) => await RunAsync(() =>
    {
        Clipboard.SetText(_state.LocalIP);
        SetNotice("Ваш виртуальный IP скопирован.");
        return Task.CompletedTask;
    });

    private async void RestartNetwork(object sender, RoutedEventArgs e) => await ManageNetworkAsync("mesh.restart");
    private async void DisconnectNetwork(object sender, RoutedEventArgs e) => await ManageNetworkAsync("mesh.disconnect");
    private async void ResumeNetwork(object sender, RoutedEventArgs e) => await ManageNetworkAsync("mesh.resume");

    private async Task ManageNetworkAsync(string method) => await RunAsync(async () =>
    {
        await StartWorkerAsync();
        Apply(await _api.CallAsync(method));
        SetNotice(method switch
        {
            "mesh.disconnect" => "Все соединения этой сети на данном ПК отключены. Для продолжения нажмите «Подключить сеть».",
            "mesh.restart" => "Сеть перезапущена. Проверяем связь с участниками.",
            _ => "Сеть запущена. Проверяем связь с участниками."
        });
    });

    private async void CloseAllConnections(object sender, RoutedEventArgs e) => await RunAsync(async () =>
    {
        _poll.Stop();
        ShowUnavailable("Завершаем текущие подключения DirectLAN…");
        await SessionController.StopAllAsync();
        await StopWorkerAsync();
        Apply(default);
        _hasSavedNetwork = HasSavedNetwork();
        UpdateLifecycle();
        StateTitle.Text = "Все подключения DirectLAN закрыты";
        Detail.Text = _hasSavedNetwork
            ? "Сохранённую сеть можно запустить кнопкой «Подключить сеть»."
            : "Можно создать новую сеть или подключиться по коду.";
        SetNotice("Сетевые службы DirectLAN на этом ПК штатно завершены.");
    });

    private void ShowLog(object sender, RoutedEventArgs e)
    {
        if (_runPath is null) return;
        var logPath = Path.ChangeExtension(_runPath, ".log");
        if (!File.Exists(logPath)) return;
        try { Process.Start(new ProcessStartInfo(logPath) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is IOException or Win32Exception) { SetNotice(ex.Message, error: true); }
    }

    private void SetNotice(string message, bool error = false)
    {
        var logMarker = message.IndexOf("Журнал:", StringComparison.Ordinal);
        Notice.Text = logMarker >= 0 ? message[..logMarker].TrimEnd() : message;
        NoticePanel.Visibility = string.IsNullOrWhiteSpace(Notice.Text) ? Visibility.Collapsed : Visibility.Visible;
        NoticePanel.Background = error ? new SolidColorBrush(Color.FromRgb(57, 34, 37)) : (Brush)FindResource("StatusNoticeBrush");
        Notice.Foreground = error ? Brushes.LightSalmon : new SolidColorBrush(Color.FromRgb(171, 193, 217));
        ShowLogButton.Visibility = error && _runPath is not null && File.Exists(Path.ChangeExtension(_runPath, ".log"))
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void RemoveMember(object sender, RoutedEventArgs e)
    {
        if (!_state.IsOwner || MembersGrid.SelectedItem is not MemberRow member) return;
        if (MessageBox.Show(this, $"Удалить компьютер «{member.Name}» из сети? Затем передайте обновлённый код сети оставшимся участникам.", Title, MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await RunAsync(async () => Apply(await _api.CallAsync("mesh.remove", new { id = member.ID })));
    }

    private async void Reset(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Удалить сохранённую сеть с этого ПК и закрыть её туннели? Для повторного подключения понадобится код сети.", Title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            await RunAsync(async () =>
            {
                await StartWorkerAsync();
                Apply(await _api.CallAsync("mesh.reset"));
            });
    }

    private async void OpenLegacy(object sender, RoutedEventArgs e)
    {
        await RunAsync(async () =>
        {
            await StopWorkerAsync();
            var legacy = new PeerWindow();
            Application.Current.MainWindow = legacy;
            legacy.Show();
            _closed = true;
            Close();
        });
    }

    private async Task RefreshAsync()
    {
        if (_busy || _polling || _closed) return;
        _polling = true;
        var sequence = _actionSequence;
        try
        {
            if (_worker?.HasExited == true)
            {
                _poll.Stop();
                ShowUnavailable(_runPath is null ? "Сетевая служба остановлена." : LauncherWindow.ReadRunState(_runPath)?.Message ?? "Сетевая служба остановлена.");
                return;
            }
            var response = await _api.CallAsync("mesh.status");
            if (sequence != _actionSequence) return;
            var recovered = _serviceUnavailable;
            Apply(response);
            if (recovered) SetNotice("");
        }
        catch (Exception ex) { if (sequence == _actionSequence) ShowUnavailable(ex.Message); }
        finally { _polling = false; }
    }

    private void ShowUnavailable(string message)
    {
        _serviceUnavailable = true;
        StateTitle.Text = "Служба не отвечает";
        StateDot.Fill = Brushes.SlateGray;
        Detail.Text = "Не удалось обновить состояние соединений.";
        PopulateMembers(unavailable: true);
        CopyCodeButton.IsEnabled = ImportButton.IsEnabled = CheckAllButton.IsEnabled = false;
        _hasSavedNetwork = HasSavedNetwork() || _hasSavedNetwork;
        UpdateLifecycle();
        UpdateStatusAnimation();
        SetNotice(message, error: true);
    }

    private async Task RunAsync(Func<Task> action)
    {
        if (_busy || _closed) return;
        _actionSequence++;
        _busy = true; Progress.Visibility = Visibility.Visible;
        SetupPanel.IsEnabled = NetworkPanel.IsEnabled = LifecyclePanel.IsEnabled = CloseAllButton.IsEnabled = false;
        SetNotice("");
        try { await action(); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { SetNotice("Запуск отменён в окне Windows."); }
        catch (Exception ex)
        {
            _hasSavedNetwork = HasSavedNetwork() || _hasSavedNetwork;
            SetNotice(ex.Message, error: true);
            UpdateLifecycle();
        }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
            SetupPanel.IsEnabled = NetworkPanel.IsEnabled = LifecyclePanel.IsEnabled = CloseAllButton.IsEnabled = true;
        }
    }

    private void Apply(JsonElement response)
    {
        _state = response.ValueKind == JsonValueKind.Object ? response.Deserialize<NetworkState>() ?? new() : new();
        _state.Members ??= [];
        _serviceUnavailable = false;
        var active = _state.State != "idle" || _state.Pending || _state.IsOwner;
        _hasSavedNetwork = active;
        var members = _state.Members.Where(member => member.IP != _state.LocalIP && member.State != "local").ToList();
        var connected = _state.IsPaused || _state.Pending ? 0 : members.Count(member => member.State == "connected");
        SetupPanel.Visibility = active ? Visibility.Collapsed : Visibility.Visible;
        NetworkPanel.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        StateTitle.Text = _state.IsPaused ? "Сеть отключена на этом ПК"
            : _state.State == "revoked" ? "Сеть остановлена"
            : !active ? "Создайте сеть или присоединитесь"
            : _state.Pending ? "Ожидаем подтверждение владельца"
            : connected > 0 ? $"Соединения работают · {connected} из {members.Count}"
            : members.Count == 0 ? "Сеть создана · пригласите участников" : "Проверяем соединения";
        StateDot.Fill = _state.IsPaused ? Brushes.SlateGray : _state.State == "revoked" ? Brushes.Salmon
            : connected > 0 ? Brushes.MediumSpringGreen : active ? Brushes.Gold : Brushes.SlateGray;
        Detail.Text = _state.Detail;
        Discovery.Text = _state.Discovery + (string.IsNullOrEmpty(_state.Egress) ? "" : $"\nИсходящий адаптер — {_state.Egress}");
        Discovery.Visibility = string.IsNullOrWhiteSpace(Discovery.Text) ? Visibility.Collapsed : Visibility.Visible;
        LocalAddress.Text = active ? $"Мой виртуальный IP — {_state.LocalIP}    ·    {(_state.Masked ? "WireGuard с маскировкой UDP" : "WireGuard")}" : "";
        LocalAddressPanel.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        CopyLocalIPButton.IsEnabled = active && !string.IsNullOrEmpty(_state.LocalIP);
        var helpMode = _state.IsPaused ? "paused" : _state.Pending ? "pending" : _state.IsOwner && members.Count == 0 ? "invite-first" : _state.IsOwner ? "invite" : "update";
        if (_helpMode != helpMode)
        {
            _helpMode = helpMode;
            ConnectionHelp.IsExpanded = _state.Pending || _state.IsOwner && members.Count == 0;
        }
        ConnectionHelp.Header = _state.IsPaused ? "Как продолжить работу"
            : _state.IsOwner ? "Пригласить компьютер"
            : _state.Pending ? "Как завершить подключение" : "Как обновить состав сети";
        Step.Text = _state.IsPaused ? "Нажмите «Подключить сеть», чтобы восстановить соединения с участниками."
            : _state.IsOwner
            ? "Скопируйте код сети и отправьте новому участнику. Когда он пришлёт код своего компьютера, нажмите «Добавить участника»."
            : _state.Pending
                ? "1. Скопируйте запрос и отправьте владельцу.  2. Получите обновлённый код сети.  3. Вставьте его кнопкой ниже."
                : "Для добавления участников или обновления адресов вставьте свежий код сети от владельца.";
        CopyCodeButton.Content = _state.IsOwner ? "Скопировать код сети" : _state.Pending ? "Скопировать запрос владельцу" : "Скопировать мой код";
        CopyCodeButton.IsEnabled = _state.CodeReady && !_state.IsPaused;
        ImportButton.Content = _state.IsOwner ? "Добавить участника" : "Вставить обновлённый код сети";
        ImportButton.IsEnabled = true;
        CheckAllButton.IsEnabled = !_state.Pending && !_state.IsPaused && members.Count > 0 && members.Any(member => !member.Checking);
        RemoveButton.Visibility = _state.IsOwner ? Visibility.Visible : Visibility.Collapsed;
        MemberCount.Text = _state.Pending ? "Запрос на подключение" : active ? $"{members.Count + 1} из 10 компьютеров" : "";
        MembersGrid.Visibility = members.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyMembersPanel.Visibility = members.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyMembers.Text = _state.Pending ? "Компьютеры сети появятся после подтверждения владельца."
            : "Других компьютеров пока нет. Пригласите первого участника кодом сети.";
        UpdateLifecycle();
        PopulateMembers();
        UpdateStatusAnimation();
    }

    private void UpdateLifecycle()
    {
        var active = _state.State != "idle" || _state.Pending || _state.IsOwner;
        LifecyclePanel.Visibility = active || _hasSavedNetwork ? Visibility.Visible : Visibility.Collapsed;
        var available = active || _hasSavedNetwork;
        var stopped = _state.State is "revoked" or "stopped";
        ResumeButton.Visibility = _state.IsPaused || _serviceUnavailable || stopped || !active ? Visibility.Visible : Visibility.Collapsed;
        ResumeButton.Content = _serviceUnavailable || stopped || !active ? "Запустить сеть" : "Подключить сеть";
        ResumeButton.IsEnabled = RestartButton.IsEnabled = available;
        DisconnectButton.Visibility = !_state.IsPaused && active && !stopped && !_serviceUnavailable ? Visibility.Visible : Visibility.Collapsed;
        LifecycleHint.Text = _state.IsPaused || !active
            ? "Профиль сети сохранён. Подключение заново поднимет туннели на этом ПК."
            : "Перезапуск заново поднимет туннели на этом ПК. Отключение сохраняет сеть для следующего запуска.";
        if (!active && _hasSavedNetwork) SetupPanel.Visibility = Visibility.Collapsed;
    }

    private void PopulateMembers(bool unavailable = false)
    {
        var selectedId = (MembersGrid.SelectedItem as MemberRow)?.ID;
        var members = _state.Members.Where(member => member.IP != _state.LocalIP && member.State != "local")
            .Select(member => new MemberRow(member, unavailable, _state.IsPaused, _state.Pending)).ToList();
        MembersGrid.ItemsSource = members;
        MembersGrid.SelectedItem = members.FirstOrDefault(member => member.ID == selectedId) ?? members.FirstOrDefault();
        UpdateSelectedMember();
    }

    private void SelectMember(object sender, SelectionChangedEventArgs e) => UpdateSelectedMember();

    private void UpdateSelectedMember()
    {
        var selected = MembersGrid.SelectedItem as MemberRow;
        CopyIPButton.IsEnabled = !_serviceUnavailable && selected?.Connected == true;
        CheckSelectedButton.IsEnabled = !_serviceUnavailable && !_state.Pending && !_state.IsPaused && selected is { Checking: false };
        RemoveButton.IsEnabled = !_serviceUnavailable && _state.IsOwner && selected is not null;
        SelectedHealth.Text = selected?.HealthText ?? "Выберите участника, чтобы проверить связь с ним.";
    }

    private async void CloseAsync(object? sender, CancelEventArgs e)
    {
        if (_closed) return;
        if (_busy) { e.Cancel = true; return; }
        if (_worker is null) return;
        e.Cancel = true;
        await RunAsync(async () =>
        {
            await StopWorkerAsync();
            _closed = true; Close();
        });
    }

    private async Task StopWorkerAsync()
    {
        _poll.Stop(); _stop?.Set();
        if (_worker is { HasExited: false }) await _worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
        _worker?.Dispose(); _worker = null;
        _stop?.Dispose(); _stop = null;
    }

    private sealed class NetworkState
    {
        [JsonPropertyName("state")] public string State { get; set; } = "idle";
        [JsonPropertyName("detail")] public string Detail { get; set; } = "Владелец создаёт сеть и передаёт её код остальным участникам.";
        [JsonPropertyName("local_ip")] public string LocalIP { get; set; } = "";
        [JsonPropertyName("egress")] public string Egress { get; set; } = "";
        [JsonPropertyName("discovery")] public string Discovery { get; set; } = "";
        [JsonPropertyName("code_ready")] public bool CodeReady { get; set; }
        [JsonPropertyName("is_owner")] public bool IsOwner { get; set; }
        [JsonPropertyName("pending")] public bool Pending { get; set; }
        [JsonPropertyName("masked")] public bool Masked { get; set; }
        [JsonPropertyName("paused")] public bool Paused { get; set; }
        [JsonIgnore] public bool IsPaused => Paused || State == "paused";
        [JsonPropertyName("members")] public List<MemberState> Members { get; set; } = [];
    }

    private sealed class MemberState
    {
        [JsonPropertyName("id")] public string ID { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("ip")] public string IP { get; set; } = "";
        [JsonPropertyName("state")] public string State { get; set; } = "connecting";
        [JsonPropertyName("rtt_ms")] public double RTT { get; set; }
        [JsonPropertyName("last_probe")] public DateTimeOffset? LastProbe { get; set; }
        [JsonPropertyName("last_handshake")] public DateTimeOffset? LastHandshake { get; set; }
        [JsonPropertyName("checking")] public bool Checking { get; set; }
    }

    private sealed class MemberRow(MemberState member, bool unavailable, bool paused, bool pending)
    {
        public string ID => member.ID;
        public string Name => string.IsNullOrWhiteSpace(member.Name) ? "Компьютер" : member.Name;
        public string IP => member.IP;
        public bool Connected => !unavailable && !paused && !pending && member.State == "connected";
        public bool Checking => !unavailable && !paused && !pending && member.Checking;
        public string StateText => unavailable ? "Нет данных" : paused || member.State == "offline" ? "Отключён" : pending ? "Ожидает допуска" : Connected ? "Работает" : Checking ? "Проверяем…"
            : member.State is "pending" or "waiting" ? "Ожидает допуска" : member.LastProbe is not null ? "Нет ответа" : "Подключаемся";
        public Brush StateBrush => unavailable || paused || member.State == "offline" ? Brushes.SlateGray : pending ? Brushes.Gold : Connected ? Brushes.MediumSpringGreen
            : member.LastProbe is not null ? Brushes.Salmon : Brushes.Gold;
        public string PingText => Connected ? $"{member.RTT:F1} мс" : "—";
        public string HealthText => unavailable ? "Служба не отвечает. Состояние соединения неизвестно."
            : paused ? "Соединения отключены на этом ПК. Нажмите «Подключить сеть», чтобы продолжить."
            : pending ? "Владелец ещё не подтвердил подключение этого ПК. Отправьте запрос и получите обновлённый код сети."
            : member.LastProbe is { } probe
                ? $"Последняя проверка в {probe.ToLocalTime():HH:mm:ss}" + (member.LastHandshake is { } handshake ? $" · Рукопожатие WireGuard в {handshake.ToLocalTime():HH:mm:ss}" : " · Рукопожатие пока не подтверждено") + (Checking ? " · Идёт новая проверка…" : "")
                : Checking ? "Идёт первая проверка…" : "Проверка через туннель ещё не завершена.";
    }
}
