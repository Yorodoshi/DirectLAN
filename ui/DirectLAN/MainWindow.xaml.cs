using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using DirectLAN.Dialogs;
using DirectLAN.Ipc;
using Microsoft.Win32;

namespace DirectLAN;

public partial class MainWindow : Window
{
    private readonly DirectLanClient _client = new();
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private readonly ObservableCollection<MemberRow> _members = [];
    private readonly ObservableCollection<AdapterRow> _adapters = [];
    private readonly ObservableCollection<EventRow> _events = [];
    private readonly List<EventRow> _localEvents = [];
    private readonly List<EventRow> _serviceEvents = [];
    private bool _refreshing;
    private bool _actionRunning;
    private bool _serviceAvailable;
    private bool _unavailableReported;
    private string? _virtualIp;
    private string? _groupName;
    private string? _activeAdapterId;

    public MainWindow()
    {
        InitializeComponent();
        MembersGrid.ItemsSource = _members;
        AdapterCombo.ItemsSource = _adapters;
        EventsList.ItemsSource = _events;
        UpdateActionState();

        Loaded += async (_, _) =>
        {
            await RefreshStatusAsync();
            _refreshTimer.Start();
        };
        Closed += (_, _) => _refreshTimer.Stop();
        _refreshTimer.Tick += async (_, _) => await RefreshStatusAsync();
    }

    private async Task RefreshStatusAsync()
    {
        if (_refreshing || _actionRunning)
        {
            return;
        }

        _refreshing = true;
        try
        {
            var result = await _client.CallAsync("status");
            var wasUnavailable = !_serviceAvailable;
            _serviceAvailable = true;
            _unavailableReported = false;
            ServiceText.Text = "Служба подключена";
            ServiceIndicator.Fill = Brush("#49C795");
            if (wasUnavailable)
            {
                AddLocalEvent("Служба", "Соединение со службой DirectLAN установлено.");
            }
            ApplyStatus(result);
            FooterText.Text = $"Обновлено: {DateTime.Now:HH:mm:ss}";
            if (wasUnavailable)
            {
                await LoadAdaptersAsync();
            }
        }
        catch (DirectLanUnavailableException ex)
        {
            SetUnavailable(ex.Message);
        }
        catch (DirectLanServiceException ex)
        {
            SetUnavailable($"{ex.Code}: {ex.Message}",
                ex.Action ?? "Проверьте журнал службы и повторите попытку.",
                "Состояние недоступно");
        }
        catch (Exception ex)
        {
            SetUnavailable(ex.Message, "Проверьте версию службы и повторите попытку.",
                "Ошибка состояния");
        }
        finally
        {
            _refreshing = false;
            UpdateActionState();
        }
    }

    private void ApplyStatus(JsonElement status)
    {
        if (status.ValueKind != JsonValueKind.Object)
        {
            throw new DirectLanProtocolException("Служба вернула пустое состояние.");
        }

        var group = Get(status, "group");
        _groupName = StringValue(group, "name", "group_name") ??
                     (group.ValueKind == JsonValueKind.String ? group.GetString() : null) ??
                     StringValue(status, "group_name");
        _virtualIp = StringValue(status, "virtual_ip", "overlay_ip");
        GroupNameText.Text = Display(_groupName);
        VirtualIpText.Text = Display(_virtualIp);

        var connection = Get(status, "connection");
        if (connection.ValueKind != JsonValueKind.Object)
        {
            connection = status;
        }
        var state = StringValue(connection, "state", "connection_state") ??
                    StringValue(status, "state");
        var egress = StringValue(connection, "egress", "exit") ??
                     StringValue(status, "egress");
        ConnectionText.Text = Display(state);
        ConnectionText.Foreground = state switch
        {
            "Direct" => Brush("#49C795"),
            "Relay" => Brush("#E5B764"),
            "Blocked" => Brush("#F17E7E"),
            _ => Brush("#F2F6FC")
        };
        EgressText.Text = Display(egress);

        var adapter = Get(status, "adapter");
        if (adapter.ValueKind != JsonValueKind.Object)
        {
            adapter = Get(connection, "adapter");
        }
        var adapterName = adapter.ValueKind == JsonValueKind.Object
            ? StringValue(adapter, "name", "display_name", "id")
            : adapter.ValueKind == JsonValueKind.String ? adapter.GetString() : null;
        _activeAdapterId = adapter.ValueKind == JsonValueKind.Object
            ? StringValue(adapter, "id", "adapter_id", "index")
            : null;
        adapterName ??= StringValue(connection, "adapter_name") ??
                       StringValue(status, "adapter_name");
        ActiveAdapterText.Text = Display(adapterName);

        var metrics = Get(connection, "metrics");
        if (metrics.ValueKind != JsonValueKind.Object)
        {
            metrics = connection;
        }
        RttText.Text = FormatMetric(metrics, "мс", "rtt_ms", "rtt");
        JitterText.Text = FormatMetric(metrics, "мс", "jitter_ms", "jitter");
        LossText.Text = FormatMetric(metrics, "%", "loss_percent", "loss_pct", "loss");
        SpeedText.Text = FormatMetric(metrics, "Мбит/с", "speed_mbps", "throughput_mbps", "speed");

        var selectedId = (MembersGrid.SelectedItem as MemberRow)?.DeviceId;
        _members.Clear();
        var members = Get(status, "members", "participants", "peers");
        if (members.ValueKind == JsonValueKind.Array)
        {
            foreach (var member in members.EnumerateArray())
            {
                if (member.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                var approved = BoolValue(member, "approved");
                _members.Add(new MemberRow(
                    StringValue(member, "device_id", "id") ?? "",
                    StringValue(member, "name", "device_name") ?? "Без имени",
                    StringValue(member, "overlay_ip", "virtual_ip") ?? "—",
                    approved,
                    StringValue(member, "state", "connection_state") ?? "—",
                    StringValue(member, "egress", "exit") ?? "—",
                    FormatMetric(member, "мс", "rtt_ms", "rtt"),
                    StringValue(member, "fingerprint", "key_fingerprint") ?? ""));
            }
        }
        if (selectedId is not null)
        {
            MembersGrid.SelectedItem = _members.FirstOrDefault(x => x.DeviceId == selectedId);
        }
        UpdateSelectedMember();

        _serviceEvents.Clear();
        var events = Get(status, "events");
        if (events.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in events.EnumerateArray().Take(50))
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    _serviceEvents.Add(new EventRow("Служба", item.GetString() ?? ""));
                    continue;
                }
                if (item.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                var level = StringValue(item, "level", "type") ?? "Служба";
                var stamp = StringValue(item, "timestamp", "time");
                var header = string.IsNullOrWhiteSpace(stamp) ? level : $"{stamp} · {level}";
                var message = StringValue(item, "message", "text") ?? "";
                if (!string.IsNullOrWhiteSpace(message))
                {
                    _serviceEvents.Add(new EventRow(header, message));
                }
            }
        }
        RenderEvents();
    }

    private async Task LoadAdaptersAsync()
    {
        if (!_serviceAvailable)
        {
            return;
        }

        try
        {
            var result = await _client.CallAsync("adapter.list");
            var entries = result.ValueKind == JsonValueKind.Array
                ? result
                : Get(result, "adapters");
            var selectedId = (AdapterCombo.SelectedItem as AdapterRow)?.Id;
            _adapters.Clear();
            if (entries.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in entries.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }
                    var id = StringValue(entry, "id", "adapter_id", "index");
                    var name = StringValue(entry, "name", "display_name");
                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        _adapters.Add(new AdapterRow(id, name ?? id));
                    }
                }
            }
            AdapterCombo.SelectedItem = _adapters.FirstOrDefault(x => x.Id == (selectedId ?? _activeAdapterId));
            UpdateActionState();
        }
        catch (DirectLanUnavailableException ex)
        {
            SetUnavailable(ex.Message);
        }
        catch (Exception ex)
        {
            ReportError(ex, false);
        }
    }

    private void SetUnavailable(string message, string? action = null,
        string serviceLabel = "Служба недоступна")
    {
        _serviceAvailable = false;
        ServiceText.Text = serviceLabel;
        ServiceIndicator.Fill = Brush("#F17E7E");
        action ??= "Запустите службу DirectLAN и обновите состояние.";
        FooterText.Text = message + " " + action;
        GroupNameText.Text = VirtualIpText.Text = ConnectionText.Text = EgressText.Text =
            ActiveAdapterText.Text = RttText.Text = JitterText.Text = LossText.Text = SpeedText.Text = "—";
        _groupName = _virtualIp = _activeAdapterId = null;
        _members.Clear();
        _adapters.Clear();
        _serviceEvents.Clear();
        UpdateSelectedMember();
        if (!_unavailableReported)
        {
            AddLocalEvent("Ошибка", message + " " + action);
            _unavailableReported = true;
        }
        RenderEvents();
        UpdateActionState();
    }

    private void UpdateActionState()
    {
        var ready = _serviceAvailable && !_actionRunning;
        var selected = MembersGrid.SelectedItem as MemberRow;
        CreateGroupButton.IsEnabled = JoinButton.IsEnabled = ready;
        InviteButton.IsEnabled = ready && !string.IsNullOrWhiteSpace(_groupName);
        CopyIpButton.IsEnabled = ready && !string.IsNullOrWhiteSpace(_virtualIp);
        CheckButton.IsEnabled = ready && selected is not null && !string.IsNullOrWhiteSpace(selected.DeviceId);
        ApproveButton.IsEnabled = ready && selected is { Approved: false } &&
                                  !string.IsNullOrWhiteSpace(selected.DeviceId) &&
                                  !string.IsNullOrWhiteSpace(selected.Fingerprint);
        RevokeButton.IsEnabled = ready && selected is not null && !string.IsNullOrWhiteSpace(selected.DeviceId);
        SelectAdapterButton.IsEnabled = ready && AdapterCombo.SelectedItem is AdapterRow;
        LoadAdaptersButton.IsEnabled = ExportButton.IsEnabled = ready;
    }

    private async Task<JsonElement?> RunActionAsync(string method, object? parameters, string success)
    {
        if (_actionRunning || !_serviceAvailable)
        {
            return null;
        }

        _actionRunning = true;
        UpdateActionState();
        try
        {
            var result = await _client.CallAsync(method, parameters);
            AddLocalEvent("Действие", success);
            FooterText.Text = success;
            return result;
        }
        catch (DirectLanUnavailableException ex)
        {
            SetUnavailable(ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            ReportError(ex, true);
            return null;
        }
        finally
        {
            _actionRunning = false;
            UpdateActionState();
            await RefreshStatusAsync();
        }
    }

    private void ReportError(Exception exception, bool showDialog)
    {
        var message = exception switch
        {
            DirectLanServiceException service =>
                $"{service.Code}: {service.Message}" +
                (string.IsNullOrWhiteSpace(service.Action) ? "" : $" Следующее действие: {service.Action}"),
            _ => exception.Message
        };
        FooterText.Text = message;
        AddLocalEvent("Ошибка", message);
        if (showDialog)
        {
            MessageBox.Show(this, message, "DirectLAN", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void AddLocalEvent(string level, string message)
    {
        _localEvents.Insert(0, new EventRow($"{DateTime.Now:HH:mm:ss} · {level}", message));
        if (_localEvents.Count > 30)
        {
            _localEvents.RemoveAt(_localEvents.Count - 1);
        }
        RenderEvents();
    }

    private void RenderEvents()
    {
        _events.Clear();
        foreach (var entry in _localEvents.Concat(_serviceEvents).Take(80))
        {
            _events.Add(entry);
        }
    }

    private void UpdateSelectedMember()
    {
        if (MembersGrid.SelectedItem is MemberRow member)
        {
            SelectedMemberText.Text = $"{member.Name} · {member.DeviceId}";
            FingerprintText.Text = string.IsNullOrWhiteSpace(member.Fingerprint)
                ? "Отпечаток ключа недоступен"
                : $"Отпечаток ключа: {member.Fingerprint}";
        }
        else
        {
            SelectedMemberText.Text = "Выберите участника";
            FingerprintText.Text = "";
        }
        UpdateActionState();
    }

    private void MembersGrid_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        UpdateSelectedMember();

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await RefreshStatusAsync();
        if (_serviceAvailable)
        {
            await LoadAdaptersAsync();
        }
    }

    private async void CreateGroupButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new TextPromptDialog("Создать группу", "Название группы") { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            await RunActionAsync("group.create", new { name = dialog.Value }, "Группа создана.");
        }
    }

    private async void InviteButton_Click(object sender, RoutedEventArgs e)
    {
        var result = await RunActionAsync("invite.create", new { }, "Одноразовое приглашение создано.");
        if (result is null)
        {
            return;
        }
        var token = StringValue(result.Value, "token", "code");
        if (string.IsNullOrWhiteSpace(token))
        {
            ReportError(new DirectLanProtocolException("Служба не вернула код приглашения."), true);
            return;
        }
        var expires = StringValue(result.Value, "expires_at");
        new InviteDialog(token, expires) { Owner = this }.ShowDialog();
    }

    private async void JoinButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new TextPromptDialog("Вступить в группу", "Одноразовый код приглашения",
            "При прямом подключении другие участники увидят ваш публичный IP-адрес. Владелец группы должен подтвердить отпечаток вашего ключа.")
        { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            await RunActionAsync("invitation.join", new { token = dialog.Value },
                "Запрос на вступление отправлен. Ожидается подтверждение владельца.");
        }
    }

    private async void ApproveButton_Click(object sender, RoutedEventArgs e)
    {
        if (MembersGrid.SelectedItem is not MemberRow member ||
            string.IsNullOrWhiteSpace(member.Fingerprint))
        {
            return;
        }
        var confirmation = MessageBox.Show(this,
            $"Подтвердить устройство «{member.Name}»?\n\nОтпечаток ключа:\n{member.Fingerprint}\n\n" +
            "Сверьте отпечаток с владельцем устройства. При прямом соединении участники увидят публичные IP-адреса друг друга.",
            "Подтверждение ключа", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirmation == MessageBoxResult.Yes)
        {
            await RunActionAsync("member.approve",
                new { device_id = member.DeviceId, fingerprint = member.Fingerprint },
                "Ключ устройства подтверждён.");
        }
    }

    private async void RevokeButton_Click(object sender, RoutedEventArgs e)
    {
        if (MembersGrid.SelectedItem is not MemberRow member)
        {
            return;
        }
        if (MessageBox.Show(this, $"Удалить доступ устройства «{member.Name}»?",
                "Отзыв доступа", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
        {
            await RunActionAsync("member.revoke", new { device_id = member.DeviceId },
                "Доступ устройства отозван.");
        }
    }

    private async void CheckButton_Click(object sender, RoutedEventArgs e)
    {
        if (MembersGrid.SelectedItem is not MemberRow member)
        {
            return;
        }
        var result = await RunActionAsync("connection.check", new { device_id = member.DeviceId },
            "Проверка связи завершена.");
        if (result is { ValueKind: JsonValueKind.Object })
        {
            var details = StringValue(result.Value, "message", "summary");
            if (!string.IsNullOrWhiteSpace(details))
            {
                AddLocalEvent("Проверка", details);
                FooterText.Text = details;
            }
        }
    }

    private async void LoadAdaptersButton_Click(object sender, RoutedEventArgs e) =>
        await LoadAdaptersAsync();

    private async void SelectAdapterButton_Click(object sender, RoutedEventArgs e)
    {
        if (AdapterCombo.SelectedItem is AdapterRow adapter)
        {
            await RunActionAsync("adapter.select", new { id = adapter.Id },
                $"Выбран адаптер «{adapter.Name}»; состояние соединения перепроверяется.");
        }
    }

    private void CopyIpButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_virtualIp))
        {
            return;
        }
        try
        {
            Clipboard.SetText(_virtualIp);
            FooterText.Text = "Виртуальный IP скопирован.";
        }
        catch (Exception ex)
        {
            ReportError(ex, true);
        }
    }

    private async void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Экспорт диагностики DirectLAN",
            Filter = "JSON (*.json)|*.json|Текстовый файл (*.txt)|*.txt",
            FileName = $"directlan-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.json"
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        // The privileged service returns data only. File creation stays in the UI process,
        // under the current user's permissions.
        var result = await RunActionAsync("diagnostics.export", new { },
            "Отчёт диагностики получен от службы.");
        if (result is null)
        {
            return;
        }

        var report = Get(result.Value, "report");
        if (report.ValueKind == JsonValueKind.Undefined)
        {
            report = result.Value;
        }
        if (report.ValueKind != JsonValueKind.Object)
        {
            ReportError(new DirectLanProtocolException("Служба вернула отчёт диагностики в неверном формате."), true);
            return;
        }

        try
        {
            await using var file = new FileStream(dialog.FileName, FileMode.Create,
                FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            await JsonSerializer.SerializeAsync(file, report,
                new JsonSerializerOptions { WriteIndented = true });
            await file.FlushAsync();
            var message = $"Диагностика сохранена: {dialog.FileName}";
            FooterText.Text = message;
            AddLocalEvent("Действие", message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            ReportError(ex, true);
        }
    }

    private static JsonElement Get(JsonElement source, params string[] names)
    {
        if (source.ValueKind != JsonValueKind.Object)
        {
            return default;
        }
        foreach (var name in names)
        {
            if (source.TryGetProperty(name, out var value))
            {
                return value;
            }
        }
        foreach (var property in source.EnumerateObject())
        {
            if (names.Any(name => string.Equals(name, property.Name,
                    StringComparison.OrdinalIgnoreCase)))
            {
                return property.Value;
            }
        }
        return default;
    }

    private static string? StringValue(JsonElement source, params string[] names)
    {
        var value = Get(source, names);
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        };
    }

    private static bool? BoolValue(JsonElement source, params string[] names)
    {
        var value = Get(source, names);
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static string FormatMetric(JsonElement source, string suffix, params string[] names)
    {
        var value = Get(source, names);
        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number))
        {
            return number.ToString("0.##", CultureInfo.CurrentCulture) + " " + suffix;
        }
        if (value.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(value.GetString()))
        {
            return value.GetString() + " " + suffix;
        }
        return "—";
    }

    private static string Display(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;
    private static Brush Brush(string hex) => (Brush)new BrushConverter().ConvertFromString(hex)!;

    public sealed record MemberRow(string DeviceId, string Name, string OverlayIp,
        bool? Approved, string State, string Egress, string Rtt, string Fingerprint)
    {
        public string ApprovalText => Approved switch
        {
            true => "Подтверждён",
            false => "Ожидает",
            _ => "—"
        };
    }

    public sealed record AdapterRow(string Id, string Name);
    public sealed record EventRow(string Header, string Message);
}
