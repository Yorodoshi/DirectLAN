using System.IO;
using System.Security.Principal;
using System.Text.Json;

namespace DirectLAN.Launcher;

public static class SessionController
{
    public static void ThrowIfBusy()
    {
        if (IsWorkerBusy())
            throw new IOException("Уже работает другое подключение DirectLAN. Нажмите «Закрыть все подключения DirectLAN», затем повторите запуск.");
    }

    public static async Task StopAllAsync()
    {
        var runs = Path.Combine(LaunchConfig.DataRoot, "launcher-runs");
        var currentSid = WindowsIdentity.GetCurrent().User?.Value;
        var inaccessibleEvent = false;
        if (Directory.Exists(runs))
        {
            foreach (var path in Directory.EnumerateFiles(runs, "*.json"))
            {
                if (!LaunchConfig.ValidConfigPath(path)) continue;
                LaunchConfig? config;
                try
                {
                    if (new FileInfo(path).Length > 65536) continue;
                    config = JsonSerializer.Deserialize<LaunchConfig>(await File.ReadAllTextAsync(path));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { continue; }
                if (config is null || !config.DirectPair || config.UserSid != currentSid ||
                    config.RunId != Path.GetFileNameWithoutExtension(path)) continue;
                try
                {
                    using var stop = EventWaitHandle.OpenExisting(config.StopEvent);
                    stop.Set();
                }
                catch (WaitHandleCannotBeOpenedException) { }
                catch (UnauthorizedAccessException) { inaccessibleEvent = true; }
            }
        }
        for (var attempt = 0; attempt < 125; attempt++)
        {
            if (!IsWorkerBusy()) return;
            await Task.Delay(200);
        }
        if (inaccessibleEvent)
            throw new UnauthorizedAccessException("Нет доступа к завершению одного из запусков DirectLAN. Закройте его текущее окно.");
        throw new TimeoutException("Служба DirectLAN ещё завершает работу. Откройте её текущее окно и закройте его. Журнал запуска поможет уточнить причину.");
    }

    private static bool IsWorkerBusy()
    {
        var path = Path.Combine(LaunchConfig.DataRoot, "direct-worker.lock");
        if (!File.Exists(path)) return false;
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (FileNotFoundException) { return false; }
        catch (IOException) { return true; }
    }
}
