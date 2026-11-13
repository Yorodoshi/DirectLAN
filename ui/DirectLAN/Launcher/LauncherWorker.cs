using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using DirectLAN.Ipc;

namespace DirectLAN.Launcher;

public static class LauncherWorker
{
    public static async Task<int> RunAsync(string configPath, bool isolatedTest = false)
    {
        if (!LaunchConfig.ValidConfigPath(configPath)) return 1;
        var processes = new List<Process>();
        var rules = new List<string>();
        EventWaitHandle? stop = null;
        StreamWriter? log = null;
        FileStream? serverLock = null;
        var logLock = new object();
        void Log(string? line) { if (line is null) return; lock (logLock) { if (log is not null && log.BaseStream.Length < 1024 * 1024) { log.WriteLine(line); log.Flush(); } } }
        void State(string phase, string message)
        {
            var path = LaunchConfig.StatePath(configPath);
            File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(new RunState(phase, message)));
            File.Move(path + ".tmp", path, true);
        }
        bool failed = false;
        bool reportedError = false;
        try
        {
            if (new FileInfo(configPath).Length > 65536) throw new InvalidDataException("Настройка запуска слишком велика.");
            var config = JsonSerializer.Deserialize<LaunchConfig>(await File.ReadAllTextAsync(configPath)) ?? throw new InvalidDataException("Пустая настройка запуска.");
            config.Validate(configPath);
            var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if ((config.StartClient || config.ConfigureFirewall) && !principal.IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException("Нужны права администратора для Wintun и правила DirectLAN.");
            stop = EventWaitHandle.OpenExisting(config.StopEvent);
            var serverHost = config.StartServer ? new Uri(config.CoordinatorUrl).Host : "";
            log = new StreamWriter(Path.ChangeExtension(configPath, ".log"), append: false) { AutoFlush = true };
            State("Starting", "Запуск компонентов DirectLAN…");
            if (config.DirectPair)
            {
                try { serverLock = new FileStream(Path.Combine(LaunchConfig.DataRoot, "direct-worker.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException ex) { throw new IOException("DirectLAN уже запущен. Используйте открытое окно программы.", ex); }
            }
            if (config.ConfigureFirewall)
            {
                if (config.StartClient) AddFirewallRule(config, "client", LaunchConfig.Executable("directlan-service.exe"), 17, null, rules);
                if (config.StartServer) AddFirewallRule(config, "server", LaunchConfig.Executable("directlan-coordinator.exe"), 6, config.Port, rules);
            }
            Process Start(string name, params string[] args)
            {
                var info = new ProcessStartInfo(LaunchConfig.Executable(name)) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = LaunchConfig.Bundle, RedirectStandardError = true, RedirectStandardOutput = true, StandardErrorEncoding = Encoding.UTF8, StandardOutputEncoding = Encoding.UTF8 };
                foreach (var arg in args) info.ArgumentList.Add(arg);
                var process = new Process { StartInfo = info };
                process.ErrorDataReceived += (_, e) => Log(e.Data);
                process.OutputDataReceived += (_, e) => Log(e.Data);
                if (!process.Start()) throw new IOException("Не удалось запустить " + name);
                processes.Add(process); process.BeginErrorReadLine(); process.BeginOutputReadLine();
                return process;
            }
            if (config.StartServer)
            {
                var stateDirectory = isolatedTest ? config.ServerDirectory : Path.Combine(LaunchConfig.DataRoot, "server");
                if (!isolatedTest)
                {
                    try { serverLock = new FileStream(Path.Combine(stateDirectory, "coordinator.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                    catch (IOException ex) { throw new IOException("Локальный сервер DirectLAN уже запущен или его состояние недоступно.", ex); }
                }
                Start("directlan-coordinator.exe", "-listen", serverHost + ":" + config.Port, "-state", Path.Combine(stateDirectory, "coordinator.json"), "-tls-cert", Path.Combine(config.ServerDirectory, "server.pem"), "-tls-key", Path.Combine(config.ServerDirectory, "server-key.pem"), "-https-relay", "-stop-event", config.StopEvent);
            }
            if (config.DirectPair)
                Start("directlan-service.exe", "-direct-pair", "-identity", LaunchConfig.PeerIdentity, "-ui-sid", config.UserSid, "-stop-event", config.StopEvent);
            else if (config.StartClient)
                Start("directlan-service.exe", "-coordinator", config.CoordinatorUrl, "-coordinator-ca", config.CAPath, "-identity", Path.Combine(LaunchConfig.DataRoot, "identity.dat"), "-ui-sid", config.UserSid, "-device-name", Environment.MachineName, "-transport", config.Transport, "-padding=" + config.Padding.ToString().ToLowerInvariant(), "-stop-event", config.StopEvent);

            var ready = false;
            for (var attempt = 0; attempt < 60 && !stop.WaitOne(0); attempt++)
            {
                ThrowIfChildExited(processes);
                try
                {
                    if (config.StartServer)
                    {
                        using var tcp = new TcpClient();
                        await tcp.ConnectAsync(serverHost, config.Port).WaitAsync(TimeSpan.FromSeconds(1));
                    }
                    if (config.DirectPair) await new DirectLanClient("DirectLAN-Peer").CallAsync("system.ready");
                    else if (config.StartClient) await new DirectLanClient().CallAsync("status");
                    await Task.Delay(200);
                    ThrowIfChildExited(processes); ready = true; break;
                }
                catch (Exception ex) when (ex is SocketException or TimeoutException or DirectLanUnavailableException) { await Task.Delay(300); }
            }
            if (!ready && !stop.WaitOne(0)) throw new TimeoutException("Служба не ответила. Подробности сохранены в журнале запуска.");
            if (ready) State("Ready", "DirectLAN запущен. Закрытие окна запуска штатно остановит его компоненты.");
            while (ready && !stop.WaitOne(0))
            {
                await Task.Delay(200);
                if (stop.WaitOne(0)) break;
                ThrowIfChildExited(processes);
                try
                {
                    using var parent = Process.GetProcessById(config.ParentId);
                    if (parent.StartTime.ToUniversalTime().Ticks != config.ParentStartTicks) break;
                }
                catch (ArgumentException) { break; }
            }
        }
        catch (Exception ex)
        {
            failed = true;
            Log(ex.Message);
            try { State("Error", ex.Message + "\nЖурнал: " + Path.ChangeExtension(configPath, ".log")); reportedError = true; } catch (IOException) { }
        }
        finally
        {
            stop?.Set();
            foreach (var process in processes)
            {
                try
                {
                    if (!process.HasExited) await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
                }
                catch (TimeoutException)
                {
                    failed = true; Log("Не завершился штатно: " + process.StartInfo.FileName);
                    try { process.Kill(); } catch (InvalidOperationException) { }
                }
                process.Dispose();
            }
            foreach (var rule in rules)
            {
                try { dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!; policy.Rules.Remove(rule); }
                catch (Exception ex) { Log("Не удалось убрать правило DirectLAN: " + ex.Message); failed = true; }
            }
            if (!failed) { try { State("Stopped", "Компоненты остановлены, временные правила DirectLAN удалены."); } catch (IOException) { } }
            else if (!reportedError) { try { State("Error", "Остановка завершилась с ошибкой. Журнал: " + Path.ChangeExtension(configPath, ".log")); } catch (IOException) { } }
            stop?.Dispose();
            serverLock?.Dispose();
            lock (logLock) { log?.Dispose(); log = null; }
        }
        return failed ? 1 : 0;
    }

    private static void ThrowIfChildExited(IEnumerable<Process> processes)
    {
        foreach (var process in processes)
            if (process.HasExited) throw new IOException($"{Path.GetFileName(process.StartInfo.FileName)} завершился с кодом {process.ExitCode}. Возможно, порт занят или DirectLAN уже запущен.");
    }

    private static void AddFirewallRule(LaunchConfig config, string suffix, string executable, int protocol, int? port, List<string> created)
    {
        var name = "DirectLAN-Launcher-" + config.RunId + "-" + suffix;
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        rule.Name = name; rule.Description = "Temporary application-scoped DirectLAN rule";
        rule.ApplicationName = executable; rule.Protocol = protocol; rule.Direction = 1; rule.Action = 1; rule.Profiles = int.MaxValue; rule.Enabled = true;
        if (port.HasValue) { rule.LocalPorts = port.Value.ToString(); rule.RemoteAddresses = "LocalSubnet"; }
        policy.Rules.Add(rule); created.Add(name);
    }
}
