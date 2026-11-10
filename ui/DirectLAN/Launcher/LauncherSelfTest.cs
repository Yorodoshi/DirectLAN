using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace DirectLAN.Launcher;

// Exercises packaged EXEs, CA trust, readiness and graceful shutdown without
// an adapter, a firewall change or an administrator token.
internal static class LauncherSelfTest
{
    public static async Task<int> RunAsync(string reportPath)
    {
        var config = new LaunchConfig { StartServer = true, StartClient = false, ConfigureFirewall = false };
        var serverRoot = Path.Combine(LaunchConfig.DataRoot, "server", "launcher test " + config.RunId);
        var runDir = Path.Combine(LaunchConfig.DataRoot, "launcher-runs");
        Directory.CreateDirectory(runDir);
        var configPath = Path.Combine(runDir, config.RunId + ".json");
        using var stop = new EventWaitHandle(false, EventResetMode.ManualReset, config.StopEvent);
        Task<int>? worker = null;
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(); config.Port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            config.CoordinatorUrl = $"https://127.0.0.1:{config.Port}";
            config.ServerDirectory = serverRoot; config.CAPath = Path.Combine(serverRoot, "ca.pem");
            await LauncherWindow.PrepareCertificateAsync("127.0.0.1", serverRoot);
            File.WriteAllText(configPath, JsonSerializer.Serialize(config));
            worker = LauncherWorker.RunAsync(configPath, isolatedTest: true);
            for (var attempt = 0; attempt < 100 && LauncherWindow.ReadRunState(configPath)?.Phase != "Ready"; attempt++)
            {
                if (worker.IsCompleted) throw new IOException(LauncherWindow.ReadRunState(configPath)?.Message ?? "Worker exited before readiness");
                await Task.Delay(100);
            }
            using var ca = X509CertificateLoader.LoadCertificateFromFile(config.CAPath);
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(ca);
            using var handler = new SocketsHttpHandler { UseProxy = false };
            handler.SslOptions.CertificateChainPolicy = policy;
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            using var health = JsonDocument.Parse(await client.GetStringAsync(config.CoordinatorUrl + "/healthz"));
            if (health.RootElement.GetProperty("status").GetString() != "ok") throw new IOException("Unexpected health response");
            stop.Set();
            if (await worker.WaitAsync(TimeSpan.FromSeconds(22)) != 0 || LauncherWindow.ReadRunState(configPath)?.Phase != "Stopped") throw new IOException("Coordinator did not stop gracefully");
            File.WriteAllText(reportPath, "PASS: packaged certificate helper, HTTPS coordinator health, and graceful stop. No Wintun or firewall changes.");
            return 0;
        }
        catch (Exception ex) { File.WriteAllText(reportPath, "FAIL: " + ex); return 1; }
        finally
        {
            stop.Set();
            if (worker is not null) { try { await worker.WaitAsync(TimeSpan.FromSeconds(22)); } catch (TimeoutException) { } }
            foreach (var name in new[] { "ca.pem", "server.pem", "server-key.pem", "coordinator.json" }) File.Delete(Path.Combine(serverRoot, name));
            if (Directory.Exists(serverRoot) && !Directory.EnumerateFileSystemEntries(serverRoot).Any()) Directory.Delete(serverRoot);
            foreach (var path in new[] { configPath, LaunchConfig.StatePath(configPath), Path.ChangeExtension(configPath, ".log") }) File.Delete(path);
        }
    }
}
