using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text.Json;

namespace DirectLAN.Launcher;

public sealed class LaunchConfig
{
    public string RunId { get; set; } = Guid.NewGuid().ToString("N");
    public string UserSid { get; set; } = WindowsIdentity.GetCurrent().User!.Value;
    public int ParentId { get; set; } = Environment.ProcessId;
    public long ParentStartTicks { get; set; } = Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;
    public bool StartServer { get; set; }
    public bool DirectPair { get; set; }
    public bool StartClient { get; set; } = true;
    public bool ConfigureFirewall { get; set; } = true;
    public string CoordinatorUrl { get; set; } = "";
    public string CAPath { get; set; } = "";
    public string ServerDirectory { get; set; } = "";
    public int Port { get; set; } = 4433;
    public string Transport { get; set; } = "https";
    public bool Padding { get; set; } = true;
    public string StopEvent => @"Local\DirectLAN.Stop." + RunId;
    public static string DataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DirectLAN");
    public static string Bundle => Directory.GetParent(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!.FullName;
    public static string Executable(string name) => Path.Combine(Bundle, name);
    public static string PeerIdentity => Path.Combine(DataRoot, "direct-identity.dat");
    public static string StatePath(string configPath) => Path.ChangeExtension(configPath, ".status.json");
    public static bool ValidConfigPath(string path) => Inside(path, Path.Combine(DataRoot, "launcher-runs")) && Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out _) && Path.GetExtension(path) == ".json";
    public static JsonSerializerOptions JsonOptions { get; } = new() { WriteIndented = true };

    public void Validate(string configPath)
    {
        if (!Guid.TryParseExact(RunId, "N", out _)) throw new InvalidDataException("Неверный идентификатор запуска.");
        if (!ValidConfigPath(configPath) || Path.GetFileNameWithoutExtension(configPath) != RunId) throw new InvalidDataException("Неверный каталог настройки запуска.");
        if (UserSid != WindowsIdentity.GetCurrent().User?.Value) throw new InvalidOperationException("Запускайте под тем же пользователем Windows. Повышение под другой учётной записью не поддерживается.");
        if (DirectPair)
        {
            if (StartServer || !StartClient) throw new InvalidDataException("Неверный режим прямой пары.");
            RequireBundleFiles("directlan-service.exe", "wintun.dll");
            return;
        }
        if (!StartServer && !StartClient) throw new InvalidDataException("Не выбран компонент для запуска.");
        if (Port < 1 || Port > 65535 || Transport is not ("https" or "auto" or "direct")) throw new InvalidDataException("Неверные параметры сети.");
        if (!Uri.TryCreate(CoordinatorUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "") throw new InvalidDataException("Укажите адрес https://адрес:порт.");
        if (StartServer && (!IPAddress.TryParse(uri.Host, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || uri.Port != Port || uri.AbsolutePath != "/")) throw new InvalidDataException("Локальному серверу нужен IPv4 и выбранный порт.");
        if (!File.Exists(CAPath) || new FileInfo(CAPath).Length > 65536) throw new InvalidDataException("Не найден или слишком велик CA-сертификат.");
        if (StartServer && (!Inside(ServerDirectory, Path.Combine(DataRoot, "server")) || !File.Exists(Path.Combine(ServerDirectory, "server.pem")) || !File.Exists(Path.Combine(ServerDirectory, "server-key.pem")))) throw new InvalidDataException("Не найдены файлы сервера.");
        RequireBundleFiles("directlan-service.exe", "directlan-coordinator.exe", "directlan-cert.exe", "wintun.dll");
    }

    private static void RequireBundleFiles(params string[] files)
    {
        foreach (var executable in files)
            if (!File.Exists(Executable(executable))) throw new FileNotFoundException("Распакуйте весь архив. Не найден " + executable);
    }

    private static bool Inside(string path, string directory) => Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}

public sealed record RunState(string Phase, string Message);
public sealed class LauncherSettings
{
    public string CoordinatorUrl { get; set; } = "";
    public string CAPath { get; set; } = "";
    public string ServerAddress { get; set; } = "";
    public string ServerDirectory { get; set; } = "";
    public int Port { get; set; } = 4433;
    public bool AutoServer { get; set; }
    public bool AutoClient { get; set; }
    public bool ServerWithClient { get; set; } = true;
    public bool ServerFirewall { get; set; } = true;
    public bool ClientFirewall { get; set; } = true;
    public string ServerTransport { get; set; } = "https";
    public string ClientTransport { get; set; } = "https";
}
