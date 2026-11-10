using System.Windows;
using DirectLAN.Launcher;

namespace DirectLAN;

public partial class App : Application
{
    private DesktopInstance? _desktopInstance;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try
        {
            if (e.Args.Length == 2 && e.Args[0] == "--worker")
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Shutdown(await LauncherWorker.RunAsync(e.Args[1]));
                return;
            }
            if (e.Args.Length == 2 && e.Args[0] == "--launcher-self-test")
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Shutdown(await LauncherSelfTest.RunAsync(e.Args[1]));
                return;
            }
            if (e.Args.Length > 1 && e.Args[0] == "--launch" && e.Args[1] is "mesh" or "peer"
                && !DesktopInstance.TryAcquire(this, out _desktopInstance))
            {
                Shutdown();
                return;
            }
            MainWindow = e.Args.Length > 1 && e.Args[0] == "--launch"
                ? e.Args[1] == "mesh" ? new NetworkWindow() : e.Args[1] == "peer" ? new PeerWindow() : new LauncherWindow(e.Args[1] == "server")
                : new MainWindow();
            MainWindow.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "DirectLAN — ошибка запуска", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _desktopInstance?.Dispose();
        base.OnExit(e);
    }
}
