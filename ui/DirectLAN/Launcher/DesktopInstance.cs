using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;

namespace DirectLAN.Launcher;

internal sealed class DesktopInstance : IDisposable
{
    private readonly Application _application;
    private readonly Mutex _mutex;
    private readonly EventWaitHandle _activation;
    private readonly MemoryMappedFile _owner;
    private readonly RegisteredWaitHandle _registration;
    private int _disposed;

    private DesktopInstance(Application application, Mutex mutex, EventWaitHandle activation, MemoryMappedFile owner)
    {
        _application = application;
        _mutex = mutex;
        _activation = activation;
        _owner = owner;
        _registration = ThreadPool.RegisterWaitForSingleObject(
            activation, (_, _) => QueueActivation(), null, Timeout.Infinite, false);
    }

    public static bool TryAcquire(Application application, out DesktopInstance? instance)
    {
        application.Dispatcher.VerifyAccess();
        instance = null;
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Не удалось определить пользователя Windows.");
        var name = @"Local\DirectLAN.Desktop." + sid;
        EventWaitHandle? activation = null;
        MemoryMappedFile? owner = null;
        Mutex? mutex = null;
        var acquired = false;
        try
        {
            activation = new EventWaitHandle(false, EventResetMode.AutoReset, name + ".Activate");
            owner = MemoryMappedFile.CreateOrOpen(name + ".Owner", 16);
            mutex = new Mutex(false, name + ".Mutex");
            try { acquired = mutex.WaitOne(0); }
            catch (AbandonedMutexException) { acquired = true; }
            if (!acquired)
            {
                AllowPrimaryForeground(owner);
                activation.Set();
                return false;
            }

            using (var process = Process.GetCurrentProcess())
            using (var metadata = owner.CreateViewAccessor())
            {
                metadata.Write(8, process.StartTime.ToUniversalTime().Ticks);
                metadata.Write(0, process.Id);
                metadata.Flush();
            }
            instance = new DesktopInstance(application, mutex, activation, owner);
            return true;
        }
        finally
        {
            if (instance is null)
            {
                if (acquired) mutex!.ReleaseMutex();
                mutex?.Dispose();
                owner?.Dispose();
                activation?.Dispose();
            }
        }
    }

    private static void AllowPrimaryForeground(MemoryMappedFile owner)
    {
        using var metadata = owner.CreateViewAccessor(0, 16, MemoryMappedFileAccess.Read);
        // A second launch can reach the mutex before the first has published
        // its PID. Keep the wait short so opening an existing window is quick.
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var processId = metadata.ReadInt32(0);
            if (processId != 0)
            {
                try
                {
                    using var primary = Process.GetProcessById(processId);
                    using var current = Process.GetCurrentProcess();
                    if (primary.ProcessName == current.ProcessName && primary.SessionId == current.SessionId
                        && primary.StartTime.ToUniversalTime().Ticks == metadata.ReadInt64(8))
                        AllowSetForegroundWindow(processId);
                }
                catch (ArgumentException) { }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
                return;
            }
            Thread.Sleep(10);
        }
    }

    private void QueueActivation()
    {
        if (Volatile.Read(ref _disposed) != 0 || _application.Dispatcher.HasShutdownStarted) return;
        try
        {
            _application.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, () =>
            {
                if (Volatile.Read(ref _disposed) != 0) return;
                var window = _application.MainWindow;
                if (window is null) return;
                if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
                window.Show();
                window.Activate();
            });
        }
        catch (InvalidOperationException) when (_application.Dispatcher.HasShutdownStarted) { }
    }

    public void Dispose()
    {
        _application.Dispatcher.VerifyAccess();
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _registration.Unregister(null);
        _activation.Dispose();
        _owner.Dispose();
        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(int processId);
}
