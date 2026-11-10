using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace DirectLAN.Ipc;

public sealed class DirectLanClient
{
    private readonly string _pipeName;

    public DirectLanClient(string pipeName = "DirectLAN") => _pipeName = pipeName;

    private const int ProtocolVersion = 1;
    private const int MaximumResponseBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<JsonElement> CallAsync(string method, object? parameters = null,
        CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        var id = Guid.NewGuid().ToString("N");
        var request = new { version = ProtocolVersion, id, method, @params = parameters ?? new { } };
        var requestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, JsonOptions) + "\n");

        try
        {
            using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous);
            await pipe.ConnectAsync(2500, token);
            await pipe.WriteAsync(requestBytes, token);
            await pipe.FlushAsync(token);

            var responseBytes = await ReadLineAsync(pipe, token);
            using var document = JsonDocument.Parse(responseBytes);
            var response = document.RootElement;

            if (response.ValueKind != JsonValueKind.Object ||
                !response.TryGetProperty("version", out var version) ||
                version.ValueKind != JsonValueKind.Number || version.GetInt32() != ProtocolVersion ||
                !response.TryGetProperty("id", out var responseId) ||
                responseId.ValueKind != JsonValueKind.String || responseId.GetString() != id ||
                !response.TryGetProperty("ok", out var ok) ||
                (ok.ValueKind != JsonValueKind.True && ok.ValueKind != JsonValueKind.False))
            {
                throw new DirectLanProtocolException("Служба вернула ответ с неверной версией, идентификатором или форматом.");
            }

            if (ok.GetBoolean())
            {
                return response.TryGetProperty("result", out var result)
                    ? result.Clone()
                    : default;
            }

            var error = response.TryGetProperty("error", out var errorElement)
                ? errorElement
                : default;
            var code = GetString(error, "code") ?? "SERVICE_ERROR";
            var message = GetString(error, "message") ?? "Операция не выполнена.";
            var action = GetString(error, "action");
            throw new DirectLanServiceException(code, message, action);
        }
        catch (TimeoutException ex)
        {
            throw new DirectLanUnavailableException("Служба DirectLAN не ответила вовремя.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DirectLanUnavailableException("Время ожидания службы DirectLAN истекло.", ex);
        }
        catch (IOException ex)
        {
            throw new DirectLanUnavailableException("Нет связи со службой DirectLAN.", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new DirectLanUnavailableException("Нет доступа к каналу службы DirectLAN.", ex);
        }
    }

    private static async Task<byte[]> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var data = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken);
            if (count == 0)
            {
                throw new DirectLanProtocolException("Служба закрыла канал без ответа.");
            }

            var end = Array.IndexOf(buffer, (byte)'\n', 0, count);
            var length = end >= 0 ? end : count;
            if (data.Length + length > MaximumResponseBytes)
            {
                throw new DirectLanProtocolException("Ответ службы превышает допустимый размер.");
            }

            data.Write(buffer, 0, length);
            if (end >= 0)
            {
                return data.ToArray();
            }
        }
    }

    private static string? GetString(JsonElement element, string name)
    {
        return element.ValueKind == JsonValueKind.Object &&
               element.TryGetProperty(name, out var property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }
}

public sealed class DirectLanServiceException(string code, string message, string? action)
    : Exception(message)
{
    public string Code { get; } = code;
    public string? Action { get; } = action;
}

public sealed class DirectLanUnavailableException(string message, Exception innerException)
    : Exception(message, innerException);

public sealed class DirectLanProtocolException(string message) : Exception(message);
