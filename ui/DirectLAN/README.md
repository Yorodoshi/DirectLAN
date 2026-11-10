# DirectLAN для Windows

WPF-клиент для службы DirectLAN. Требуются Windows 11 x64 и .NET 10 Desktop Runtime.

```powershell
dotnet build ui/DirectLAN/DirectLAN.csproj -c Release
dotnet run --project ui/DirectLAN/DirectLAN.csproj
```

Клиент открывает локальный именованный канал `\\.\pipe\DirectLAN`. Каждый вызов использует новый канал и одну UTF-8 JSON-строку в каждом направлении:

```json
{"version":1,"id":"...","method":"status","params":{}}
{"version":1,"id":"...","ok":true,"result":{}}
```

Ошибки службы имеют вид `{"version":1,"id":"...","ok":false,"error":{"code":"...","message":"...","action":"..."}}`. Клиент проверяет версию и идентификатор ответа, ограничивает размер ответа 2 МиБ и время вызова 15 секундами. Если служба недоступна, экран не показывает старое состояние как актуальное.

Команды интерфейса: `status`, `group.create` (`name`), `invite.create`, `invitation.join` (`token`), `member.approve` (`device_id`, `fingerprint`), `member.revoke` (`device_id`), `adapter.list`, `adapter.select` (`id`), `connection.check` (`device_id`) и `diagnostics.export` (без параметров).

Для подтверждения участника служба должна включить `fingerprint` в его запись `status.members`. Без отпечатка кнопка подтверждения недоступна. Проверка связи выполняется для выбранного участника. Экспорт диагностики запускается только по действию пользователя: служба возвращает очищенный JSON-отчёт (напрямую или в поле `report`), а клиент сохраняет его с правами текущего пользователя. Путь файла не передаётся службе.
