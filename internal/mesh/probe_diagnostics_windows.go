//go:build windows

package mesh

import (
	"strings"
	"time"

	"directlan/internal/tunnel"
)

func counterDelta(before, after uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func describeTransportFailure(stage, detail string, stats tunnel.PeerStats, d tunnel.TransportDiagnostics) (string, string) {
	if stage != "reply_timeout" || !stats.LastHandshake.IsZero() || !d.PeerAttributed {
		return stage, detail
	}
	if d.ResponseIn > 0 {
		return "wireguard_response_unconfirmed", "Ответ рукопожатия дошёл и прошёл проверку шифрованной оболочки, но завершение сеанса WireGuard не подтверждено. Обновите коды существующей сети на обоих ПК."
	}
	if d.InitiationIn > 0 && d.ResponseOut > 0 {
		return "handshake_incomplete", "Принимаем запросы рукопожатия и отправляем ответы, но завершение не подтверждено. Нужно проверить приём ответа на втором ПК и обратный UDP-путь."
	}
	return stage, detail
}

func describeProbeFailure(err error, stats tunnel.PeerStats, before, after tunnel.PeerDiagnostics, now time.Time) (string, string) {
	stage := "unknown"
	if err != nil {
		for _, candidate := range []string{"before_stats", "open_socket", "deadline", "nonce", "send", "reply_timeout", "reply_read", "bad_reply", "after_stats", "handshake_missing", "stale_handshake", "no_stats_delta"} {
			if strings.Contains(err.Error(), "stage="+candidate) {
				stage = candidate
				break
			}
		}
	}
	if after.WriteErrors > before.WriteErrors {
		return "adapter_write", "Windows не приняла пакет виртуального адаптера. Подробности записаны в журнал работы."
	}
	if after.InboundDrops > before.InboundDrops || after.OutboundDrops > before.OutboundDrops {
		return "packet_policy", "Проверка адресов отклонила пакет. Обновите подписанный состав сети на обоих ПК."
	}
	if stage == "open_socket" || stage == "send" {
		return stage, "Windows не смогла отправить проверку через виртуальный IP. Проверьте адаптер, маршруты и другие VPN."
	}
	if stage == "reply_timeout" && after.OutboundPackets == before.OutboundPackets {
		return "local_route", "Проверочный пакет не дошёл до адаптера DirectLAN. Возможен конфликт маршрутов или другого VPN."
	}
	if stage == "no_stats_delta" || stage == "bad_reply" {
		return stage, "Полученный ответ проверки не совпал с запросом или не подтверждён счётчиками WireGuard. Подробности записаны в журнал."
	}
	if after.InboundPackets > before.InboundPackets {
		if after.EchoRequests > before.EchoRequests {
			return stage, "Данные от участника приходят, но ответ на нашу проверку не получен. Проверьте брандмауэр и другие VPN на обоих ПК."
		}
		return stage, "Данные расшифрованы и переданы адаптеру, но Windows не вернула ответ проверки. Проверьте брандмауэр и другие VPN."
	}
	if stats.LastHandshake.IsZero() {
		return stage, "Рукопожатие WireGuard не получено. Прямой UDP-путь к этому участнику пока не подтверждён."
	}
	if now.Sub(stats.LastHandshake) > 3*time.Minute {
		return stage, "Рукопожатие WireGuard устарело. Доступность прямого UDP-пути сейчас не подтверждена."
	}
	return stage, "Рукопожатие есть, но ответ на данные не пришёл. Возможны потери или фильтрация UDP, либо блокировка на втором ПК."
}
