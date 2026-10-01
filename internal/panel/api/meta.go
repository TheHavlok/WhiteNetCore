package api

import (
	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/panel/keygen"
)

// carrierLabels are the human names for the flux carriers, and what each one
// needs. The panel's form reads this rather than hard-coding it, so adding a
// carrier to the core shows up in the UI without a second change.
var carrierLabels = map[string]struct {
	Label string
	Needs []string
	Note  string
}{
	fluxnode.CarrierDirect: {
		Label: "Direct (plain TCP)",
		Needs: []string{"listen"},
		Note:  "The exit listens on this address; the client dials it. Fast, but an ordinary port.",
	},
	fluxnode.CarrierYandexDocs: {
		Label: "Yandex.Docs",
		Needs: []string{"url", "cookies_file"},
		Note: "Traffic rides a Yandex document over a WebSocket. A public document needs no account, " +
			"but from an address Yandex challenges with SmartCaptcha it will not open without one: " +
			"put a Netscape cookies.txt for a signed-in account on the node and give its path.",
	},
	fluxnode.CarrierYandexVolga: {
		Label: "Yandex Volga",
		Needs: []string{"url", "cookies_file"},
		Note:  "Needs a Netscape cookies.txt with a signed-in Yandex account.",
	},
	fluxnode.CarrierYandexBoards: {
		Label: "Yandex Boards",
		Needs: []string{"url"},
	},
	fluxnode.CarrierMailruDocs: {
		Label: "Mail.ru Docs",
		Needs: []string{"url"},
	},
	fluxnode.CarrierCupsOnline: {
		Label: "Cups.online",
		Needs: []string{"url"},
		Note:  "A Centrifugo room. Only the exit creates rooms.",
	},
	fluxnode.CarrierOneMe: {
		Label: "MAX / OneMe",
		Needs: []string{"token", "uid"},
		Note:  "A WebRTC data channel. The token belongs to the exit's own MAX account, so this carrier is never put in a share link.",
	},
}

// fluxCarrierMeta is what the UI's carrier picker shows.
func fluxCarrierMeta() []map[string]any {
	out := make([]map[string]any, 0, len(fluxnode.Carriers()))
	for _, name := range fluxnode.Carriers() {
		meta := carrierLabels[name]
		label := meta.Label
		if label == "" {
			label = name
		}
		out = append(out, map[string]any{
			"value": name,
			"label": label,
			"needs": meta.Needs,
			"note":  meta.Note,
		})
	}
	return out
}

// shadowsocksMethodMeta lists the methods with whether each can serve several
// users, which an operator has to know before picking one.
func shadowsocksMethodMeta() []map[string]any {
	var out []map[string]any
	for _, method := range keygen.LegacyShadowsocksMethods() {
		out = append(out, map[string]any{
			"value":         method,
			"protocol":      "shadowsocks",
			"multiuser":     keygen.SupportsMultipleUsers(method),
			"key_is_base64": false,
		})
	}
	for _, method := range keygen.Shadowsocks2022Methods() {
		size, _ := keygen.Shadowsocks2022KeySize(method)
		out = append(out, map[string]any{
			"value":         method,
			"protocol":      "shadowsocks2022",
			"multiuser":     keygen.SupportsMultipleUsers(method),
			"key_is_base64": true,
			"key_bytes":     size,
		})
	}
	return out
}
