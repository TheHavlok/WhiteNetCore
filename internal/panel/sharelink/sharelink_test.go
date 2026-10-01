package sharelink

import (
	"strings"
	"testing"

	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

func vlessServer() subscription.Server {
	return subscription.Server{
		ID:        "4f1c9e0a-1111-2222-3333-444455556666:vless-reality",
		Name:      "🇩🇪 Germany 1",
		Country:   "DE",
		Group:     "Europe",
		Protocol:  subscription.ProtocolVLESS,
		Transport: "reality",
		Address:   "1.2.3.4",
		Port:      443,
		Params: map[string]string{
			"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"flow": "xtls-rprx-vision",
			"sni":  "www.microsoft.com",
			"pbk":  "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
			"sid":  "6ba85179e30d4fc2",
			"fp":   "chrome",
		},
	}
}

func fluxServer() subscription.Server {
	return subscription.Server{
		ID:        "4f1c9e0a-1111-2222-3333-444455556666:flux-yandex",
		Name:      "🇳🇱 Netherlands (Yandex Docs)",
		Country:   "NL",
		Protocol:  subscription.ProtocolFlux,
		Transport: "yandex",
		Flux: &subscription.Flux{
			Mode: "l4",
			Channels: []subscription.Channel{{
				ID:      "ch-1",
				Secret:  strings.Repeat("ab", 32),
				Context: "https://docs.yandex.ru/docs/view/abc",
				Carriers: []subscription.Carrier{
					{Type: "yandex", URL: "https://docs.yandex.ru/docs/view/abc", Priority: 50},
					{Type: "direct", Priority: 100, Params: map[string]string{"dial": "1.2.3.4:8443"}},
				},
			}},
		},
	}
}

func wndnsServer() subscription.Server {
	return subscription.Server{
		ID:        "4f1c9e0a-1111-2222-3333-444455556666:wndns-53",
		Name:      "🇩🇪 Germany 1 (DNS)",
		Protocol:  subscription.ProtocolWNDNS,
		Transport: "dns",
		Address:   "1.2.3.4",
		Port:      53,
		Params: map[string]string{
			"domains":           "t1.example.com,t2.example.com",
			"encryption_method": "2",
			"encryption_key":    strings.Repeat("c", 32),
		},
		Chain: &subscription.Chain{
			Protocol:  subscription.ProtocolVLESS,
			Transport: "raw",
			Params:    map[string]string{"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := Bundle{
		Name:    "WhiteNet",
		Servers: []subscription.Server{vlessServer(), fluxServer(), wndnsServer()},
		Sub:     "https://sub.example.com/sub/7f3a9c1e",
		Branding: &subscription.Branding{
			AppName:    "WhiteNetVPN",
			SupportURL: "https://t.me/whitenet",
		},
	}
	link, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, Prefix) {
		t.Fatalf("link does not start with %s: %s", Prefix, link)
	}
	// A link has to survive a QR code and a chat message, so keep an eye on
	// its length: version 20 QR at medium correction holds about 1050
	// alphanumeric characters.
	if len(link) > 1000 {
		t.Errorf("link is %d characters, which starts to be hard to scan: %s", len(link), link)
	}

	got, err := Decode(link)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || got.Sub != want.Sub {
		t.Errorf("name/sub = %q/%q, want %q/%q", got.Name, got.Sub, want.Name, want.Sub)
	}
	if len(got.Servers) != 3 {
		t.Fatalf("got %d servers, want 3", len(got.Servers))
	}
	if got.Servers[0].Params["pbk"] != want.Servers[0].Params["pbk"] {
		t.Error("reality public key did not survive the round trip")
	}
	if got.Servers[1].Flux == nil || len(got.Servers[1].Flux.Channels[0].Carriers) != 2 {
		t.Error("flux carriers did not survive the round trip")
	}
	if got.Servers[2].Chain == nil || got.Servers[2].Chain.Protocol != subscription.ProtocolVLESS {
		t.Error("wndns chain did not survive the round trip")
	}
	if got.Branding == nil || got.Branding.SupportURL != want.Branding.SupportURL {
		t.Error("branding did not survive the round trip")
	}
}

// A link gets wrapped, padded and alphabet-swapped on its way through
// terminals and chat apps. All of that must still decode.
func TestDecodeToleratesDamage(t *testing.T) {
	link, err := EncodeServer("one", vlessServer())
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(link, Prefix)

	variants := map[string]string{
		"leading and trailing space": "  " + link + "\n",
		"wrapped":                    Prefix + body[:20] + "\n" + body[20:],
		"padded":                     link + "==",
		"standard alphabet":          Prefix + strings.NewReplacer("-", "+", "_", "/").Replace(body),
		"non-breaking space":         Prefix + body[:10] + " " + body[10:],
	}
	for name, variant := range variants {
		if _, err := Decode(variant); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeRejections(t *testing.T) {
	link, err := EncodeServer("one", vlessServer())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		link string
		code string
	}{
		"not a link":      {"https://example.com", CodeNotLink},
		"vless link":      {"vless://uuid@1.2.3.4:443", CodeNotLink},
		"other version":   {"whitenet://v9/abcd", CodeUnsupportedVersion},
		"uppercased":      {strings.ToUpper(link), CodeCaseChanged},
		"garbage payload": {Prefix + "!!!!not base64!!!!", CodeDamaged},
		"empty payload":   {Prefix, CodeDamaged},
	}
	for name, tc := range cases {
		_, err := Decode(tc.link)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if got := ErrorCode(err); got != tc.code {
			t.Errorf("%s: code = %q, want %q (%v)", name, got, tc.code, err)
		}
	}
}

func TestEncodeRejectsBadBundles(t *testing.T) {
	cases := map[string]Bundle{
		"no servers": {Name: "empty"},
		"server without an address": {Servers: []subscription.Server{{
			ID: "x:y", Name: "n", Protocol: subscription.ProtocolVLESS,
		}}},
		"wndns without a chain": {Servers: []subscription.Server{{
			ID: "x:y", Name: "n", Protocol: subscription.ProtocolWNDNS,
			Address: "1.2.3.4", Params: map[string]string{"domains": "a.example"},
		}}},
		"flux without channels or lease": {Servers: []subscription.Server{{
			ID: "x:y", Name: "n", Protocol: subscription.ProtocolFlux,
			Flux: &subscription.Flux{Mode: "l4"},
		}}},
		"unknown protocol": {Servers: []subscription.Server{{
			ID: "x:y", Name: "n", Protocol: "wireguard", Address: "1.2.3.4", Port: 51820,
		}}},
		"duplicate ids": {Servers: []subscription.Server{vlessServer(), vlessServer()}},
		"http subscription": {
			Servers: []subscription.Server{vlessServer()},
			Sub:     "http://sub.example.com/sub/abc",
		},
	}
	for name, bundle := range cases {
		if _, err := Encode(bundle); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestImportLinkRoundTrip(t *testing.T) {
	const subURL = "https://sub.example.com/sub/7f3a9c1e?x=1&y=2"
	link, err := ImportLink(subURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "whitenetvpn://import?") {
		t.Fatalf("unexpected link: %s", link)
	}
	got, err := ParseImportLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != subURL {
		t.Errorf("url = %q, want %q", got, subURL)
	}

	// The triple-slash form is what some URL builders produce; accept it.
	if got, err := ParseImportLink("whitenetvpn:///import?url=https%3A%2F%2Fsub.example.com%2Fsub%2Fabc"); err != nil {
		t.Errorf("triple slash form: %v", err)
	} else if got != "https://sub.example.com/sub/abc" {
		t.Errorf("triple slash form: url = %q", got)
	}
}

func TestImportLinkRejections(t *testing.T) {
	cases := map[string]struct {
		link string
		code string
	}{
		"wrong scheme":     {"https://sub.example.com/sub/abc", CodeNotLink},
		"wrong action":     {"whitenetvpn://connect?url=https%3A%2F%2Fa.example%2Fs", CodeNotLink},
		"missing url":      {"whitenetvpn://import", CodeNoURL},
		"plain http":       {"whitenetvpn://import?url=http%3A%2F%2Fa.example%2Fs", CodeNotHTTPS},
		"url with no host": {"whitenetvpn://import?url=%2Fsub%2Fabc", CodeNoURL},
	}
	for name, tc := range cases {
		_, err := ParseImportLink(tc.link)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if got := ErrorCode(err); got != tc.code {
			t.Errorf("%s: code = %q, want %q (%v)", name, got, tc.code, err)
		}
	}
	if _, err := ImportLink("http://sub.example.com/s"); err == nil {
		t.Error("ImportLink accepted plain http")
	}
}
