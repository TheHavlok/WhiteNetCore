package mobile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// TestLeasedFluxProfileIsStartable is the end-to-end shape check: a leased
// mail.ru channel has to come back as a profile the flux client recognises,
// or the app would hand it to the wrong core and fail with no clear cause.
func TestLeasedFluxProfileIsStartable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(subscription.LeaseResponse{
			Channel: subscription.Channel{
				ID:     "ch-mailru",
				Secret: "7b1f0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4",
				Carriers: []subscription.Carrier{
					{Type: "mailru", URL: "https://cloud.mail.ru/public/wb2s/P6QA7iCRC", Priority: 50},
				},
			},
			ExpiresAt:  time.Now().Add(5 * time.Minute).UTC(),
			RenewURL:   "https://sub.example/lease/T/9/renew",
			ReleaseURL: "https://sub.example/lease/T/9/release",
		})
	}))
	defer server.Close()

	raw, err := json.Marshal(subscription.Server{
		ID: "n:flux", Name: "node mailru", Protocol: "flux", Transport: "mailru",
		Flux: &subscription.Flux{Mode: "l4", Lease: server.URL + "/lease/T"},
	})
	if err != nil {
		t.Fatal(err)
	}

	lease := FluxConnect(string(raw), "hw-1", true)
	if !lease.OK {
		t.Fatalf("FluxConnect: %+v", lease)
	}
	// The config has to be what the flux client accepts - the whole point of
	// the mobile integration is that this reaches startFluxClient, not Xray.
	if !IsFluxConfig(lease.Config) {
		t.Fatalf("the leased profile is not a flux profile the core would run:\n%s", lease.Config)
	}
	if IsXrayConfig(lease.Config) && !IsFluxConfig(lease.Config) {
		t.Fatal("a flux profile must not be mistaken for an Xray one")
	}

	var profile FluxProfile
	if err := json.Unmarshal([]byte(lease.Config), &profile); err != nil {
		t.Fatalf("flux profile does not parse: %v", err)
	}
	if profile.Secret == "" || len(profile.Carriers) != 1 || profile.Carriers[0].Type != "mailru" {
		t.Fatalf("the mail.ru carrier did not survive the round trip: %+v", profile)
	}
}

// TestImportedDedicatedFluxLinkIsStartable ties the panel's share link to the
// app: a self-contained flux link (a channel embedded, no lease) has to import
// into a profile the flux core runs. This is the "share a config with someone"
// path end to end.
func TestImportedDedicatedFluxLinkIsStartable(t *testing.T) {
	// The shape the panel's ChannelShareLink produces: a flux server with the
	// channel embedded rather than a lease URL.
	link, err := sharelink.Encode(sharelink.Bundle{
		Name: "node-2 mailru",
		Servers: []subscription.Server{{
			ID: "node:ch", Name: "node-2 mailru", Protocol: "flux", Transport: "mailru",
			Flux: &subscription.Flux{
				Mode: "l4",
				Channels: []subscription.Channel{{
					ID:      "ch-mailru",
					Secret:  "bdb8cc930318a8c61c1d6dee0fceb9354a268baba22ec6ae8b6858505cdac62b",
					Context: "https://cloud.mail.ru/public/wb2s/P6QA7iCRC",
					Carriers: []subscription.Carrier{
						{Type: "mailru", URL: "https://cloud.mail.ru/public/wb2s/P6QA7iCRC", Priority: 50},
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	result := ImportText(link)
	if !result.OK || result.ServerCount() != 1 {
		t.Fatalf("import result = %+v", result)
	}
	server := result.Server(0)
	if server == nil {
		t.Fatal("no server came back from the link")
	}
	// A dedicated channel needs no lease: the config is ready immediately.
	if server.NeedsLease() {
		t.Fatal("a dedicated flux link must not require a lease")
	}
	if !server.Usable() {
		t.Fatalf("the shared server is not usable: %s", server.Error)
	}
	if !IsFluxConfig(server.Config) {
		t.Fatalf("the shared config would not reach the flux core:\n%s", server.Config)
	}
	var profile FluxProfile
	if err := json.Unmarshal([]byte(server.Config), &profile); err != nil {
		t.Fatalf("flux config does not parse: %v", err)
	}
	if profile.Secret == "" || len(profile.Carriers) != 1 || profile.Carriers[0].Type != "mailru" {
		t.Fatalf("the mail.ru channel did not survive the share round trip: %+v", profile)
	}
}
