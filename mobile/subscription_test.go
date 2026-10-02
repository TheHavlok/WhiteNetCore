package mobile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

func TestDaysLeftRoundsUp(t *testing.T) {
	// Six hours left is "1 day", not "0 days": a subscription that still
	// works must not read as expired.
	if got := daysLeft(time.Now().Add(6 * time.Hour)); got != 1 {
		t.Fatalf("daysLeft = %d, want 1", got)
	}
	if got := daysLeft(time.Now().Add(-time.Hour)); got != 0 {
		t.Fatalf("an expired account should be 0, got %d", got)
	}
	if got := daysLeft(time.Now().Add(48 * time.Hour)); got != 2 {
		t.Fatalf("daysLeft = %d, want 2", got)
	}
}

func TestPooledFluxServerIsHandedBackWithItsLease(t *testing.T) {
	server := buildServer(subscription.Server{
		ID: "n:flux", Name: "flux", Protocol: "flux", Transport: "yandex",
		Flux: &subscription.Flux{Mode: "l4", Lease: "https://sub.example/lease/T"},
	})
	if !server.NeedsLease() || server.Usable() {
		t.Fatalf("server = %+v", server)
	}
	if server.LeaseURL != "https://sub.example/lease/T" {
		t.Fatalf("lease = %q", server.LeaseURL)
	}
	if server.RawJSON() == "" {
		t.Fatal("the raw server is needed to build a profile after leasing")
	}
}

func TestAnUnreadableServerIsSkippedNotFatal(t *testing.T) {
	// A protocol this app does not know must not take the rest of the
	// subscription with it.
	server := buildServer(subscription.Server{
		ID: "n:x", Name: "future", Protocol: "something-new",
		Address: "198.51.100.1", Port: 443,
	})
	if server.Usable() || server.Error == "" {
		t.Fatalf("server = %+v", server)
	}
}

func TestChainedServerCarriesBothHalves(t *testing.T) {
	server := buildServer(subscription.Server{
		ID: "n:dns", Name: "dns", Protocol: "wndns", Transport: "dns",
		Address: "198.51.100.2", Port: 53,
		Params: map[string]string{
			"domains": "t1.tun.example", "encryption_key": "4f3c2b1a09876543210fedcba9876543",
			"encryption_method": "2",
		},
		Chain: &subscription.Chain{Protocol: "vless", Transport: "raw",
			Params: map[string]string{"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"}},
	})
	if server.Config == "" || server.InnerConfig == "" {
		t.Fatalf("a DNS server needs both halves: %+v", server)
	}
	if !strings.Contains(server.InnerConfig, "dialerProxy") {
		t.Fatal("the inner core does not dial through the tunnel")
	}
}

func TestImportTextHandlesALinkAndRubbish(t *testing.T) {
	link, err := sharelink.Encode(sharelink.Bundle{
		Name: "DE-1",
		Servers: []subscription.Server{{
			ID: "n:v", Name: "DE-1", Protocol: "vless", Transport: "raw",
			Address: "198.51.100.1", Port: 443,
			Params: map[string]string{"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	result := ImportText(link)
	if !result.OK || result.ServerCount() != 1 {
		t.Fatalf("result = %+v", result)
	}
	if first := result.Server(0); first == nil || !first.Usable() {
		t.Fatalf("server = %+v", first)
	}
	if result.Server(5) != nil {
		t.Fatal("an out-of-range index must be nil, not a crash across the bridge")
	}

	if bad := ImportText("hello"); bad.OK || bad.Code == "" {
		t.Fatalf("result = %+v", bad)
	}
}

func TestFetchSubscriptionReportsTheDeviceLimitCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"device_limit","message":"this account allows 3 devices"}}`))
	}))
	defer server.Close()

	result := FetchSubscription(server.URL+"/sub/T", "hw-1", "iPhone", "ios", "2.0", true)
	if result.OK || result.Code != "device_limit" {
		t.Fatalf("result = %+v", result)
	}
}

func TestFetchSubscriptionBuildsEveryServer(t *testing.T) {
	expires := time.Now().Add(72 * time.Hour).UTC()
	doc := subscription.Response{
		Version: subscription.Version, IssuedAt: time.Now().UTC(), UpdateIntervalHours: 12,
		User: subscription.User{
			UUID: "u", Name: "pat", ExpiresAt: &expires,
			TrafficLimit: 1 << 30, DevicesLimit: 3, Status: subscription.StatusActive,
		},
		Servers: []subscription.Server{
			{ID: "n:v", Name: "VLESS", Protocol: "vless", Transport: "raw",
				Address: "198.51.100.1", Port: 443,
				Params: map[string]string{"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"}},
			{ID: "n:flux", Name: "flux", Protocol: "flux", Transport: "direct",
				Flux: &subscription.Flux{Mode: "l4", Lease: "https://sub.example/lease/T"}},
		},
		Branding: &subscription.Branding{AppName: "WhiteNetVPN", SupportURL: "https://t.me/x"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	result := FetchSubscription(server.URL+"/sub/T", "hw-1", "iPhone", "ios", "2.0", true)
	if !result.OK {
		t.Fatalf("result = %+v", result)
	}
	sub := result.Sub
	if sub.ServerCount() != 2 || sub.DaysLeft != 3 || sub.Blocked() {
		t.Fatalf("sub = %+v", sub)
	}
	if !sub.Server(0).Usable() || !sub.Server(1).NeedsLease() {
		t.Fatalf("servers = %+v / %+v", sub.Server(0), sub.Server(1))
	}
	if sub.AppName != "WhiteNetVPN" || sub.JSON == "" {
		t.Fatalf("branding or raw document missing: %+v", sub)
	}
}

func TestFluxConnectBuildsAProfileFromTheLease(t *testing.T) {
	var leased bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leased = true
		_ = json.NewEncoder(w).Encode(subscription.LeaseResponse{
			Channel: subscription.Channel{
				ID: "ch-7", Secret: "7b1f0c9d", Context: "https://cups.online/room/a",
				Carriers: []subscription.Carrier{{Type: "cupsonline", URL: "https://cups.online/room/a", Priority: 50}},
			},
			ExpiresAt:  time.Now().Add(5 * time.Minute).UTC(),
			RenewURL:   "https://sub.example/lease/T/9/renew",
			ReleaseURL: "https://sub.example/lease/T/9/release",
		})
	}))
	defer server.Close()

	raw, err := json.Marshal(subscription.Server{
		ID: "n:flux", Name: "flux", Protocol: "flux", Transport: "cupsonline",
		Flux: &subscription.Flux{Mode: "l4", Lease: server.URL + "/lease/T"},
	})
	if err != nil {
		t.Fatal(err)
	}

	lease := FluxConnect(string(raw), "hw-1", true)
	if !lease.OK {
		t.Fatalf("lease = %+v", lease)
	}
	if !leased {
		t.Fatal("no lease was taken")
	}
	if lease.Kind != "flux" {
		t.Fatalf("kind = %q, want flux", lease.Kind)
	}
	// The leased carrier has to be in the profile the app will start, in the
	// flux client's JSON shape.
	if !strings.Contains(lease.Config, `"type":"cupsonline"`) ||
		!strings.Contains(lease.Config, "whitenet_flux") {
		t.Fatalf("config does not carry the leased carrier:\n%s", lease.Config)
	}
	if lease.RenewURL == "" || lease.ReleaseURL == "" {
		t.Fatalf("the app cannot keep or return the channel: %+v", lease)
	}
}
