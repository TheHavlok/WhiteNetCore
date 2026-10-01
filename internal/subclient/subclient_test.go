package subclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

func testDocument() subscription.Response {
	expires := time.Now().Add(30 * 24 * time.Hour).UTC()
	return subscription.Response{
		Version:             subscription.Version,
		IssuedAt:            time.Now().UTC(),
		UpdateIntervalHours: 12,
		User: subscription.User{
			UUID: "4f1c9e0a-7b2d-4e8a-9c31-5a6b7c8d9e0f", Name: "pat",
			ExpiresAt: &expires, TrafficLimit: 1 << 30, DevicesLimit: 3, Status: "active",
		},
		Servers: []subscription.Server{{
			ID: "n:vless", Name: "DE-1", Protocol: "vless", Transport: "reality",
			Address: "198.51.100.10", Port: 443,
			Params: map[string]string{
				"uuid": "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
				"pbk":  "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
				"sni":  "www.microsoft.com", "sid": "6ba85179e30d4fc2",
			},
		}},
	}
}

// serve returns a client pointed at a test server. AllowInsecure is on
// because httptest speaks plain http; the https rule itself is tested
// separately.
func serve(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := New()
	client.AllowInsecure = true
	return client, server.URL
}

func TestFetchSendsTheDeviceHeaders(t *testing.T) {
	var got http.Header
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		if !strings.HasSuffix(r.URL.Path, "/json") {
			t.Errorf("asked for %q, want the /json form", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(testDocument())
	})

	doc, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{
		HWID: "hw-1", Model: "iPhone 17", Platform: "ios", AppVersion: "2.0",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if doc.User.Name != "pat" || len(doc.Servers) != 1 {
		t.Fatalf("document = %+v", doc.User)
	}
	// The device header is what the panel's device limit counts, so sending
	// it is the whole reason the app's fetch differs from a browser's.
	if got.Get("X-HWID") != "hw-1" || got.Get("X-Device-Model") != "iPhone 17" {
		t.Fatalf("headers = %v", got)
	}
	if got.Get("X-Platform") != "ios" || got.Get("X-App-Version") != "2.0" {
		t.Fatalf("headers = %v", got)
	}
}

func TestFetchKeepsAlreadyJSONPath(t *testing.T) {
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(r.URL.Path, "/json") != 1 {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(testDocument())
	})
	if _, err := client.Fetch(context.Background(), base+"/sub/TOKEN/json", Device{}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceLimitIsItsOwnCode(t *testing.T) {
	// The app has to tell this apart from a network failure: retrying never
	// helps, the user has to remove a device.
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"device_limit","message":"this account allows 3 devices"}}`))
	})
	_, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{HWID: "hw-9"})
	if ErrorCode(err) != CodeDeviceLimit {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
	if !strings.Contains(err.Error(), "3 devices") {
		t.Fatalf("the panel's own wording was lost: %v", err)
	}
}

func TestReissuedTokenIsNotFound(t *testing.T) {
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	_, err := client.Fetch(context.Background(), base+"/sub/GONE", Device{})
	if ErrorCode(err) != CodeNotFound {
		t.Fatalf("code = %q", ErrorCode(err))
	}
}

func TestACaptivePortalIsNotASubscription(t *testing.T) {
	// A hotel portal answers 200 with HTML for every request. Reporting that
	// as a bad document, not as an empty subscription, is what stops the app
	// from wiping its server list on a captive network.
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>sign in to continue</html>"))
	})
	_, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{})
	if ErrorCode(err) != CodeBadDocument {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
}

func TestNewerFormatAsksForAnUpdate(t *testing.T) {
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		doc := testDocument()
		doc.Version = subscription.Version + 1
		_ = json.NewEncoder(w).Encode(doc)
	})
	_, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{})
	if ErrorCode(err) != CodeVersion {
		t.Fatalf("code = %q", ErrorCode(err))
	}
}

func TestPlainHTTPIsRefusedByDefault(t *testing.T) {
	client := New()
	_, err := client.Fetch(context.Background(), "http://sub.example.com/sub/TOKEN", Device{})
	if ErrorCode(err) != CodeNotHTTPS {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
}

func TestBlockedUserStillGetsADocument(t *testing.T) {
	// An expired account is served with no servers on purpose, so the app can
	// say why instead of showing a network error.
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		doc := testDocument()
		doc.User.Status = subscription.StatusExpired
		doc.Servers = []subscription.Server{}
		_ = json.NewEncoder(w).Encode(doc)
	})
	doc, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{})
	if err != nil {
		t.Fatalf("an expired account must still parse: %v", err)
	}
	if doc.User.Status != subscription.StatusExpired || len(doc.Servers) != 0 {
		t.Fatalf("document = %+v", doc.User)
	}
}

func TestImportRecognisesEveryForm(t *testing.T) {
	bundle := sharelink.Bundle{
		Name:    "DE-1",
		Servers: testDocument().Servers,
		Sub:     "https://sub.example.com/sub/TOKEN",
	}
	shareLink, err := sharelink.Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	deepLink, err := sharelink.ImportLink("https://sub.example.com/sub/TOKEN")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		text       string
		wantSub    string
		wantBundle bool
	}{
		{"share link", shareLink, "https://sub.example.com/sub/TOKEN", true},
		{"deep link", deepLink, "https://sub.example.com/sub/TOKEN", false},
		{"bare url", "https://sub.example.com/sub/TOKEN", "https://sub.example.com/sub/TOKEN", false},
		// A link copied out of a chat arrives wrapped and padded.
		{"wrapped share link", "  " + shareLink[:20] + "\n" + shareLink[20:] + "  ",
			"https://sub.example.com/sub/TOKEN", true},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result, err := Import(test.text)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if result.SubURL != test.wantSub {
				t.Fatalf("sub = %q, want %q", result.SubURL, test.wantSub)
			}
			if (result.Bundle != nil) != test.wantBundle {
				t.Fatalf("bundle present = %t", result.Bundle != nil)
			}
		})
	}
}

func TestImportRejectsRubbishWithACode(t *testing.T) {
	for _, text := range []string{"", "hello", "vmess://notours"} {
		if _, err := Import(text); ErrorCode(err) != sharelink.CodeNotLink {
			t.Fatalf("%q: code = %q", text, ErrorCode(err))
		}
	}
}

func TestLeaseRoundTrip(t *testing.T) {
	var released bool
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/release"):
			released = true
			w.WriteHeader(http.StatusNoContent)
		default:
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(subscription.LeaseResponse{
				Channel: subscription.Channel{
					ID: "ch-7", Secret: "7b1f0c9d", Context: "ctx",
					Carriers: []subscription.Carrier{{Type: "yandex", URL: "https://x", Priority: 50}},
				},
				ExpiresAt:  time.Now().Add(5 * time.Minute).UTC(),
				RenewURL:   "/lease/T/9/renew",
				ReleaseURL: "/lease/T/9/release",
			})
		}
	})

	lease, err := client.Acquire(context.Background(), base+"/lease/T", Device{HWID: "hw-1"})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lease.Channel.ID != "ch-7" {
		t.Fatalf("channel = %+v", lease.Channel)
	}
	if _, err := client.Renew(context.Background(), base+"/lease/T/9/renew", Device{}); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := client.Release(context.Background(), base+"/lease/T/9/release", Device{}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !released {
		t.Fatal("the channel was never released")
	}
}

func TestEmptyLeaseIsRefused(t *testing.T) {
	// A lease with no carriers would build a profile that cannot connect, and
	// the failure would surface much later as a timeout.
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"channel":{"id":"ch-1"},"expires_at":"2026-01-01T00:00:00Z"}`))
	})
	_, err := client.Acquire(context.Background(), base+"/lease/T", Device{})
	if ErrorCode(err) != CodeBadDocument {
		t.Fatalf("code = %q", ErrorCode(err))
	}
}

func TestOversizedAnswerIsRefused(t *testing.T) {
	client, base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("x", 1<<16)
		for written := 0; written <= MaxDocument; written += len(chunk) {
			_, _ = w.Write([]byte(chunk))
		}
	})
	_, err := client.Fetch(context.Background(), base+"/sub/TOKEN", Device{})
	if ErrorCode(err) != CodeBadDocument {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
}
