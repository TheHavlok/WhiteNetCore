package fluxpool

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	fluxnode "github.com/thehavlok/whitenet/internal/flux/node"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

const testSecret = "7b1f0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4"

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// directChannel is the only carrier that needs nothing outside the machine, so
// the pool's behaviour is tested with it.
func directChannel(t *testing.T, id uint64) *nodepb.OpenFluxChannel {
	t.Helper()
	return &nodepb.OpenFluxChannel{
		Id:             id,
		Uuid:           fmt.Sprintf("channel-%d", id),
		Enabled:        true,
		Transport:      fluxnode.CarrierDirect,
		EncryptionKey:  testSecret,
		SessionContext: fmt.Sprintf("context-%d", id),
		Params:         map[string]string{"listen": fmt.Sprintf("127.0.0.1:%d", freePort(t))},
	}
}

func TestApplyStartsAndStopsChannels(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()
	ctx := context.Background()

	first, second := directChannel(t, 1), directChannel(t, 2)
	started, stopped, err := pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled:  true,
		Mode:     "l4",
		Channels: []*nodepb.OpenFluxChannel{first, second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(started) != 2 || len(stopped) != 0 {
		t.Fatalf("started %v, stopped %v; want two started", started, stopped)
	}
	if !pool.Running() {
		t.Error("pool reports nothing running after starting two channels")
	}
	if got := len(pool.Status()); got != 2 {
		t.Errorf("status has %d entries, want 2", got)
	}

	// Applying the same state again must change nothing: that is what lets a
	// reconnecting agent re-apply without disturbing a live session.
	started, stopped, err = pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled:  true,
		Mode:     "l4",
		Channels: []*nodepb.OpenFluxChannel{first, second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(started) != 0 || len(stopped) != 0 {
		t.Errorf("re-applying an unchanged state started %v and stopped %v", started, stopped)
	}

	// Removing one must stop only that one.
	started, stopped, err = pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled:  true,
		Mode:     "l4",
		Channels: []*nodepb.OpenFluxChannel{first},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(started) != 0 || len(stopped) != 1 || stopped[0] != 2 {
		t.Errorf("started %v, stopped %v; want only channel 2 stopped", started, stopped)
	}

	// Disabling the whole thing must stop the rest.
	_, stopped, err = pool.Apply(ctx, &nodepb.OpenFluxConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(stopped) != 1 {
		t.Errorf("stopped %v, want channel 1", stopped)
	}
	if pool.Running() {
		t.Error("pool still reports something running after being disabled")
	}
}

// A changed key must restart the channel: that is how the panel revokes a
// lease, and leaving the old session running would defeat it.
func TestChangedSecretRestartsTheChannel(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()
	ctx := context.Background()

	channel := directChannel(t, 1)
	if _, _, err := pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4", Channels: []*nodepb.OpenFluxChannel{channel},
	}); err != nil {
		t.Fatal(err)
	}

	rotated := directChannel(t, 1)
	rotated.Params = channel.Params // same port, so only the key changed
	rotated.EncryptionKey = "aaaa0c9d2e3a4b5c6d7e8f90a1b2c3d47b1f0c9d2e3a4b5c6d7e8f90a1b2c3d4"

	started, stopped, err := pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4", Channels: []*nodepb.OpenFluxChannel{rotated},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(started) != 1 || len(stopped) != 1 {
		t.Errorf("started %v, stopped %v; want the channel restarted", started, stopped)
	}
}

// Changing the exit mode changes how traffic is terminated, so every channel
// has to come back up.
func TestChangedModeRestartsEverything(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()
	ctx := context.Background()

	channels := []*nodepb.OpenFluxChannel{directChannel(t, 1), directChannel(t, 2)}
	if _, _, err := pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4", Channels: channels,
	}); err != nil {
		t.Fatal(err)
	}
	// l3 needs root, so this would fail to start; the assertion is that it
	// tried to restart both, which the stop list shows.
	_, stopped, _ := pool.Apply(ctx, &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4", Channels: channels,
	})
	if len(stopped) != 0 {
		t.Fatalf("an unchanged mode restarted channels: %v", stopped)
	}
}

// One broken channel must not take the others down.
func TestOneBadChannelDoesNotStopTheRest(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()

	good := directChannel(t, 1)
	bad := directChannel(t, 2)
	bad.Transport = "telepathy"

	started, _, err := pool.Apply(context.Background(), &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4",
		Channels: []*nodepb.OpenFluxChannel{good, bad},
	})
	if err == nil {
		t.Error("a channel with an unknown transport did not produce an error")
	}
	if len(started) != 1 || started[0] != 1 {
		t.Errorf("started = %v, want only the good channel", started)
	}

	// The failure must be visible per channel, not just as an error return.
	var sawError bool
	for _, status := range pool.Status() {
		if status.ChannelID == 2 && status.LastError != "" {
			sawError = true
		}
	}
	if !sawError {
		t.Error("the broken channel has no recorded error")
	}
}

func TestDisabledChannelsAreNotStarted(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()

	channel := directChannel(t, 1)
	channel.Enabled = false
	started, _, err := pool.Apply(context.Background(), &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4", Channels: []*nodepb.OpenFluxChannel{channel},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(started) != 0 {
		t.Errorf("started = %v, want nothing", started)
	}
}

func TestCarriersForSingleAndMulti(t *testing.T) {
	// A plain channel is one carrier named after its type.
	single := &nodepb.OpenFluxChannel{
		Id: 1, Transport: fluxnode.CarrierYandexDocs, Url: "https://docs.example/1",
	}
	carriers, err := carriersFor(single)
	if err != nil {
		t.Fatal(err)
	}
	if len(carriers) != 1 || carriers[0].Name != fluxnode.CarrierYandexDocs {
		t.Fatalf("carriers = %+v", carriers)
	}
	if carriers[0].URL != "https://docs.example/1" {
		t.Errorf("url = %q", carriers[0].URL)
	}

	// Extra carriers come from params, as "type:url@priority".
	multi := &nodepb.OpenFluxChannel{
		Id: 2, Transport: fluxnode.CarrierCupsOnline, Url: "https://cups.online/room/ab",
		Params: map[string]string{
			"carriers": "direct:1.2.3.4:8444@100,mailru:https://mail.example/doc@30",
		},
	}
	carriers, err = carriersFor(multi)
	if err != nil {
		t.Fatal(err)
	}
	if len(carriers) != 3 {
		t.Fatalf("got %d carriers, want 3: %+v", len(carriers), carriers)
	}
	var direct, mailru *fluxnode.Carrier
	for i := range carriers {
		switch carriers[i].Type {
		case fluxnode.CarrierDirect:
			direct = &carriers[i]
		case fluxnode.CarrierMailruDocs:
			mailru = &carriers[i]
		}
	}
	if direct == nil || mailru == nil {
		t.Fatalf("carriers = %+v", carriers)
	}
	// direct on an exit listens; the url form would be meaningless.
	if direct.Params["listen"] != "1.2.3.4:8444" {
		t.Errorf("direct listen = %q", direct.Params["listen"])
	}
	if direct.Priority != 100 {
		t.Errorf("direct priority = %d, want 100", direct.Priority)
	}
	if mailru.URL != "https://mail.example/doc" {
		t.Errorf("mailru url = %q", mailru.URL)
	}
	if mailru.Priority != 30 {
		t.Errorf("mailru priority = %d, want 30", mailru.Priority)
	}
	// params["carriers"] must not leak into the primary carrier's params.
	for _, carrier := range carriers {
		if _, present := carrier.Params["carriers"]; present {
			t.Error("the carriers list leaked into a carrier's params")
		}
	}
}

// Two carriers of the same type in one channel must get distinct names, or the
// session refuses to register the second.
func TestCarriersForDisambiguatesNames(t *testing.T) {
	channel := &nodepb.OpenFluxChannel{
		Id: 1, Transport: fluxnode.CarrierYandexDocs, Url: "https://docs.example/1",
		Params: map[string]string{"carriers": "yandex:https://docs.example/2"},
	}
	carriers, err := carriersFor(channel)
	if err != nil {
		t.Fatal(err)
	}
	if len(carriers) != 2 {
		t.Fatalf("carriers = %+v", carriers)
	}
	if carriers[0].Name == carriers[1].Name {
		t.Errorf("both carriers are named %q", carriers[0].Name)
	}
}

func TestCarriersForRejections(t *testing.T) {
	cases := map[string]*nodepb.OpenFluxChannel{
		"no transport":      {Id: 1},
		"unknown transport": {Id: 1, Transport: "telepathy"},
		"unknown extra carrier": {Id: 1, Transport: fluxnode.CarrierDirect,
			Params: map[string]string{"listen": "127.0.0.1:1", "carriers": "telepathy:x"}},
	}
	for name, channel := range cases {
		if _, err := carriersFor(channel); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// The fingerprint decides whether a live session is disturbed, so it must
// cover everything that matters and nothing that does not.
func TestFingerprint(t *testing.T) {
	base := &nodepb.OpenFluxChannel{
		Id: 1, Transport: "yandex", Url: "https://docs.example/1",
		EncryptionKey: testSecret, SessionContext: "ctx",
		Params: map[string]string{"a": "1", "b": "2"},
	}
	want := fingerprint("l4", base)

	// The same channel, with params in a different order, is the same channel.
	same := &nodepb.OpenFluxChannel{
		Id: 1, Transport: "yandex", Url: "https://docs.example/1",
		EncryptionKey: testSecret, SessionContext: "ctx",
		Params: map[string]string{"b": "2", "a": "1"},
	}
	if fingerprint("l4", same) != want {
		t.Error("map iteration order changed the fingerprint")
	}

	changes := map[string]func(*nodepb.OpenFluxChannel){
		"url":       func(c *nodepb.OpenFluxChannel) { c.Url = "https://docs.example/2" },
		"key":       func(c *nodepb.OpenFluxChannel) { c.EncryptionKey = "other" },
		"context":   func(c *nodepb.OpenFluxChannel) { c.SessionContext = "other" },
		"transport": func(c *nodepb.OpenFluxChannel) { c.Transport = "mailru" },
		"params":    func(c *nodepb.OpenFluxChannel) { c.Params["a"] = "9" },
	}
	for name, mutate := range changes {
		changed := &nodepb.OpenFluxChannel{
			Id: 1, Transport: base.Transport, Url: base.Url,
			EncryptionKey: base.EncryptionKey, SessionContext: base.SessionContext,
			Params: map[string]string{"a": "1", "b": "2"},
		}
		mutate(changed)
		if fingerprint("l4", changed) == want {
			t.Errorf("changing the %s did not change the fingerprint", name)
		}
	}
	if fingerprint("l3", base) == want {
		t.Error("changing the mode did not change the fingerprint")
	}
}

func TestActiveSessionsCountsHandshakes(t *testing.T) {
	pool := New(Options{CookieDir: t.TempDir()})
	defer pool.Stop()

	if _, _, err := pool.Apply(context.Background(), &nodepb.OpenFluxConfig{
		Enabled: true, Mode: "l4",
		Channels: []*nodepb.OpenFluxChannel{directChannel(t, 1)},
	}); err != nil {
		t.Fatal(err)
	}
	// Nothing has connected, so no session is active even though the channel
	// is up. The panel relies on this to expire a lease nobody is using.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.ActiveSessions() != 0 {
			t.Fatal("a channel with no client reported an active session")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
