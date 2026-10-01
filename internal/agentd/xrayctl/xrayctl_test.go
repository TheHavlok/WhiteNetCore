package xrayctl

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/thehavlok/whitenet/internal/agentd/xraycfg"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

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

func user(id uint64, uuid string) *nodepb.User {
	return &nodepb.User{
		Id:         id,
		Uuid:       uuid,
		Email:      xraycfg.UserEmail(id, uuid),
		VlessUuid:  uuid,
		Password:   "password-" + uuid[:8],
		SsPassword: "c2hhZG93c29ja3NVc2VyS2V5MTIzNA==",
	}
}

// startXray brings up a real xray-core in this process from a generated
// configuration. Testing the API against the real thing is the only way to
// know the account types and the stat names are right.
func startXray(t *testing.T, inbounds []*nodepb.Inbound, users []*nodepb.User) string {
	t.Helper()

	apiAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	raw, err := xraycfg.Generate(&nodepb.NodeState{Inbounds: inbounds, Users: users}, xraycfg.Options{
		APIAddress: apiAddr,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("generated config did not parse: %v\n%s", err, raw)
	}
	built, err := decoded.Build()
	if err != nil {
		t.Fatalf("generated config did not build: %v\n%s", err, raw)
	}
	instance, err := core.New(built)
	if err != nil {
		t.Fatalf("xray-core: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("xray-core start: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return apiAddr
}

func vlessInbound(port int) *nodepb.Inbound {
	return &nodepb.Inbound{
		Tag:           "vless-test",
		Core:          nodepb.Core_CORE_XRAY,
		Protocol:      nodepb.Protocol_PROTOCOL_VLESS,
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    uint32(port),
		Params:        map[string]string{"network": "raw"},
	}
}

func TestAddAndRemoveUserOnLiveXray(t *testing.T) {
	first := user(1, "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0")
	apiAddr := startXray(t, []*nodepb.Inbound{vlessInbound(freePort(t))}, []*nodepb.User{first})

	client := New(apiAddr)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.WaitReady(ctx, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// The inbound from the configuration must be visible through the API, or
	// the agent cannot tell what Xray is actually serving.
	tags, err := client.ListInboundTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(tags, "vless-test") {
		t.Fatalf("inbound tags = %v, want vless-test", tags)
	}

	emails, err := client.InboundUserEmails(ctx, "vless-test")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(emails, first.GetEmail()) {
		t.Fatalf("users = %v, want the configured user %s", emails, first.GetEmail())
	}

	// Adding at runtime is the whole point: no restart.
	second := user(2, "11111111-2222-3333-4444-555555555555")
	if err := client.AddUser(ctx, vlessInbound(0), second); err != nil {
		t.Fatal(err)
	}
	emails, err = client.InboundUserEmails(ctx, "vless-test")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(emails, second.GetEmail()) {
		t.Fatalf("after add, users = %v", emails)
	}

	// Adding the same user again must not be an error: the agent reconciles
	// state instead of tracking what it already did.
	if err := client.AddUser(ctx, vlessInbound(0), second); err != nil {
		t.Errorf("adding an existing user failed: %v", err)
	}

	if err := client.RemoveUser(ctx, "vless-test", second.GetEmail()); err != nil {
		t.Fatal(err)
	}
	emails, err = client.InboundUserEmails(ctx, "vless-test")
	if err != nil {
		t.Fatal(err)
	}
	if contains(emails, second.GetEmail()) {
		t.Fatalf("after remove, users = %v", emails)
	}

	// Removing someone who is not there must not be an error either.
	if err := client.RemoveUser(ctx, "vless-test", second.GetEmail()); err != nil {
		t.Errorf("removing an absent user failed: %v", err)
	}
}

// Every protocol's account type must be one Xray accepts on a live inbound.
// A wrong type here means a user is "added" and still cannot connect.
func TestAddUserForEveryProtocol(t *testing.T) {
	cert, key := testCertificate(t)
	u := user(7, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

	cases := []struct {
		name    string
		inbound *nodepb.Inbound
	}{
		{"vless", vlessInbound(freePort(t))},
		{"vmess", &nodepb.Inbound{
			Tag: "vmess-test", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VMESS,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: uint32(freePort(t)),
			Params: map[string]string{"network": "raw"},
		}},
		{"trojan", &nodepb.Inbound{
			Tag: "trojan-test", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_TROJAN,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: uint32(freePort(t)),
			Params:  map[string]string{"network": "raw", "security": "tls"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		}},
		{"shadowsocks", &nodepb.Inbound{
			Tag: "ss-test", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: uint32(freePort(t)),
			Params:  map[string]string{"method": "aes-256-gcm"},
			Secrets: map[string]string{"password": "fallback-key-nobody-has"},
		}},
		{"shadowsocks2022", &nodepb.Inbound{
			Tag: "ss2022-test", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: uint32(freePort(t)),
			Params:  map[string]string{"method": "2022-blake3-aes-128-gcm"},
			Secrets: map[string]string{"password": "qxGZVPkTfTCCRWg6cNFVMg=="},
		}},
		{"hysteria2", &nodepb.Inbound{
			Tag: "hy2-test", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_HYSTERIA2,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: uint32(freePort(t)),
			Params:  map[string]string{"security": "tls", "sni": "hy2.example"},
			Secrets: map[string]string{"certificate": cert, "key": key},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Start with no users, so the add is what puts the first one in.
			apiAddr := startXray(t, []*nodepb.Inbound{tc.inbound}, nil)
			client := New(apiAddr)
			defer func() { _ = client.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := client.WaitReady(ctx, 100*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if err := client.AddUser(ctx, tc.inbound, u); err != nil {
				t.Fatalf("add user: %v", err)
			}
			emails, err := client.InboundUserEmails(ctx, tc.inbound.GetTag())
			if err != nil {
				t.Fatal(err)
			}
			if !contains(emails, u.GetEmail()) {
				t.Fatalf("users = %v, want %s", emails, u.GetEmail())
			}
			if err := client.RemoveUser(ctx, tc.inbound.GetTag(), u.GetEmail()); err != nil {
				t.Fatalf("remove user: %v", err)
			}
		})
	}
}

func TestReadTrafficAndOnlineUsers(t *testing.T) {
	u := user(1, "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0")
	apiAddr := startXray(t, []*nodepb.Inbound{vlessInbound(freePort(t))}, []*nodepb.User{u})

	client := New(apiAddr)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.WaitReady(ctx, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// No traffic yet, so the maps are empty rather than missing. The call
	// itself working is what matters: a wrong stat name pattern would error
	// or silently return nothing forever.
	counters, err := client.ReadTraffic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counters.Users == nil || counters.Inbounds == nil {
		t.Fatal("ReadTraffic returned nil maps")
	}

	online, err := client.OnlineUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(online) != 0 {
		t.Errorf("online users = %v, want none on a fresh instance", online)
	}
}

// Against nothing at all, every call must report that Xray is not running
// rather than hanging or returning an empty success.
func TestCallsFailWhenXrayIsDown(t *testing.T) {
	client := New(net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))))
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.ListInboundTags(ctx); err == nil {
		t.Error("ListInboundTags succeeded against a dead port")
	}
	if err := client.Ping(ctx); err == nil {
		t.Error("Ping succeeded against a dead port")
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer waitCancel()
	if err := client.WaitReady(waitCtx, 100*time.Millisecond); err == nil {
		t.Error("WaitReady succeeded against a dead port")
	}
}

func TestParseStatName(t *testing.T) {
	cases := []struct {
		name                     string
		kind, subject, direction string
		ok                       bool
	}{
		{"user>>>1.9f8e7d6c@whitenet>>>traffic>>>uplink", "user", "1.9f8e7d6c@whitenet", "uplink", true},
		{"user>>>1.9f8e7d6c@whitenet>>>traffic>>>downlink", "user", "1.9f8e7d6c@whitenet", "downlink", true},
		{"inbound>>>vless-443>>>traffic>>>uplink", "inbound", "vless-443", "uplink", true},
		{"outbound>>>direct>>>traffic>>>downlink", "outbound", "direct", "downlink", true},
		{"user>>>someone>>>online", "", "", "", false},
		{"nonsense", "", "", "", false},
		{"user>>>someone>>>traffic>>>sideways", "", "", "", false},
	}
	for _, tc := range cases {
		kind, subject, direction, ok := parseStatName(tc.name)
		if ok != tc.ok || kind != tc.kind || subject != tc.subject || direction != tc.direction {
			t.Errorf("parseStatName(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				tc.name, kind, subject, direction, ok, tc.kind, tc.subject, tc.direction, tc.ok)
		}
	}
}

func TestSupportsUsers(t *testing.T) {
	for _, p := range []nodepb.Protocol{
		nodepb.Protocol_PROTOCOL_VLESS, nodepb.Protocol_PROTOCOL_VMESS,
		nodepb.Protocol_PROTOCOL_TROJAN, nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
		nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022, nodepb.Protocol_PROTOCOL_HYSTERIA2,
	} {
		if !SupportsUsers(p) {
			t.Errorf("%s should support runtime users", p)
		}
	}
	// The DNS tunnel has no accounts, which is the whole reason it chains
	// into Xray; trying to add a user to it would be a bug.
	if SupportsUsers(nodepb.Protocol_PROTOCOL_WNDNS) {
		t.Error("wndns should not claim to support runtime users")
	}
	if SupportsUsers(nodepb.Protocol_PROTOCOL_UNSPECIFIED) {
		t.Error("an unspecified protocol should not claim to support runtime users")
	}
}

func TestBuildAccountRejectsMissingCredentials(t *testing.T) {
	empty := &nodepb.User{Id: 1, Email: "e@whitenet"}
	for _, p := range []nodepb.Protocol{
		nodepb.Protocol_PROTOCOL_VLESS, nodepb.Protocol_PROTOCOL_VMESS,
		nodepb.Protocol_PROTOCOL_TROJAN, nodepb.Protocol_PROTOCOL_HYSTERIA2,
		nodepb.Protocol_PROTOCOL_SHADOWSOCKS, nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
	} {
		in := &nodepb.Inbound{Tag: "t", Protocol: p, Params: map[string]string{"method": "aes-256-gcm"}}
		if _, err := buildAccount(in, empty); err == nil {
			t.Errorf("%s accepted a user with no credentials", p)
		}
	}
	wndns := &nodepb.Inbound{Tag: "t", Protocol: nodepb.Protocol_PROTOCOL_WNDNS}
	if _, err := buildAccount(wndns, user(1, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")); err == nil {
		t.Error("wndns produced an xray account")
	}
	// A legacy Shadowsocks account needs a cipher it can name.
	badMethod := &nodepb.Inbound{Tag: "t", Protocol: nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
		Params: map[string]string{"method": "rot13"}}
	if _, err := buildAccount(badMethod, user(1, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")); err == nil {
		t.Error("an unsupported shadowsocks method was accepted")
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
