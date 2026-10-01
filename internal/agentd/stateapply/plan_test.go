package stateapply

import (
	"testing"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

func user(id uint64, uuid string) *nodepb.User {
	return &nodepb.User{
		Id:         id,
		Uuid:       uuid,
		Email:      uuid[:8] + "@whitenet",
		VlessUuid:  uuid,
		Password:   "pw-" + uuid[:4],
		SsPassword: "ss-" + uuid[:4],
	}
}

func vless(tag string, port uint32) *nodepb.Inbound {
	return &nodepb.Inbound{
		Tag: tag, Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
		Enabled: true, ListenPort: port,
		Params: map[string]string{"network": "raw", "security": "none"},
	}
}

func state(inbounds []*nodepb.Inbound, users []*nodepb.User) *nodepb.NodeState {
	return &nodepb.NodeState{Inbounds: inbounds, Users: users}
}

// Adding a user must never restart Xray. This is the single most important
// property here: a restart drops every live connection on the node.
func TestAddingAUserDoesNotRestartXray(t *testing.T) {
	inbounds := []*nodepb.Inbound{vless("vless-443", 443)}
	a := user(1, "11111111-2222-3333-4444-555555555555")
	b := user(2, "99999999-8888-7777-6666-555555555555")

	plan := PlanFor(state(inbounds, []*nodepb.User{a}), state(inbounds, []*nodepb.User{a, b}))
	if plan.RestartXray {
		t.Fatal("adding a user asked for a restart")
	}
	if len(plan.AddUsers["vless-443"]) != 1 || plan.AddUsers["vless-443"][0].GetId() != 2 {
		t.Errorf("AddUsers = %+v", plan.AddUsers)
	}
	if len(plan.RemoveUsers) != 0 {
		t.Errorf("RemoveUsers = %+v", plan.RemoveUsers)
	}
	if plan.Reason != "users added" {
		t.Errorf("reason = %q", plan.Reason)
	}
}

func TestRemovingAUserDoesNotRestartXray(t *testing.T) {
	inbounds := []*nodepb.Inbound{vless("vless-443", 443)}
	a := user(1, "11111111-2222-3333-4444-555555555555")
	b := user(2, "99999999-8888-7777-6666-555555555555")

	plan := PlanFor(state(inbounds, []*nodepb.User{a, b}), state(inbounds, []*nodepb.User{a}))
	if plan.RestartXray {
		t.Fatal("removing a user asked for a restart")
	}
	if got := plan.RemoveUsers["vless-443"]; len(got) != 1 || got[0] != b.GetEmail() {
		t.Errorf("RemoveUsers = %+v, want %s", plan.RemoveUsers, b.GetEmail())
	}
}

// Xray's API has no update operation, so changed credentials are a remove and
// an add - and the remove has to use the *old* email, or the stale account
// stays behind and keeps working.
func TestChangedCredentialsBecomeARemoveAndAnAdd(t *testing.T) {
	inbounds := []*nodepb.Inbound{vless("vless-443", 443)}
	before := user(1, "11111111-2222-3333-4444-555555555555")
	after := user(1, "11111111-2222-3333-4444-555555555555")
	after.VlessUuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	plan := PlanFor(state(inbounds, []*nodepb.User{before}), state(inbounds, []*nodepb.User{after}))
	if plan.RestartXray {
		t.Fatal("a credential change asked for a restart")
	}
	if got := plan.RemoveUsers["vless-443"]; len(got) != 1 || got[0] != before.GetEmail() {
		t.Errorf("RemoveUsers = %v, want the old email %s", got, before.GetEmail())
	}
	if got := plan.AddUsers["vless-443"]; len(got) != 1 || got[0].GetVlessUuid() != after.GetVlessUuid() {
		t.Errorf("AddUsers = %+v", got)
	}

	// A changed email is the same story, and the old one is what gets removed.
	renamed := user(1, "11111111-2222-3333-4444-555555555555")
	renamed.Email = "renamed@whitenet"
	plan = PlanFor(state(inbounds, []*nodepb.User{before}), state(inbounds, []*nodepb.User{renamed}))
	if got := plan.RemoveUsers["vless-443"]; len(got) != 1 || got[0] != before.GetEmail() {
		t.Errorf("RemoveUsers = %v, want the old email", got)
	}
}

// Changing anything about an inbound is a restart: Xray reads those at startup.
func TestInboundChangesRestartXray(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	before := state([]*nodepb.Inbound{vless("vless-443", 443)}, []*nodepb.User{a})

	cases := map[string]*nodepb.NodeState{
		"port changed":    state([]*nodepb.Inbound{vless("vless-443", 8443)}, []*nodepb.User{a}),
		"inbound added":   state([]*nodepb.Inbound{vless("vless-443", 443), vless("vless-8443", 8443)}, []*nodepb.User{a}),
		"inbound removed": state(nil, []*nodepb.User{a}),
		"tag renamed":     state([]*nodepb.Inbound{vless("vless-new", 443)}, []*nodepb.User{a}),
	}
	for name, next := range cases {
		if plan := PlanFor(before, next); !plan.RestartXray {
			t.Errorf("%s: no restart planned", name)
		}
	}

	// A changed parameter counts too.
	changed := vless("vless-443", 443)
	changed.Params["security"] = "reality"
	if plan := PlanFor(before, state([]*nodepb.Inbound{changed}, []*nodepb.User{a})); !plan.RestartXray {
		t.Error("a changed parameter did not plan a restart")
	}

	// And so does a changed secret: a rotated Reality key must take effect.
	rotated := vless("vless-443", 443)
	rotated.Secrets = map[string]string{"private_key": "new-key"}
	if plan := PlanFor(before, state([]*nodepb.Inbound{rotated}, []*nodepb.User{a})); !plan.RestartXray {
		t.Error("a changed secret did not plan a restart")
	}
}

// When a restart is already happening, the user lists must be empty: the
// restart applies them from the configuration file, and sending them again
// through the API would be work for nothing.
func TestRestartSupersedesUserDeltas(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	b := user(2, "99999999-8888-7777-6666-555555555555")
	before := state([]*nodepb.Inbound{vless("vless-443", 443)}, []*nodepb.User{a})
	next := state([]*nodepb.Inbound{vless("vless-443", 8443)}, []*nodepb.User{a, b})

	plan := PlanFor(before, next)
	if !plan.RestartXray {
		t.Fatal("expected a restart")
	}
	if len(plan.AddUsers) != 0 || len(plan.RemoveUsers) != 0 {
		t.Errorf("user deltas alongside a restart: add=%v remove=%v", plan.AddUsers, plan.RemoveUsers)
	}
}

// An identical state must plan nothing at all. A reconnecting agent re-applies
// what it already has, and that has to be free.
func TestNoChangePlansNothing(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	s := state([]*nodepb.Inbound{vless("vless-443", 443)}, []*nodepb.User{a})
	plan := PlanFor(s, s)
	if !plan.Empty() {
		t.Fatalf("an identical state planned %+v", plan)
	}
	if plan.Reason != "no change" {
		t.Errorf("reason = %q", plan.Reason)
	}

	// Map iteration order must not make two identical states look different.
	same := state([]*nodepb.Inbound{vless("vless-443", 443)}, []*nodepb.User{user(1, "11111111-2222-3333-4444-555555555555")})
	for i := 0; i < 50; i++ {
		if !PlanFor(s, same).Empty() {
			t.Fatal("two identical states compared as different")
		}
	}
}

// A node that has just started has no current state, so everything starts.
func TestFirstStateStartsEverything(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	plan := PlanFor(nil, state([]*nodepb.Inbound{vless("vless-443", 443)}, []*nodepb.User{a}))
	if !plan.RestartXray {
		t.Error("the first state did not start xray")
	}
	if len(plan.AddUsers) != 0 {
		t.Error("the first state planned user deltas as well as a start")
	}

	// A first state with no Xray inbounds must not start Xray for nothing.
	plan = PlanFor(nil, state(nil, []*nodepb.User{a}))
	if plan.RestartXray {
		t.Error("a node with no xray inbounds started xray anyway")
	}
}

func dnsState(port uint32, targetPort uint32, domains string) *nodepb.NodeState {
	return state([]*nodepb.Inbound{
		{
			Tag: "wndns", Core: nodepb.Core_CORE_WNDNS, Protocol: nodepb.Protocol_PROTOCOL_WNDNS,
			Enabled: true, ListenPort: port, ForwardToTag: "vless-local",
			Params:  map[string]string{"domains": domains},
			Secrets: map[string]string{"encryption_key": "k"},
		},
		{
			Tag: "vless-local", Core: nodepb.Core_CORE_XRAY, Protocol: nodepb.Protocol_PROTOCOL_VLESS,
			Enabled: true, ListenAddress: "127.0.0.1", ListenPort: targetPort,
			Params: map[string]string{"network": "raw"},
		},
	}, []*nodepb.User{user(1, "11111111-2222-3333-4444-555555555555")})
}

// The tunnel has no runtime API, so any change to it is a restart.
func TestDNSTunnelChangesRestartIt(t *testing.T) {
	before := dnsState(53, 21080, "t1.example")

	if plan := PlanFor(before, before); plan.RestartWNDNS {
		t.Error("an unchanged tunnel planned a restart")
	}
	if plan := PlanFor(before, dnsState(53, 21080, "t1.example,t2.example")); !plan.RestartWNDNS {
		t.Error("a changed domain list did not plan a restart")
	}
	if plan := PlanFor(before, dnsState(5353, 21080, "t1.example")); !plan.RestartWNDNS {
		t.Error("a changed port did not plan a restart")
	}
}

// The tunnel forwards into an Xray inbound by port. If that port moves, the
// tunnel is pointing at nothing and has to follow.
func TestTunnelFollowsItsForwardTarget(t *testing.T) {
	before := dnsState(53, 21080, "t1.example")
	plan := PlanFor(before, dnsState(53, 21081, "t1.example"))
	if !plan.RestartXray {
		t.Error("the target's port changed without restarting xray")
	}
	if !plan.RestartWNDNS {
		t.Error("the tunnel did not follow its forward target's port")
	}
}

func TestTunnelRemovalStopsIt(t *testing.T) {
	before := dnsState(53, 21080, "t1.example")
	after := state([]*nodepb.Inbound{vless("vless-local", 21080)}, before.GetUsers())

	plan := PlanFor(before, after)
	if !plan.StopWNDNS {
		t.Error("removing the tunnel did not stop it")
	}
	if plan.RestartWNDNS {
		t.Error("a removed tunnel was also asked to restart")
	}
}

func fluxState(channels ...*nodepb.OpenFluxChannel) *nodepb.NodeState {
	s := state([]*nodepb.Inbound{vless("vless-443", 443)}, nil)
	s.Openflux = &nodepb.OpenFluxConfig{Enabled: true, Mode: "l4", Channels: channels}
	return s
}

func TestFluxChangesArePlanned(t *testing.T) {
	first := &nodepb.OpenFluxChannel{Id: 1, Enabled: true, Transport: "yandex",
		Url: "https://docs.example/1", EncryptionKey: "k1"}
	second := &nodepb.OpenFluxChannel{Id: 2, Enabled: true, Transport: "mailru",
		Url: "https://mail.example/1", EncryptionKey: "k2"}

	before := fluxState(first)
	if plan := PlanFor(before, fluxState(first)); plan.ApplyFlux {
		t.Error("an unchanged flux block was planned")
	}
	if plan := PlanFor(before, fluxState(first, second)); !plan.ApplyFlux {
		t.Error("an added channel was not planned")
	}

	rotated := &nodepb.OpenFluxChannel{Id: 1, Enabled: true, Transport: "yandex",
		Url: "https://docs.example/1", EncryptionKey: "rotated"}
	if plan := PlanFor(before, fluxState(rotated)); !plan.ApplyFlux {
		t.Error("a rotated key was not planned")
	}

	// Channel order must not look like a change.
	for i := 0; i < 20; i++ {
		if PlanFor(fluxState(first, second), fluxState(second, first)).ApplyFlux {
			t.Fatal("channel order looked like a change")
		}
	}

	// Turning it off is a change.
	off := fluxState(first)
	off.Openflux.Enabled = false
	if plan := PlanFor(before, off); !plan.ApplyFlux {
		t.Error("disabling flux was not planned")
	}
}

// A protocol with no runtime user support must not get user deltas: the DNS
// tunnel authenticates through the inbound it chains into, and flux has no
// users at all.
func TestUserDeltasOnlyGoToInboundsThatSupportThem(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	b := user(2, "99999999-8888-7777-6666-555555555555")
	inbounds := []*nodepb.Inbound{
		vless("vless-443", 443),
		{Tag: "wndns", Core: nodepb.Core_CORE_WNDNS, Protocol: nodepb.Protocol_PROTOCOL_WNDNS,
			Enabled: true, ListenPort: 53, ForwardToTag: "vless-443",
			Params: map[string]string{"domains": "t.example"}},
	}
	plan := PlanFor(state(inbounds, []*nodepb.User{a}), state(inbounds, []*nodepb.User{a, b}))
	if _, present := plan.AddUsers["wndns"]; present {
		t.Error("a user delta was planned for the dns tunnel")
	}
	if len(plan.AddUsers["vless-443"]) != 1 {
		t.Errorf("AddUsers = %+v", plan.AddUsers)
	}
}

// A disabled inbound is not served, so changing one must not restart anything.
func TestDisabledInboundsAreIgnored(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	disabled := vless("vless-8443", 8443)
	disabled.Enabled = false
	before := state([]*nodepb.Inbound{vless("vless-443", 443), disabled}, []*nodepb.User{a})

	changedDisabled := vless("vless-8443", 9443)
	changedDisabled.Enabled = false
	after := state([]*nodepb.Inbound{vless("vless-443", 443), changedDisabled}, []*nodepb.User{a})

	if plan := PlanFor(before, after); !plan.Empty() {
		t.Errorf("changing a disabled inbound planned %+v", plan)
	}

	// Enabling it, on the other hand, is a restart.
	enabled := vless("vless-8443", 8443)
	after = state([]*nodepb.Inbound{vless("vless-443", 443), enabled}, []*nodepb.User{a})
	if plan := PlanFor(before, after); !plan.RestartXray {
		t.Error("enabling an inbound did not plan a restart")
	}
}

// Inbound order in the state must not look like a change: the panel renders
// from a database and the order is not guaranteed.
func TestInboundOrderIsNotAChange(t *testing.T) {
	a := user(1, "11111111-2222-3333-4444-555555555555")
	one, two := vless("a-inbound", 443), vless("b-inbound", 8443)
	for i := 0; i < 20; i++ {
		plan := PlanFor(
			state([]*nodepb.Inbound{one, two}, []*nodepb.User{a}),
			state([]*nodepb.Inbound{two, one}, []*nodepb.User{a}),
		)
		if !plan.Empty() {
			t.Fatalf("inbound order planned %+v", plan)
		}
	}
}

func TestCredentialsChanged(t *testing.T) {
	base := user(1, "11111111-2222-3333-4444-555555555555")
	if credentialsChanged(base, user(1, "11111111-2222-3333-4444-555555555555")) {
		t.Error("identical users compared as changed")
	}
	changes := map[string]func(*nodepb.User){
		"email":       func(u *nodepb.User) { u.Email = "other@whitenet" },
		"vless uuid":  func(u *nodepb.User) { u.VlessUuid = "other" },
		"password":    func(u *nodepb.User) { u.Password = "other" },
		"ss password": func(u *nodepb.User) { u.SsPassword = "other" },
		"flow":        func(u *nodepb.User) { u.Flow = "xtls-rprx-vision" },
	}
	for name, mutate := range changes {
		changed := user(1, "11111111-2222-3333-4444-555555555555")
		mutate(changed)
		if !credentialsChanged(base, changed) {
			t.Errorf("a changed %s compared as unchanged", name)
		}
	}
	// Things a node never sees must not count as a change.
	sameCreds := user(1, "11111111-2222-3333-4444-555555555555")
	sameCreds.Uuid = "a-different-public-uuid"
	if credentialsChanged(base, sameCreds) {
		t.Error("a field no node uses counted as a credential change")
	}
}
