package subscription

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validResponse() Response {
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	return Response{
		Version:             Version,
		IssuedAt:            time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		UpdateIntervalHours: 12,
		User: User{
			UUID:         "11111111-2222-3333-4444-555555555555",
			Name:         "test",
			ExpiresAt:    &expires,
			TrafficUsed:  123456789,
			TrafficLimit: 107374182400,
			DevicesLimit: 3,
			DevicesUsed:  1,
			Status:       StatusActive,
		},
		Servers: []Server{{
			ID:        "node:tag",
			Name:      "🇩🇪 Germany 1",
			Protocol:  ProtocolVLESS,
			Transport: "reality",
			Address:   "1.2.3.4",
			Port:      443,
			Params:    map[string]string{"uuid": "aaaa"},
		}},
	}
}

func TestValidateAcceptsAValidDocument(t *testing.T) {
	if err := validResponse().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejections(t *testing.T) {
	cases := map[string]func(*Response){
		"wrong version":       func(r *Response) { r.Version = 99 },
		"no user uuid":        func(r *Response) { r.User.UUID = "" },
		"unknown status":      func(r *Response) { r.User.Status = "pending" },
		"duplicate ids":       func(r *Response) { r.Servers = append(r.Servers, r.Servers[0]) },
		"server with no name": func(r *Response) { r.Servers[0].Name = "" },
		"server with no port": func(r *Response) { r.Servers[0].Port = 0 },
	}
	for name, mutate := range cases {
		r := validResponse()
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// A disabled or expired user still gets a document, with no servers, so the
// app can explain itself instead of showing a network error.
func TestValidateAllowsNoServersForABlockedUser(t *testing.T) {
	r := validResponse()
	r.User.Status = StatusExpired
	r.Servers = nil
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The field names are a contract with the app; a rename is a breaking change
// that must not happen by accident during a refactor.
func TestJSONFieldNames(t *testing.T) {
	raw, err := json.Marshal(validResponse())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`"version":1`,
		`"update_interval_hours":12`,
		`"user":{`,
		`"expires_at":"2026-12-31T23:59:59Z"`,
		`"traffic_used":123456789`,
		`"traffic_limit":107374182400`,
		`"devices_limit":3`,
		`"devices_used":1`,
		`"status":"active"`,
		`"servers":[`,
		`"protocol":"vless"`,
		`"transport":"reality"`,
		`"address":"1.2.3.4"`,
		`"port":443`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
}

// An empty server list must serialise as [] and not null: a client that
// iterates a null gets a crash or a silent skip depending on its language.
func TestEmptyServersMarshalAsList(t *testing.T) {
	r := validResponse()
	r.Servers = nil
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"servers":[]`) {
		t.Errorf("servers did not marshal as an empty list: %s", raw)
	}
}

// A caller that builds the struct by hand and forgets the version must still
// produce a valid document.
func TestMarshalFillsVersion(t *testing.T) {
	raw, err := json.Marshal(Response{User: User{UUID: "u", Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"version":1`) {
		t.Errorf("version was not filled in: %s", raw)
	}
}

func TestServerValidate(t *testing.T) {
	ok := map[string]Server{
		"vless": {ID: "a:b", Name: "n", Protocol: ProtocolVLESS, Address: "1.2.3.4", Port: 443},
		"hysteria2": {ID: "a:c", Name: "n", Protocol: ProtocolHysteria2, Address: "1.2.3.4", Port: 8443,
			Params: map[string]string{"auth": "pw"}},
		"wndns": {ID: "a:d", Name: "n", Protocol: ProtocolWNDNS, Address: "1.2.3.4", Port: 53,
			Params: map[string]string{"domains": "t.example"},
			Chain:  &Chain{Protocol: ProtocolVLESS, Params: map[string]string{"uuid": "u"}}},
		"flux with a lease": {ID: "a:e", Name: "n", Protocol: ProtocolFlux,
			Flux: &Flux{Mode: "l4", Lease: "https://sub.example/lease/t"}},
		"flux with a channel": {ID: "a:f", Name: "n", Protocol: ProtocolFlux,
			Flux: &Flux{Channels: []Channel{{ID: "c", Secret: "s",
				Carriers: []Carrier{{Type: "yandex", URL: "https://d.example/1"}}}}}},
	}
	for name, server := range ok {
		if err := server.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	bad := map[string]Server{
		"no id":             {Name: "n", Protocol: ProtocolVLESS, Address: "a", Port: 1},
		"no name":           {ID: "a:b", Protocol: ProtocolVLESS, Address: "a", Port: 1},
		"no protocol":       {ID: "a:b", Name: "n"},
		"port out of range": {ID: "a:b", Name: "n", Protocol: ProtocolVLESS, Address: "a", Port: 70000},
		"wndns without domains": {ID: "a:b", Name: "n", Protocol: ProtocolWNDNS, Address: "a",
			Chain: &Chain{Protocol: ProtocolVLESS}},
		"wndns chain without protocol": {ID: "a:b", Name: "n", Protocol: ProtocolWNDNS, Address: "a",
			Params: map[string]string{"domains": "t.example"}, Chain: &Chain{}},
		"flux without a block": {ID: "a:b", Name: "n", Protocol: ProtocolFlux},
		"flux channel without carriers": {ID: "a:b", Name: "n", Protocol: ProtocolFlux,
			Flux: &Flux{Channels: []Channel{{ID: "c", Secret: "s"}}}},
		"flux carriers with the same name": {ID: "a:b", Name: "n", Protocol: ProtocolFlux,
			Flux: &Flux{Channels: []Channel{{ID: "c", Secret: "s", Carriers: []Carrier{
				{Type: "yandex", URL: "https://d.example/1"},
				{Type: "yandex", URL: "https://d.example/2"},
			}}}}},
	}
	for name, server := range bad {
		if err := server.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestDomainList(t *testing.T) {
	s := Server{Params: map[string]string{"domains": " a.example , b.example ,, c.example "}}
	got := s.DomainList()
	want := []string{"a.example", "b.example", "c.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	var empty Server
	if empty.DomainList() != nil {
		t.Error("a server with no domains should return nil")
	}
}
