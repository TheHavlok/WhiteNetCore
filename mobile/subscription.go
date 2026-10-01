package mobile

// The app's subscription API, as gomobile sees it.
//
// Everything here is shaped for the bridge: no maps, no slices of structs, and
// failures come back as a result object with a code rather than as an error,
// because an NSError across the bridge keeps only its message and the apps
// need to branch on *why* a fetch failed - a device limit is not a network
// problem and must not be retried.
//
// The rules live in internal/subclient and internal/clientprofile; this file
// is the binding and nothing more.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/thehavlok/whitenet/internal/clientprofile"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
	"github.com/thehavlok/whitenet/internal/subclient"
)

// Server is one connectable server, with its configuration already built.
type Server struct {
	ID      string
	Name    string
	Country string
	Group   string
	// Proto, not Protocol: "protocol" is a keyword in Swift, and a field by
	// that name has to be written in backticks at every use. ShareLink made
	// the same choice for the same reason.
	Proto     string
	Transport string
	Address   string
	Port      int

	// Kind is "xray" or "whitenet" - which core Config belongs to. The apps
	// already store one opaque config string per profile, so this is only
	// needed when something has to be shown about it.
	Kind string
	// Config is what to hand the core.
	Config string
	// InnerConfig is the second half of a chained profile: the app starts
	// Config, waits for it, then starts InnerConfig, which dials out through
	// it. Only the DNS tunnel uses this, because the tunnel authenticates
	// nobody on its own. Empty for everything else.
	InnerConfig string

	// LeaseURL is set on a flux server instead of Config: a flux channel
	// carries one client at a time, so the app has to take a lease first and
	// then call FluxConnect, which fills in the configuration.
	LeaseURL string

	// Error says why this server has no configuration, when it has none. A
	// server the app does not understand is skipped rather than failing the
	// whole subscription, which is what lets a new protocol reach nodes
	// before every app has caught up.
	Error string

	// raw is the server as the subscription sent it, kept so a flux lease can
	// be turned into a profile without a second fetch.
	raw string
}

// NeedsLease reports whether this server has to be leased before it can be
// used.
func (s *Server) NeedsLease() bool { return s != nil && s.LeaseURL != "" }

// Usable reports whether the app can connect with this server as it stands.
func (s *Server) Usable() bool { return s != nil && s.Config != "" }

// RawJSON is the server as the subscription sent it.
func (s *Server) RawJSON() string { return s.raw }

// Subscription is a fetched document.
type Subscription struct {
	Version             int
	IssuedAtUnix        int64
	UpdateIntervalHours int

	UserUUID string
	UserName string
	// ExpiresAtUnix is 0 for an account that never expires.
	ExpiresAtUnix int64
	// DaysLeft is what the app shows. It is -1 when there is no expiry, and
	// 0 on the last day rather than going negative.
	DaysLeft     int
	TrafficUsed  int64
	TrafficLimit int64
	DevicesLimit int
	DevicesUsed  int
	// Status is active, disabled, expired or limited. A blocked account is
	// still served, with no servers, so the app can say why.
	Status string

	AppName     string
	LogoURL     string
	SupportURL  string
	Message     string
	AccentColor string

	// JSON is the whole document, for an app that wants a field this struct
	// does not carry.
	JSON string

	servers []*Server
}

// ServerCount is how many servers the subscription offers.
func (s *Subscription) ServerCount() int { return len(s.servers) }

// Server returns one server, or nil when the index is out of range.
func (s *Subscription) Server(index int) *Server {
	if s == nil || index < 0 || index >= len(s.servers) {
		return nil
	}
	return s.servers[index]
}

// Blocked reports whether the account cannot connect at all, which is why the
// server list is empty.
func (s *Subscription) Blocked() bool {
	return s != nil && s.Status != subscription.StatusActive
}

// FetchResult is what FetchSubscription answers.
//
// A result rather than an error: the apps have to tell a device limit from a
// dead network, and only Code says which.
type FetchResult struct {
	OK bool
	// Code is empty on success. Otherwise: device_limit, not_found,
	// rate_limited, unavailable, bad_document, not_https,
	// unsupported_version.
	Code string
	// Message is already worded for a user.
	Message string
	// Sub is the document on success.
	Sub *Subscription
}

// FetchSubscription fetches and parses a subscription.
//
// hwid is what the panel's device limit counts, so it must be stable for the
// life of the install. allowInsecure permits a plain-http panel; leave it off
// outside testing, because a subscription carries every credential the user
// has.
func FetchSubscription(subURL, hwid, model, platform, appVersion string, allowInsecure bool) *FetchResult {
	client := subclient.New()
	client.AllowInsecure = allowInsecure

	ctx, cancel := context.WithTimeout(context.Background(), subclient.DefaultTimeout)
	defer cancel()

	doc, err := client.Fetch(ctx, subURL, subclient.Device{
		HWID: hwid, Model: model, Platform: platform, AppVersion: appVersion,
	})
	if err != nil {
		return &FetchResult{Code: codeOrUnavailable(err), Message: err.Error()}
	}
	return &FetchResult{OK: true, Sub: convert(doc)}
}

// ImportResult is what ImportText answers.
type ImportResult struct {
	OK bool
	// Code is empty on success, else one of the link codes: not_link,
	// unsupported_version, case_changed, damaged, too_large, bad_payload,
	// no_servers, bad_server, no_url, not_https.
	Code    string
	Message string

	// SubURL is set when the import leads to a subscription. Storing it and
	// fetching is the form that stays up to date.
	SubURL string
	// Name is the bundle's suggested profile name, when it has one.
	Name string

	servers []*Server
}

// ServerCount is how many servers a share link carried. Zero for a plain
// subscription link, which has to be fetched.
func (r *ImportResult) ServerCount() int { return len(r.servers) }

// Server returns one of the link's servers.
func (r *ImportResult) Server(index int) *Server {
	if r == nil || index < 0 || index >= len(r.servers) {
		return nil
	}
	return r.servers[index]
}

// ImportText makes sense of whatever the user pasted, scanned or tapped: a
// whitenet:// share link, a whitenetvpn://import deep link, or a plain
// subscription address. It touches no network.
func ImportText(text string) *ImportResult {
	result, err := subclient.Import(text)
	if err != nil {
		return &ImportResult{Code: codeOrUnavailable(err), Message: err.Error()}
	}
	out := &ImportResult{OK: true, SubURL: result.SubURL}
	if result.Bundle != nil {
		out.Name = result.Bundle.Name
		for _, server := range result.Bundle.Servers {
			out.servers = append(out.servers, buildServer(server))
		}
	}
	return out
}

// FluxLease is a channel the app holds while it uses it.
type FluxLease struct {
	OK      bool
	Code    string
	Message string

	// Config is the profile to start, already built from the leased channel.
	Config string
	// Kind is always "whitenet" for flux; present so the app can treat every
	// profile the same way.
	Kind string
	// ExpiresAtUnix is when the lease lapses unless renewed. Renew at about
	// half the remaining time: a lapsed lease frees the channel for someone
	// else, and the session then drops.
	ExpiresAtUnix int64
	RenewURL      string
	ReleaseURL    string
}

// FluxConnect takes a channel for a flux server and builds its profile.
//
// serverJSON is Server.RawJSON() for a server whose NeedsLease is true.
func FluxConnect(serverJSON, hwid string, allowInsecure bool) *FluxLease {
	var server subscription.Server
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		return &FluxLease{Code: subclient.CodeBadDocument, Message: "that server cannot be read: " + err.Error()}
	}
	if server.Flux == nil || server.Flux.Lease == "" {
		return &FluxLease{Code: subclient.CodeBadDocument, Message: "that server has no lease endpoint"}
	}

	client := subclient.New()
	client.AllowInsecure = allowInsecure
	ctx, cancel := context.WithTimeout(context.Background(), subclient.DefaultTimeout)
	defer cancel()

	lease, err := client.Acquire(ctx, server.Flux.Lease, subclient.Device{HWID: hwid})
	if err != nil {
		return &FluxLease{Code: codeOrUnavailable(err), Message: err.Error()}
	}
	return leaseProfile(server, lease)
}

// RenewFluxLease extends a lease and returns the channel again, so an app that
// was handed a different one notices.
func RenewFluxLease(renewURL, hwid, serverJSON string, allowInsecure bool) *FluxLease {
	var server subscription.Server
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		return &FluxLease{Code: subclient.CodeBadDocument, Message: "that server cannot be read"}
	}

	client := subclient.New()
	client.AllowInsecure = allowInsecure
	ctx, cancel := context.WithTimeout(context.Background(), subclient.DefaultTimeout)
	defer cancel()

	lease, err := client.Renew(ctx, renewURL, subclient.Device{HWID: hwid})
	if err != nil {
		return &FluxLease{Code: codeOrUnavailable(err), Message: err.Error()}
	}
	return leaseProfile(server, lease)
}

// ReleaseFluxLease hands the channel back, which is what keeps a pool of
// channels usable: without it the channel sits idle until the lease expires.
// Call it on disconnect. A failure here is not worth showing - the lease
// lapses on its own - so this returns only a message for the log.
func ReleaseFluxLease(releaseURL, hwid string, allowInsecure bool) string {
	client := subclient.New()
	client.AllowInsecure = allowInsecure
	ctx, cancel := context.WithTimeout(context.Background(), subclient.DefaultTimeout)
	defer cancel()

	if err := client.Release(ctx, releaseURL, subclient.Device{HWID: hwid}); err != nil {
		return err.Error()
	}
	return ""
}

// --- conversion -------------------------------------------------------------

func leaseProfile(server subscription.Server, lease *subclient.Lease) *FluxLease {
	// The leased channel replaces whatever the subscription carried, which is
	// normally nothing: a pooled server has a lease endpoint and no channel.
	server.Flux.Channels = []subscription.Channel{lease.Channel}

	profile, err := clientprofile.FromServer(server, clientprofile.Options{SocksPort: xraySocksPort})
	if err != nil {
		return &FluxLease{Code: subclient.CodeBadDocument, Message: err.Error()}
	}
	return &FluxLease{
		OK:            true,
		Config:        profile.Config,
		Kind:          string(profile.Kind),
		ExpiresAtUnix: lease.ExpiresAt.Unix(),
		RenewURL:      lease.RenewURL,
		ReleaseURL:    lease.ReleaseURL,
	}
}

func convert(doc *subscription.Response) *Subscription {
	out := &Subscription{
		Version:             doc.Version,
		IssuedAtUnix:        doc.IssuedAt.Unix(),
		UpdateIntervalHours: doc.UpdateIntervalHours,
		UserUUID:            doc.User.UUID,
		UserName:            doc.User.Name,
		DaysLeft:            -1,
		TrafficUsed:         int64(doc.User.TrafficUsed),
		TrafficLimit:        int64(doc.User.TrafficLimit),
		DevicesLimit:        doc.User.DevicesLimit,
		DevicesUsed:         doc.User.DevicesUsed,
		Status:              doc.User.Status,
	}
	if doc.User.ExpiresAt != nil {
		out.ExpiresAtUnix = doc.User.ExpiresAt.Unix()
		out.DaysLeft = daysLeft(*doc.User.ExpiresAt)
	}
	if doc.Branding != nil {
		out.AppName = doc.Branding.AppName
		out.LogoURL = doc.Branding.LogoURL
		out.SupportURL = doc.Branding.SupportURL
		out.Message = doc.Branding.Message
		out.AccentColor = doc.Branding.AccentColor
	}
	if raw, err := json.Marshal(doc); err == nil {
		out.JSON = string(raw)
	}
	for _, server := range doc.Servers {
		out.servers = append(out.servers, buildServer(server))
	}
	return out
}

// daysLeft rounds up, so an account with six hours to run shows one day
// rather than none: "0 days left" on a subscription that still works reads as
// a bug.
func daysLeft(expires time.Time) int {
	remaining := time.Until(expires)
	if remaining <= 0 {
		return 0
	}
	days := int(remaining / (24 * time.Hour))
	if remaining%(24*time.Hour) > 0 {
		days++
	}
	return days
}

func buildServer(server subscription.Server) *Server {
	out := &Server{
		ID:        server.ID,
		Name:      server.Name,
		Country:   server.Country,
		Group:     server.Group,
		Proto:     server.Protocol,
		Transport: server.Transport,
		Address:   server.Address,
		Port:      server.Port,
	}
	if raw, err := json.Marshal(server); err == nil {
		out.raw = string(raw)
	}

	// A pooled flux server has nothing to connect with until a channel is
	// leased, so it is handed back with its lease endpoint instead of a
	// configuration.
	if server.Protocol == subscription.ProtocolFlux &&
		server.Flux != nil && len(server.Flux.Channels) == 0 {
		out.Kind = string(clientprofile.KindWhiteNet)
		out.LeaseURL = server.Flux.Lease
		if out.LeaseURL == "" {
			out.Error = "this flux server offers neither a channel nor a lease endpoint"
		}
		return out
	}

	profile, err := clientprofile.FromServer(server, clientprofile.Options{SocksPort: xraySocksPort})
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Kind = string(profile.Kind)
	out.Config = profile.Config
	if profile.Inner != nil {
		out.InnerConfig = profile.Inner.Config
	}
	return out
}

func codeOrUnavailable(err error) string {
	if code := subclient.ErrorCode(err); code != "" {
		return code
	}
	return subclient.CodeUnavailable
}
