// Package xrayctl talks to a running Xray over its gRPC API.
//
// Two jobs:
//
//	HandlerService - add and remove users on a live inbound, which is what
//	                 keeps Xray from restarting every time someone's
//	                 subscription changes;
//	StatsService   - read traffic counters and the online-user list.
//
// The API is on the loopback interface and has no authentication of its own:
// anything that can reach it can add a user and read every counter. That is
// why xraycfg refuses to bind it anywhere else.
package xrayctl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	handler "github.com/xtls/xray-core/app/proxyman/command"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"

	"github.com/thehavlok/whitenet/internal/nodepb"
)

// ErrNotRunning is returned when Xray is not answering on its API port. The
// agent treats it as "retry after the supervisor has it up" rather than as a
// failure of whatever it was trying to do.
var ErrNotRunning = errors.New("xrayctl: xray is not answering on its api port")

// Client is a connection to one Xray instance.
type Client struct {
	address string

	mu      sync.Mutex
	conn    *grpc.ClientConn
	handler handler.HandlerServiceClient
	stats   statscmd.StatsServiceClient
}

// New returns a client. It does not connect: the agent builds the client
// before Xray is running, and dialling is lazy so startup order does not
// matter.
func New(address string) *Client {
	return &Client{address: address}
}

// Close releases the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.handler, c.stats = nil, nil, nil
	return err
}

// Reset drops the connection so the next call dials again. The agent calls it
// after restarting Xray: the old connection would keep failing against a
// process that no longer exists.
func (c *Client) Reset() {
	_ = c.Close()
}

func (c *Client) dial(ctx context.Context) (handler.HandlerServiceClient, statscmd.StatsServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handler != nil && c.stats != nil {
		return c.handler, c.stats, nil
	}
	conn, err := grpc.NewClient(c.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("xrayctl: dial %s: %w", c.address, err)
	}
	c.conn = conn
	c.handler = handler.NewHandlerServiceClient(conn)
	c.stats = statscmd.NewStatsServiceClient(conn)
	return c.handler, c.stats, nil
}

// AddUser adds one user to one inbound. Adding a user who is already there is
// not an error: the agent reconciles state rather than tracking what it
// already did, so idempotence is the whole point.
func (c *Client) AddUser(ctx context.Context, inbound *nodepb.Inbound, user *nodepb.User) error {
	h, _, err := c.dial(ctx)
	if err != nil {
		return err
	}
	inboundTag := inbound.GetTag()
	account, err := buildAccount(inbound, user)
	if err != nil {
		return err
	}
	_, err = h.AlterInbound(ctx, &handler.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&handler.AddUserOperation{
			User: &protocol.User{
				Email:   user.GetEmail(),
				Level:   0,
				Account: account,
			},
		}),
	})
	if err != nil {
		if isAlreadyExists(err) {
			return nil
		}
		return wrapErr(fmt.Sprintf("add user %s to %s", user.GetEmail(), inboundTag), err)
	}
	return nil
}

// RemoveUser removes one user from one inbound. A user who is not there is not
// an error, for the same reason.
func (c *Client) RemoveUser(ctx context.Context, inboundTag, email string) error {
	h, _, err := c.dial(ctx)
	if err != nil {
		return err
	}
	_, err = h.AlterInbound(ctx, &handler.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(&handler.RemoveUserOperation{Email: email}),
	})
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return wrapErr(fmt.Sprintf("remove user %s from %s", email, inboundTag), err)
	}
	return nil
}

// ListInboundTags returns the tags Xray is currently serving. The agent
// compares them with the desired state to decide whether a restart is needed
// or whether users alone can be adjusted.
func (c *Client) ListInboundTags(ctx context.Context) ([]string, error) {
	h, _, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := h.ListInbounds(ctx, &handler.ListInboundsRequest{IsOnlyTags: true})
	if err != nil {
		return nil, wrapErr("list inbounds", err)
	}
	tags := make([]string, 0, len(resp.GetInbounds()))
	for _, in := range resp.GetInbounds() {
		tags = append(tags, in.GetTag())
	}
	return tags, nil
}

// InboundUserEmails returns the emails on one inbound.
func (c *Client) InboundUserEmails(ctx context.Context, inboundTag string) ([]string, error) {
	h, _, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	// An empty email means "every user on this inbound".
	resp, err := h.GetInboundUsers(ctx, &handler.GetInboundUserRequest{Tag: inboundTag})
	if err != nil {
		return nil, wrapErr("get inbound users of "+inboundTag, err)
	}
	emails := make([]string, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		emails = append(emails, u.GetEmail())
	}
	return emails, nil
}

// TrafficCounters are the counters read in one pass, keyed by the thing they
// belong to.
type TrafficCounters struct {
	// Users maps a user's email to their uplink and downlink.
	Users map[string]Traffic
	// Inbounds maps an inbound tag to its uplink and downlink.
	Inbounds map[string]Traffic
}

// Traffic is one pair of counters, in bytes.
type Traffic struct {
	Uplink   uint64
	Downlink uint64
}

// ReadTraffic reads every counter and resets them.
//
// Reset is deliberate: the agent reports deltas, and resetting is how the next
// read is a delta without the agent having to remember the previous values
// across its own restarts. The cost is that a report lost in flight is traffic
// nobody is billed for - which is the right way round, and why the report
// carries a batch id so a retry is not counted twice instead.
func (c *Client) ReadTraffic(ctx context.Context) (TrafficCounters, error) {
	_, s, err := c.dial(ctx)
	if err != nil {
		return TrafficCounters{}, err
	}
	resp, err := s.QueryStats(ctx, &statscmd.QueryStatsRequest{Pattern: "", Reset_: true})
	if err != nil {
		return TrafficCounters{}, wrapErr("query stats", err)
	}

	out := TrafficCounters{
		Users:    map[string]Traffic{},
		Inbounds: map[string]Traffic{},
	}
	for _, stat := range resp.GetStat() {
		kind, name, direction, ok := parseStatName(stat.GetName())
		if !ok || stat.GetValue() <= 0 {
			continue
		}
		value := uint64(stat.GetValue())
		switch kind {
		case "user":
			entry := out.Users[name]
			if direction == "uplink" {
				entry.Uplink += value
			} else {
				entry.Downlink += value
			}
			out.Users[name] = entry
		case "inbound":
			entry := out.Inbounds[name]
			if direction == "uplink" {
				entry.Uplink += value
			} else {
				entry.Downlink += value
			}
			out.Inbounds[name] = entry
		}
	}
	return out, nil
}

// parseStatName splits Xray's counter names, which look like
// "user>>>someone@whitenet>>>traffic>>>uplink" or
// "inbound>>>vless-443>>>traffic>>>downlink".
func parseStatName(name string) (kind, subject, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[2] != "traffic" {
		return "", "", "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[3], true
}

// OnlineUsers returns the emails Xray currently has connections for. It is
// what the panel shows as "online now".
func (c *Client) OnlineUsers(ctx context.Context) ([]string, error) {
	_, s, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := s.GetAllOnlineUsers(ctx, &statscmd.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, wrapErr("get online users", err)
	}
	return resp.GetUsers(), nil
}

// Ping reports whether Xray is answering. The supervisor uses it to decide
// whether a start actually succeeded, rather than trusting that the process
// did not exit immediately.
func (c *Client) Ping(ctx context.Context) error {
	_, s, err := c.dial(ctx)
	if err != nil {
		return err
	}
	if _, err := s.GetSysStats(ctx, &statscmd.SysStatsRequest{}); err != nil {
		return wrapErr("ping", err)
	}
	return nil
}

// WaitReady polls until Xray answers or the context is done. Starting Xray is
// not instant, and treating "not yet" as a failure would make the supervisor
// restart a process that was about to work.
func (c *Client) WaitReady(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := c.Ping(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("xrayctl: xray did not become ready: %w (last error: %v)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

// buildAccount turns a user into the protocol-specific account Xray wants.
// Getting this wrong is why a user can be "added" and still not able to
// connect, so each case mirrors what xraycfg writes into the config file.
//
// It takes the whole inbound, not just the protocol, because legacy
// Shadowsocks needs the inbound's cipher: an account with an unset cipher is
// rejected at runtime even though the configuration file can leave it out.
func buildAccount(inbound *nodepb.Inbound, user *nodepb.User) (*serial.TypedMessage, error) {
	switch inbound.GetProtocol() {
	case nodepb.Protocol_PROTOCOL_VLESS:
		if user.GetVlessUuid() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no vless uuid", user.GetEmail())
		}
		return serial.ToTypedMessage(&vless.Account{
			Id:   user.GetVlessUuid(),
			Flow: user.GetFlow(),
		}), nil

	case nodepb.Protocol_PROTOCOL_VMESS:
		if user.GetVlessUuid() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no uuid", user.GetEmail())
		}
		return serial.ToTypedMessage(&vmess.Account{Id: user.GetVlessUuid()}), nil

	case nodepb.Protocol_PROTOCOL_TROJAN:
		if user.GetPassword() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no password", user.GetEmail())
		}
		return serial.ToTypedMessage(&trojan.Account{Password: user.GetPassword()}), nil

	case nodepb.Protocol_PROTOCOL_HYSTERIA2:
		if user.GetPassword() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no password", user.GetEmail())
		}
		return serial.ToTypedMessage(&hysteriaaccount.Account{Auth: user.GetPassword()}), nil

	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS:
		if user.GetSsPassword() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no shadowsocks password", user.GetEmail())
		}
		// The cipher has to be spelled out: AlterInbound rejects an account
		// whose cipher is unset, even though the configuration file may omit
		// it and inherit the inbound's.
		cipher, err := cipherFromMethod(inbound.GetParams()["method"])
		if err != nil {
			return nil, err
		}
		return serial.ToTypedMessage(&shadowsocks.Account{
			Password:   user.GetSsPassword(),
			CipherType: cipher,
		}), nil

	case nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022:
		if user.GetSsPassword() == "" {
			return nil, fmt.Errorf("xrayctl: user %s has no shadowsocks password", user.GetEmail())
		}
		return serial.ToTypedMessage(&ss2022.Account{Key: user.GetSsPassword()}), nil

	default:
		return nil, fmt.Errorf("xrayctl: protocol %s has no xray account", inbound.GetProtocol())
	}
}

// cipherFromMethod maps a legacy Shadowsocks method name to Xray's enum. The
// 2022 methods are not here: they are a different proxy with a different
// account type.
func cipherFromMethod(method string) (shadowsocks.CipherType, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM, nil
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM, nil
	case "chacha20-poly1305", "chacha20-ietf-poly1305", "aead_chacha20_poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305, nil
	case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305, nil
	case "none", "plain":
		return shadowsocks.CipherType_NONE, nil
	default:
		return shadowsocks.CipherType_UNKNOWN, fmt.Errorf("xrayctl: unsupported shadowsocks method %q", method)
	}
}

// SupportsUsers reports whether a protocol can have users added and removed at
// runtime. Everything xray-core serves can; the DNS tunnel and flux cannot,
// and the agent must not try.
func SupportsUsers(protocolKind nodepb.Protocol) bool {
	switch protocolKind {
	case nodepb.Protocol_PROTOCOL_VLESS,
		nodepb.Protocol_PROTOCOL_VMESS,
		nodepb.Protocol_PROTOCOL_TROJAN,
		nodepb.Protocol_PROTOCOL_SHADOWSOCKS,
		nodepb.Protocol_PROTOCOL_SHADOWSOCKS_2022,
		nodepb.Protocol_PROTOCOL_HYSTERIA2:
		return true
	default:
		return false
	}
}

// isAlreadyExists and isNotFound read Xray's errors, which are strings rather
// than codes for these cases.
func isAlreadyExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "already in use")
}

func isNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such user")
}

// wrapErr turns a connection refused into ErrNotRunning, so the caller can
// tell "Xray is down" from "Xray said no".
func wrapErr(what string, err error) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return fmt.Errorf("xrayctl: %s: %w (%v)", what, ErrNotRunning, err)
		}
	}
	return fmt.Errorf("xrayctl: %s: %w", what, err)
}
