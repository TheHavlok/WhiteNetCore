// Package subclient is the app's half of the subscription: fetching one,
// importing a link, and taking a flux lease.
//
// It lives in Go rather than in Swift and Kotlin because all three of those
// jobs are rules, not UI - which servers a document really offers, what a
// damaged link means, when a lease has to be renewed - and two
// implementations of a rule eventually disagree. The apps keep the UI and
// hand these the strings.
package subclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/sharelink"
	"github.com/thehavlok/whitenet/internal/panel/subscription"
)

// MaxDocument bounds what a subscription may be. A panel's answer is a few
// kilobytes; anything approaching this is either a different service or
// something trying to exhaust the phone's memory.
const MaxDocument = 4 << 20

// DefaultTimeout is how long a fetch may take. Short enough that a dead
// subscription host does not hold a connect attempt open, long enough for a
// phone on a bad mobile link.
const DefaultTimeout = 20 * time.Second

// Device is what the app tells the panel about itself. HWID is the only field
// that matters to the panel's accounting: it is what the device limit counts,
// so it has to be stable for the life of the install.
type Device struct {
	HWID       string
	Model      string
	Platform   string
	AppVersion string
}

// Error codes an app can act on, as opposed to display.
const (
	// CodeDeviceLimit means this device is past the account's limit. The user
	// has to remove a device, so retrying is pointless.
	CodeDeviceLimit = "device_limit"
	// CodeNotFound means the token is gone - reissued, or never existed. The
	// app should stop refreshing and say the subscription needs replacing.
	CodeNotFound = "not_found"
	// CodeRateLimited means back off.
	CodeRateLimited = "rate_limited"
	// CodeUnavailable covers a network failure and a panel that is down,
	// which the app treats the same way: keep the last document and retry.
	CodeUnavailable = "unavailable"
	// CodeBadDocument means the answer was not a subscription. Usually a
	// captive portal answering for the real host.
	CodeBadDocument = "bad_document"
	// CodeNotHTTPS means the URL was not https. A subscription carries every
	// credential the user has, so this is refused rather than warned about.
	CodeNotHTTPS = "not_https"
	// CodeVersion means the document is a newer format than this app reads.
	CodeVersion = "unsupported_version"
)

// Error is a failure an app can branch on.
type Error struct {
	Code    string
	Message string
	Status  int
	cause   error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.cause }

func fail(code, message string, status int, cause error) error {
	return &Error{Code: code, Message: message, Status: status, cause: cause}
}

// ErrorCode returns the code of an error from this package, or "" for
// anything else.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Client fetches subscriptions.
type Client struct {
	HTTP *http.Client
	// UserAgent identifies the app. The panel also recognises the device
	// header, so this is for the operator's logs rather than for routing.
	UserAgent string
	// AllowInsecure permits a plain-http subscription URL. Off by default,
	// and only meant for a test panel without a certificate: over http
	// anyone on the path reads every credential in the answer.
	AllowInsecure bool
}

// New returns a client with sensible defaults.
func New() *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: DefaultTimeout},
		UserAgent: "WhiteNetVPN",
	}
}

// Fetch retrieves and validates a subscription.
func (c *Client) Fetch(ctx context.Context, subURL string, device Device) (*subscription.Response, error) {
	if err := c.checkURL(subURL); err != nil {
		return nil, err
	}

	// The /json path rather than content negotiation: the panel decides by
	// headers too, but asking for exactly what we parse means a proxy that
	// rewrites Accept cannot turn the answer into a web page.
	target := strings.TrimRight(subURL, "/")
	if !strings.HasSuffix(target, "/json") {
		target += "/json"
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fail(CodeBadDocument, "that subscription address cannot be requested", 0, err)
	}
	request.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	if device.HWID != "" {
		request.Header.Set("X-HWID", device.HWID)
	}
	if device.Model != "" {
		request.Header.Set("X-Device-Model", device.Model)
	}
	if device.Platform != "" {
		request.Header.Set("X-Platform", device.Platform)
	}
	if device.AppVersion != "" {
		request.Header.Set("X-App-Version", device.AppVersion)
	}

	response, err := c.client().Do(request)
	if err != nil {
		return nil, fail(CodeUnavailable, "the subscription server could not be reached", 0, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxDocument+1))
	if err != nil {
		return nil, fail(CodeUnavailable, "the subscription could not be read", response.StatusCode, err)
	}
	if len(body) > MaxDocument {
		return nil, fail(CodeBadDocument, "that answer is too large to be a subscription", response.StatusCode, nil)
	}

	if response.StatusCode != http.StatusOK {
		return nil, statusError(response.StatusCode, body)
	}

	var doc subscription.Response
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&doc); err != nil {
		return nil, fail(CodeBadDocument,
			"that address answered with something that is not a subscription", response.StatusCode, err)
	}
	if doc.Version > subscription.Version {
		return nil, fail(CodeVersion,
			fmt.Sprintf("this subscription is version %d and this app reads %d; update the app",
				doc.Version, subscription.Version), response.StatusCode, nil)
	}
	if err := doc.Validate(); err != nil {
		return nil, fail(CodeBadDocument, "that subscription is not usable: "+err.Error(),
			response.StatusCode, err)
	}
	return &doc, nil
}

// statusError turns a non-200 into something the app can branch on, keeping
// the panel's own code when it sent one.
func statusError(status int, body []byte) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)

	switch {
	case envelope.Error.Code == CodeDeviceLimit:
		return fail(CodeDeviceLimit, orDefault(envelope.Error.Message,
			"this account does not allow another device"), status, nil)
	case status == http.StatusNotFound:
		return fail(CodeNotFound, "that subscription link no longer works", status, nil)
	case status == http.StatusTooManyRequests:
		return fail(CodeRateLimited, "too many requests; try again shortly", status, nil)
	case envelope.Error.Code != "":
		return fail(envelope.Error.Code, envelope.Error.Message, status, nil)
	default:
		return fail(CodeUnavailable,
			fmt.Sprintf("the subscription server answered %d", status), status, nil)
	}
}

// Import makes sense of whatever the user pasted, scanned or tapped.
//
// Three things arrive here: a subscription URL, a whitenetvpn://import deep
// link wrapping one, and a whitenet:// share link carrying servers. The first
// two are the same thing once unwrapped, which is why the app only needs this
// one entry point.
type ImportResult struct {
	// SubURL is set when the import leads to a subscription. The app should
	// store it and fetch, because that is the form that stays up to date.
	SubURL string
	// Bundle is set for a share link. Its servers work immediately and never
	// change; when it also carries Sub, the app connects with the servers and
	// then switches to the subscription.
	Bundle *sharelink.Bundle
}

// Import parses text. It does not touch the network.
func Import(text string) (*ImportResult, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fail(sharelink.CodeNotLink, "there is nothing to import", 0, nil)
	}

	switch {
	case strings.HasPrefix(text, sharelink.Prefix):
		bundle, err := sharelink.Decode(text)
		if err != nil {
			return nil, fail(sharelink.ErrorCode(err), err.Error(), 0, err)
		}
		return &ImportResult{Bundle: &bundle, SubURL: bundle.Sub}, nil

	case strings.HasPrefix(text, sharelink.ImportScheme+"://"):
		subURL, err := sharelink.ParseImportLink(text)
		if err != nil {
			return nil, fail(sharelink.ErrorCode(err), err.Error(), 0, err)
		}
		return &ImportResult{SubURL: subURL}, nil

	case strings.HasPrefix(text, "http://"), strings.HasPrefix(text, "https://"):
		return &ImportResult{SubURL: text}, nil

	default:
		return nil, fail(sharelink.CodeNotLink,
			"that is not a WhiteNet link or a subscription address", 0, nil)
	}
}

// --- flux leases ------------------------------------------------------------

// Lease is a channel the app holds for as long as it uses it.
type Lease = subscription.LeaseResponse

// Acquire takes a channel from a lease endpoint.
//
// A flux channel carries one client at a time, so this is how the app gets a
// usable one. Asking again while already holding a lease returns the same
// channel, so a retry after a timeout does not consume two.
func (c *Client) Acquire(ctx context.Context, leaseURL string, device Device) (*Lease, error) {
	return c.lease(ctx, leaseURL, device)
}

// Renew extends a lease. Renew at about half the remaining time: a lease that
// lapses frees the channel for someone else, and the app then has to take a
// new one mid-session.
func (c *Client) Renew(ctx context.Context, renewURL string, device Device) (*Lease, error) {
	return c.lease(ctx, renewURL, device)
}

// Release hands the channel back. Doing this on disconnect is what keeps a
// pool of channels usable: without it the channel sits idle until the lease
// expires.
func (c *Client) Release(ctx context.Context, releaseURL string, device Device) error {
	request, err := c.leaseRequest(ctx, releaseURL, device)
	if err != nil {
		return err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return fail(CodeUnavailable, "the channel could not be released", 0, err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
	if response.StatusCode >= 400 {
		// A release that fails is not worth retrying or showing: the lease
		// lapses on its own, which is the same outcome a little later.
		return fail(CodeUnavailable,
			fmt.Sprintf("the server answered %d when releasing the channel", response.StatusCode),
			response.StatusCode, nil)
	}
	return nil
}

func (c *Client) lease(ctx context.Context, endpoint string, device Device) (*Lease, error) {
	request, err := c.leaseRequest(ctx, endpoint, device)
	if err != nil {
		return nil, err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return nil, fail(CodeUnavailable, "no channel could be taken", 0, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxDocument))
	if err != nil {
		return nil, fail(CodeUnavailable, "the lease could not be read", response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, statusError(response.StatusCode, body)
	}

	var lease Lease
	if err := json.Unmarshal(body, &lease); err != nil {
		return nil, fail(CodeBadDocument, "that lease endpoint answered with something else",
			response.StatusCode, err)
	}
	if len(lease.Channel.Carriers) == 0 || lease.Channel.Secret == "" {
		return nil, fail(CodeBadDocument, "the lease carries no usable channel", response.StatusCode, nil)
	}
	return &lease, nil
}

func (c *Client) leaseRequest(ctx context.Context, endpoint string, device Device) (*http.Request, error) {
	if err := c.checkURL(endpoint); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fail(CodeBadDocument, "that lease address cannot be requested", 0, err)
	}
	request.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	if device.HWID != "" {
		request.Header.Set("X-HWID", device.HWID)
	}
	return request, nil
}

func (c *Client) checkURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return fail(CodeBadDocument, "that is not a usable address", 0, err)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if c.AllowInsecure {
			return nil
		}
		return fail(CodeNotHTTPS,
			"this address is not https, and a subscription carries every credential you have", 0, nil)
	default:
		return fail(CodeBadDocument, "only https addresses can be used", 0, nil)
	}
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: DefaultTimeout}
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
