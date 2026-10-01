// Package memprofile carries one process-wide hint: whether whitenet runs
// inside a mobile VPN extension, where the memory budget is a hard ceiling
// rather than a preference.
//
// iOS gives a NEPacketTunnelProvider roughly 50 MB for everything at once -
// the Go heap, gvisor's netstack, pion's WebRTC stack and the Swift side.
// Going over it does not degrade performance: the OS kills the extension
// outright, and the user sees the VPN switch itself off. Buffer sizes chosen
// for a desktop, where a spare 16 MB costs nothing, do not survive in that
// budget under sustained load.
//
// It lives in its own package, importing nothing, so both internal/runtime
// and the transports can read it without an import cycle.
package memprofile

import "sync/atomic"

var mobile atomic.Bool //nolint:gochecknoglobals // process-wide by design

// SetMobile marks this process as running under a mobile VPN extension's
// memory limit. Call it before starting the client.
func SetMobile(v bool) { mobile.Store(v) }

// IsMobile reports whether mobile-sized buffers should be used.
func IsMobile() bool { return mobile.Load() }
