package xray

import (
	"sync"

	"github.com/thehavlok/whitenet/internal/logger"
	"github.com/thehavlok/whitenet/internal/protect"
	"github.com/xtls/xray-core/transport/internet"
)

var controllerOnce sync.Once //nolint:gochecknoglobals // registration is process-wide

// installDialerController routes every socket xray-core opens through the
// platform's socket protector.
//
// On Android this is mandatory. Without VpnService.protect() the proxy's own
// connection to the server is captured by our own TUN, and the tunnel starts
// feeding itself - it looks like a dead server rather than a routing loop,
// which makes it an expensive bug to find.
//
// On iOS protect.Protector is nil: a Network Extension's own traffic is not
// routed through the tunnel it provides, so no controller is installed.
func installDialerController() {
	if protect.Protector == nil {
		return
	}

	controllerOnce.Do(func() {
		if err := internet.RegisterDialerController(protect.Control); err != nil {
			logger.Warnf("xray: cannot register dialer controller: %v", err)
		}
	})
}
