package client

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentconfig "github.com/thehavlok/whitenet/internal/agentd/config"
	"github.com/thehavlok/whitenet/internal/nodepb"
)

// osHostname is os.Hostname, wrapped so the caller reads as one idea.
func osHostname() (string, error) { return os.Hostname() }

// kernelVersion reads the running kernel. It is advisory - the panel shows it
// so an operator can tell a stale node from a current one - so a failure is an
// empty string rather than an error.
func kernelVersion() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// localAddresses lists the node's own addresses, so the panel can offer them
// when an operator fills in the address clients dial. They are advisory: the
// panel never overwrites a configured address with one of these, because a
// node behind a proxy or with a vanity domain would break.
func localAddresses() (v4, v6 []string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4.String())
			continue
		}
		v6 = append(v6, ip.String())
	}
	return v4, v6
}

// coreBinaryVersion asks a core binary for its version. A core that is not
// installed yet reports an empty string rather than failing the heartbeat.
func coreBinaryVersion(path string, args ...string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return ""
	}
	line := out.String()
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return compactVersion(strings.TrimSpace(line))
}

// compactVersion pulls the version out of a banner line.
//
// Xray prints "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1
// linux/amd64)", which is seventy-odd characters of mostly nothing. The panel
// shows this in a table and stores it in a short column, so what it wants is
// "26.3.27".
func compactVersion(line string) string {
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	for _, field := range fields {
		trimmed := strings.TrimPrefix(field, "v")
		if trimmed == "" {
			continue
		}
		// The first field that starts with a digit and contains a dot is the
		// version; everything around it is decoration.
		if trimmed[0] >= '0' && trimmed[0] <= '9' && strings.Contains(trimmed, ".") {
			return trimmed
		}
	}
	// Nothing recognisable: keep the line, but short enough to store.
	if len(line) > 60 {
		return line[:60]
	}
	return line
}

// readCoreLog returns the last lines of a core's log.
//
// The cores log to their own files under the agent's directory rather than to
// the journal, because the panel has to be able to fetch them without the
// agent needing to parse journald's format or hold its permissions.
func readCoreLog(cfg agentconfig.Config, core nodepb.Core, lines int) (string, error) {
	var name string
	switch core {
	case nodepb.Core_CORE_XRAY:
		name = "xray.log"
	case nodepb.Core_CORE_WNDNS:
		name = "wndns.log"
	case nodepb.Core_CORE_OPENFLUX:
		// flux runs in the agent, so its log is the agent's.
		name = "agent.log"
	default:
		return "", fmt.Errorf("client: no log for core %s", core)
	}

	path := filepath.Join(cfg.DataDir, "logs", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("client: read %s: %w", path, err)
	}
	return lastLines(string(raw), lines), nil
}

// lastLines returns the final n lines of s.
func lastLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) <= n {
		return strings.Join(all, "\n")
	}
	return strings.Join(all[len(all)-n:], "\n")
}
