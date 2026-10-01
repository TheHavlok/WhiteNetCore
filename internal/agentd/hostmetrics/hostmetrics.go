// Package hostmetrics samples the node's CPU, memory, disk, network and
// uptime.
//
// It reads /proc and /sys directly rather than pulling in a metrics library:
// the agent needs seven numbers on Linux, and a dependency that supports every
// operating system is a lot of code to carry onto a VPS for that. Everything
// here degrades to a zero value rather than an error, because a missing
// counter must not stop a heartbeat - a gap in a graph is better than a node
// that looks offline.
package hostmetrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sample is one reading. Byte counters are absolute since boot; the panel
// turns them into rates, so a lost report shows up as a gap rather than as a
// permanently wrong total.
type Sample struct {
	At time.Time

	CPUPercent float64
	Load1      float64

	MemUsedBytes  uint64
	MemTotalBytes uint64

	DiskUsedBytes  uint64
	DiskTotalBytes uint64

	NetRxBytes uint64
	NetTxBytes uint64

	UptimeSeconds uint64
	TCPConns      uint32
}

// Collector samples the host. CPU usage needs two readings to mean anything,
// so the collector keeps the previous one; it is safe for concurrent use.
type Collector struct {
	// Root is the filesystem root, overridden in tests. Empty means "/".
	Root string
	// DiskPath is the mount point whose usage is reported. Empty means "/".
	DiskPath string
	// NetInterfaces limits which interfaces are summed. Empty means every
	// interface except loopback and the obvious virtual ones.
	NetInterfaces []string

	mu      sync.Mutex
	lastCPU cpuTimes
	hasLast bool
}

type cpuTimes struct {
	idle  uint64
	total uint64
}

// Collect takes one sample. The first call cannot know CPU usage yet and
// reports 0 for it.
func (c *Collector) Collect() Sample {
	s := Sample{At: time.Now().UTC()}

	s.CPUPercent = c.cpuPercent()
	s.Load1 = c.load1()
	s.MemUsedBytes, s.MemTotalBytes = c.memory()
	s.DiskUsedBytes, s.DiskTotalBytes = c.disk()
	s.NetRxBytes, s.NetTxBytes = c.network()
	s.UptimeSeconds = c.uptime()
	s.TCPConns = c.tcpConnections()
	return s
}

func (c *Collector) path(parts ...string) string {
	root := c.Root
	if root == "" {
		root = "/"
	}
	return strings.TrimRight(root, "/") + "/" + strings.Join(parts, "/")
}

// cpuPercent reads the aggregate line of /proc/stat and compares it with the
// previous reading.
func (c *Collector) cpuPercent() float64 {
	now, ok := c.readCPUTimes()
	if !ok {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.hasLast {
		c.lastCPU, c.hasLast = now, true
		return 0
	}
	deltaTotal := now.total - c.lastCPU.total
	deltaIdle := now.idle - c.lastCPU.idle
	c.lastCPU = now
	if deltaTotal == 0 || deltaTotal > now.total {
		// Counters wrapped or did not move; report nothing rather than a
		// nonsense spike.
		return 0
	}
	busy := float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100
	if busy < 0 {
		return 0
	}
	if busy > 100 {
		return 100
	}
	return busy
}

func (c *Collector) readCPUTimes() (cpuTimes, bool) {
	f, err := os.Open(c.path("proc", "stat"))
	if err != nil {
		return cpuTimes{}, false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var times cpuTimes
		for i, field := range fields[1:] {
			v, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				continue
			}
			times.total += v
			// Fields are user, nice, system, idle, iowait, ... Idle and
			// iowait both mean "not doing work".
			if i == 3 || i == 4 {
				times.idle += v
			}
		}
		return times, times.total > 0
	}
	return cpuTimes{}, false
}

func (c *Collector) load1() float64 {
	raw, err := os.ReadFile(c.path("proc", "loadavg"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return v
}

// memory reports used and total. "Used" is total minus MemAvailable, which is
// the number that matters operationally: MemFree on a busy box is always small
// because the kernel uses the rest for cache.
func (c *Collector) memory() (used, total uint64) {
	f, err := os.Open(c.path("proc", "meminfo"))
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	var available uint64
	var haveAvailable bool
	var free, buffers, cached uint64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		bytes := kb * 1024
		switch key {
		case "MemTotal":
			total = bytes
		case "MemAvailable":
			available, haveAvailable = bytes, true
		case "MemFree":
			free = bytes
		case "Buffers":
			buffers = bytes
		case "Cached":
			cached = bytes
		}
	}
	if total == 0 {
		return 0, 0
	}
	if haveAvailable {
		if available > total {
			return 0, total
		}
		return total - available, total
	}
	// Very old kernels have no MemAvailable; approximate it.
	reclaimable := free + buffers + cached
	if reclaimable > total {
		return 0, total
	}
	return total - reclaimable, total
}

func (c *Collector) network() (rx, tx uint64) {
	f, err := os.Open(c.path("proc", "net", "dev"))
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	want := map[string]bool{}
	for _, name := range c.NetInterfaces {
		want[name] = true
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		name, counters, found := strings.Cut(line, ":")
		if !found {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if len(want) > 0 {
			if !want[name] {
				continue
			}
		} else if skipInterface(name) {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 9 {
			continue
		}
		// Receive bytes is the first field, transmit bytes the ninth.
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			rx += v
		}
		if v, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
			tx += v
		}
	}
	return rx, tx
}

// skipInterface leaves out loopback and the interfaces the node's own tunnels
// create, so the reported traffic is what crossed the real network once rather
// than counted twice.
func skipInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "tun", "tap", "utun", "wg", "tailscale"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (c *Collector) uptime() uint64 {
	raw, err := os.ReadFile(c.path("proc", "uptime"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0
	}
	return uint64(seconds)
}

// tcpConnections counts established TCP sockets. It is a cheap proxy for how
// busy a node is, and it is what the panel shows next to the user count.
func (c *Collector) tcpConnections() uint32 {
	const established = "01" // TCP_ESTABLISHED in /proc/net/tcp
	var count uint32
	for _, file := range []string{"tcp", "tcp6"} {
		f, err := os.Open(c.path("proc", "net", file))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[0] == "sl" {
				continue
			}
			if fields[3] == established {
				count++
			}
		}
		_ = f.Close()
	}
	return count
}

// DiskUsage is split out because it needs a syscall rather than a file, and
// that is the one part of this package that differs per platform.
func (c *Collector) disk() (used, total uint64) {
	path := c.DiskPath
	if path == "" {
		path = c.path()
	}
	return diskUsage(path)
}

// String is for logs and for the "metrics" line of wn-agent status.
func (s Sample) String() string {
	return fmt.Sprintf("cpu=%.1f%% load=%.2f mem=%s/%s disk=%s/%s net=%s/%s up=%s conns=%d",
		s.CPUPercent, s.Load1,
		humanBytes(s.MemUsedBytes), humanBytes(s.MemTotalBytes),
		humanBytes(s.DiskUsedBytes), humanBytes(s.DiskTotalBytes),
		humanBytes(s.NetRxBytes), humanBytes(s.NetTxBytes),
		time.Duration(s.UptimeSeconds)*time.Second, s.TCPConns)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	for _, suffix := range []string{"K", "M", "G", "T", "P"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fE", value)
}
