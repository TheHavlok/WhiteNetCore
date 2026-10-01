package hostmetrics

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeProc writes a /proc tree with known contents, so the parsing is tested
// without depending on the machine the tests run on.
func fakeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestMemoryUsesMemAvailable(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/meminfo": `MemTotal:        1000000 kB
MemFree:           50000 kB
MemAvailable:     400000 kB
Buffers:           20000 kB
Cached:           300000 kB
`,
	})
	c := &Collector{Root: root}
	used, total := c.memory()
	if total != 1000000*1024 {
		t.Errorf("total = %d", total)
	}
	// Used is total minus MemAvailable, not total minus MemFree: on a busy
	// box MemFree is always small because the kernel uses the rest as cache.
	if want := uint64(600000 * 1024); used != want {
		t.Errorf("used = %d, want %d", used, want)
	}
}

func TestMemoryFallsBackWithoutMemAvailable(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/meminfo": `MemTotal:        1000000 kB
MemFree:          100000 kB
Buffers:           50000 kB
Cached:           150000 kB
`,
	})
	used, total := (&Collector{Root: root}).memory()
	if total != 1000000*1024 {
		t.Errorf("total = %d", total)
	}
	if want := uint64(700000 * 1024); used != want {
		t.Errorf("used = %d, want %d", used, want)
	}
}

func TestMemoryMissingFile(t *testing.T) {
	used, total := (&Collector{Root: t.TempDir()}).memory()
	if used != 0 || total != 0 {
		t.Errorf("a missing meminfo should report zeros, got %d/%d", used, total)
	}
}

// The first CPU sample has nothing to compare against, and the second must
// reflect the delta between the two readings.
func TestCPUPercentNeedsTwoSamples(t *testing.T) {
	root := t.TempDir()
	statPath := filepath.Join(root, "proc", "stat")
	if err := os.MkdirAll(filepath.Dir(statPath), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(statPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// user nice system idle iowait irq softirq
	write("cpu  100 0 100 800 0 0 0\n")
	c := &Collector{Root: root}
	if got := c.cpuPercent(); got != 0 {
		t.Errorf("first sample = %v, want 0", got)
	}

	// 100 more busy ticks, 100 more idle: half busy.
	write("cpu  150 0 150 900 0 0 0\n")
	got := c.cpuPercent()
	if got < 49 || got > 51 {
		t.Errorf("second sample = %v, want about 50", got)
	}
}

// A counter that went backwards (a container restart, a wrapped counter) must
// not produce a spike.
func TestCPUPercentIgnoresGoingBackwards(t *testing.T) {
	root := t.TempDir()
	statPath := filepath.Join(root, "proc", "stat")
	_ = os.MkdirAll(filepath.Dir(statPath), 0o755)
	_ = os.WriteFile(statPath, []byte("cpu  1000 0 1000 8000 0\n"), 0o644)

	c := &Collector{Root: root}
	_ = c.cpuPercent()
	_ = os.WriteFile(statPath, []byte("cpu  10 0 10 80 0\n"), 0o644)
	if got := c.cpuPercent(); got != 0 {
		t.Errorf("after a reset the sample = %v, want 0", got)
	}
}

func TestNetworkSkipsLoopbackAndVirtual(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/net/dev": `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000000  100    0    0    0     0          0         0  1000000  100    0    0    0     0       0          0
  eth0: 5000     50     0    0    0     0          0         0  7000     70     0    0    0     0       0          0
  eth1: 1000     10     0    0    0     0          0         0  2000     20     0    0    0     0       0          0
docker0: 9999     99     0    0    0     0          0         0  9999     99     0    0    0     0       0          0
 tun0: 8888     88     0    0    0     0          0         0  8888     88     0    0    0     0       0          0
`,
	})
	rx, tx := (&Collector{Root: root}).network()
	// eth0 + eth1 only: loopback, docker0 and tun0 would double count the
	// node's own tunnels.
	if rx != 6000 || tx != 9000 {
		t.Errorf("rx/tx = %d/%d, want 6000/9000", rx, tx)
	}
}

func TestNetworkRespectsExplicitInterfaces(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/net/dev": `Inter-|   Receive  |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 5000     50     0    0    0     0          0         0  7000     70     0    0    0     0       0          0
  eth1: 1000     10     0    0    0     0          0         0  2000     20     0    0    0     0       0          0
`,
	})
	rx, tx := (&Collector{Root: root, NetInterfaces: []string{"eth1"}}).network()
	if rx != 1000 || tx != 2000 {
		t.Errorf("rx/tx = %d/%d, want 1000/2000", rx, tx)
	}
}

func TestUptimeAndLoad(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/uptime":  "123456.78 987654.32\n",
		"proc/loadavg": "0.42 0.35 0.30 1/234 5678\n",
	})
	c := &Collector{Root: root}
	if got := c.uptime(); got != 123456 {
		t.Errorf("uptime = %d", got)
	}
	if got := c.load1(); got < 0.41 || got > 0.43 {
		t.Errorf("load1 = %v", got)
	}
}

func TestTCPConnectionsCountsEstablishedOnly(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"proc/net/tcp": `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
   1: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 2
   2: 0100007F:1F90 0100007F:C351 01 00000000:00000000 00:00000000 00000000     0        0 3
   3: 0100007F:1F90 0100007F:C352 06 00000000:00000000 00:00000000 00000000     0        0 4
`,
		"proc/net/tcp6": `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 01
`,
	})
	// Two established in tcp (state 01), one in tcp6; listening (0A) and
	// time-wait (06) do not count.
	if got := (&Collector{Root: root}).tcpConnections(); got != 3 {
		t.Errorf("tcpConnections = %d, want 3", got)
	}
}

// On the machine running the tests, a real sample must come back with the
// numbers that the host can actually answer.
func TestCollectOnThisHost(t *testing.T) {
	c := &Collector{}
	first := c.Collect()
	if first.At.IsZero() {
		t.Error("sample has no timestamp")
	}
	if first.DiskTotalBytes == 0 && runtime.GOOS != "windows" {
		t.Error("disk total is zero on a real host")
	}
	// /proc only exists on Linux, so the rest is asserted there.
	if runtime.GOOS != "linux" {
		t.Skipf("skipping /proc assertions on %s", runtime.GOOS)
	}
	if first.MemTotalBytes == 0 {
		t.Error("memory total is zero on a real Linux host")
	}
	if first.UptimeSeconds == 0 {
		t.Error("uptime is zero on a real Linux host")
	}
	second := c.Collect()
	if second.NetRxBytes < first.NetRxBytes {
		t.Error("network counters went backwards between two samples")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0:                      "0B",
		512:                    "512B",
		1024:                   "1.0K",
		1536:                   "1.5K",
		1024 * 1024:            "1.0M",
		3 * 1024 * 1024 * 1024: "3.0G",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
