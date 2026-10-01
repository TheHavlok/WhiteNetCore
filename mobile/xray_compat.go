package mobile

import (
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"time"

	"github.com/thehavlok/whitenet/internal/memprofile"
	"github.com/thehavlok/whitenet/internal/xray"
)

// xraySocksPort is the local port xray-core listens on. The two cores never
// run at the same time - one profile is active - so a fixed port is safe and
// keeps the packet path free of extra bookkeeping.
const xraySocksPort = 10808

const (
	xrayReadyTimeout  = 15 * time.Second
	xrayReadyInterval = 100 * time.Millisecond

	// Сколько ждём, пока предыдущее ядро отпустит локальный порт.
	portFreeTimeout = 5 * time.Second
)

// ShareLink is the gomobile-visible form of a parsed subscription link.
//
// The apps show Name, Protocol and Address in the profile list and store
// ConfigJSON in exactly the field that used to hold the WhiteNet YAML.
type ShareLink struct {
	Name string
	// Proto, а не Protocol: в Swift "protocol" — ключевое слово, и обращение
	// к такому полю пришлось бы писать через бэктики на каждом вызове.
	Proto      string
	Address    string
	Security   string
	Transport  string
	ConfigJSON string
}

// IsShareLink reports whether text looks like a vless://, vmess://, trojan://
// or ss:// link. Use it to decide whether pasted text is a profile at all.
func IsShareLink(text string) bool {
	return xray.IsShareLink(text)
}

// ParseShareLink turns one share link into a ready Xray configuration.
func ParseShareLink(text string) (*ShareLink, error) {
	parsed, err := xray.ParseShareLink(text)
	if err != nil {
		return nil, err
	}

	return &ShareLink{
		Name:       parsed.Name,
		Proto:      parsed.Protocol,
		Address:    parsed.Address,
		Security:   parsed.Security,
		Transport:  parsed.Transport,
		ConfigJSON: parsed.ConfigJSON,
	}, nil
}

// IsXrayConfig tells the two profile formats apart by shape: an Xray config is
// JSON, a WhiteNet profile is YAML. The platform layers therefore keep storing
// one opaque config string and never have to carry a type flag alongside it.
func IsXrayConfig(config string) bool {
	return strings.HasPrefix(strings.TrimSpace(config), "{")
}

// IsXrayRunning reports whether the Xray core is the active one.
func IsXrayRunning() bool {
	return xray.IsRunning()
}

// startXrayAndroid brings up xray-core and hands back the same Client handle
// the WhiteNet path returns, so tun2socks cannot tell the two apart.
func startXrayAndroid(configJSON string) (*Client, error) {
	memprofile.SetMobile(true)

	if err := startXrayCore(configJSON); err != nil {
		return nil, err
	}

	initTUNAndroid()
	activeClientAndroid = &Client{socksPort: xraySocksPort}

	return activeClientAndroid, nil
}

// startXrayIOS is the same for the packet tunnel extension.
func startXrayIOS(configJSON string) (*Client, error) {
	debug.SetGCPercent(20)
	debug.SetMemoryLimit(iosSoftMemoryLimit)
	memprofile.SetMobile(true)

	initTUN()

	if err := startXrayCore(configJSON); err != nil {
		return nil, err
	}

	activeClient = &Client{socksPort: xraySocksPort}

	return activeClient, nil
}

func startXrayCore(configJSON string) error {
	// Whatever was running before has to go first: the two cores would
	// otherwise fight over the SOCKS port, and on iOS over the memory budget.
	Stop()

	waitForPortFree(xraySocksPort, portFreeTimeout)

	if err := xray.Start(configJSON, xraySocksPort); err != nil {
		return err
	}

	if err := waitForSocks(xraySocksPort, xrayReadyTimeout); err != nil {
		xray.Stop()
		return err
	}

	log.Printf("Xray ready, SOCKS5 on 127.0.0.1:%d", xraySocksPort)

	return nil
}

// waitForPortFree blocks until nothing is listening on the local port.
//
// Профили сплошь и рядом используют один и тот же SOCKS-порт, а предыдущее
// ядро могло ещё не отпустить слушатель к моменту старта следующего. Без этого
// ожидания проверка готовности ниже успешно достучится до УМИРАЮЩЕГО
// слушателя: туннель отрапортует, что поднялся, хотя новое ядро так и не
// смогло занять порт — снаружи это выглядит как «подключено, но не работает».
func waitForPortFree(port int, timeout time.Duration) {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err != nil {
			return
		}

		_ = conn.Close()
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("port %s is still busy after %s - starting anyway", address, timeout)
}

// waitForSocks blocks until the local SOCKS listener accepts a connection.
func waitForSocks(port int, timeout time.Duration) error {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, xrayReadyInterval)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		time.Sleep(xrayReadyInterval)
	}

	return fmt.Errorf("xray: SOCKS listener on %s did not come up in %s", address, timeout)
}
