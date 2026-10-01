package app

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DistDir is where the panel looks for the binaries the installer downloads.
// The Docker image puts the Linux builds there; a panel running from source
// can be pointed at a directory with the same layout.
const DistDir = "/opt/whitenet/dist"

// distHandler serves the agent and core binaries.
//
// This is why a node only needs to reach the panel: the installer fetches the
// agent from here rather than from a release page, so an air-gapped or
// filtered node still installs. Only an explicit allow-list of names is
// served, so the handler cannot be turned into a file browser.
func (a *App) distHandler() http.Handler {
	dir := os.Getenv("WN_DIST_DIR")
	if dir == "" {
		dir = DistDir
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/dist/")
		if !allowedDistName(name) {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			a.log.Warn("an installer asked for a binary that is not published",
				"name", name, "dir", dir)
			http.Error(w, "that build is not published on this panel", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// The binaries change with every release, and a node fetching a stale
		// one would be a confusing failure.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, path)
	})
}

// allowedDistName is the exact set of names the installer asks for. Anything
// else is refused before it touches the filesystem, so no path can escape the
// directory and nothing unexpected can be downloaded.
func allowedDistName(name string) bool {
	switch name {
	case "wn-agent-linux-amd64", "wn-agent-linux-arm64",
		"whitenet-linux-amd64", "whitenet-linux-arm64":
		return true
	default:
		return false
	}
}
