// Package webui serves the admin interface, built into the binary.
//
// The React app is built by `npm run build` in web/ and its output is copied
// into dist/ before the Go build, so a deployment is one file: no static
// directory to keep in step with the binary, and no way for the two to drift.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// assets holds the built interface. The all: prefix keeps files whose names
// start with an underscore, which bundlers produce.
//
//go:embed all:dist
var assets embed.FS

// Built reports whether a real interface was embedded, rather than the
// placeholder that says how to build one.
func Built() bool {
	entries, err := fs.ReadDir(assets, "dist")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.Name() == "index.html" {
			return true
		}
	}
	return false
}

// Handler serves the interface under basePath.
//
// Anything that is not a file falls back to index.html, because the interface
// is a single page application: a deep link such as /admin/users is a route
// inside it, not a file on disk.
func Handler(basePath string) http.Handler {
	content, err := fs.Sub(assets, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "the admin interface was not built into this binary", http.StatusNotImplemented)
		})
	}
	if !Built() {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(placeholder))
		})
	}

	files := http.FileServer(http.FS(content))
	prefix := strings.TrimRight(basePath, "/")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(r.URL.Path, prefix)
		requested = strings.TrimPrefix(requested, "/")
		if requested == "" {
			requested = "index.html"
		}

		if requested == "index.html" {
			serveIndex(w, r, content, prefix)
			return
		}
		if _, err := fs.Stat(content, requested); err != nil {
			// A page cached before the <base> tag existed asks for an asset
			// relative to its route, so the same file arrives under a deeper
			// path. Retrying from the assets segment serves it rather than
			// handing back index.html with the wrong content type.
			if index := strings.Index(requested, "assets/"); index > 0 {
				retry := requested[index:]
				if _, err := fs.Stat(content, retry); err == nil {
					requested = retry
				} else {
					serveIndex(w, r, content, prefix)
					return
				}
			} else {
				// Not a file: hand the single page application its entry
				// point and let its router work out the rest.
				serveIndex(w, r, content, prefix)
				return
			}
		}

		// Hashed asset names never change meaning, so they can be cached hard;
		// index.html must not be, or a deploy would not reach anyone.
		if isHashedAsset(requested) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + requested
		files.ServeHTTP(w, r2)
	})
}

// basePlaceholder is what index.html carries until the panel fills it in.
const basePlaceholder = "__WN_BASE_PATH__"

func serveIndex(w http.ResponseWriter, r *http.Request, content fs.FS, basePath string) {
	raw, err := fs.ReadFile(content, "index.html")
	if err != nil {
		http.Error(w, "the admin interface was not built into this binary", http.StatusNotImplemented)
		return
	}
	// The interface has to know where it was mounted so its API calls and its
	// router agree with the server. Substituting it here is exact; letting the
	// interface guess from the URL breaks as soon as a route looks like a path
	// segment.
	page := strings.ReplaceAll(string(raw), basePlaceholder, basePath)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// isHashedAsset reports whether a name contains a content hash, which is what
// makes it safe to cache forever.
func isHashedAsset(name string) bool {
	if !strings.HasPrefix(name, "assets/") {
		return false
	}
	base := path.Base(name)
	// Vite names files like index-DiwrgTda.js: a dash, then at least eight
	// characters of hash, then the extension.
	dash := strings.LastIndex(base, "-")
	if dash < 0 {
		return false
	}
	rest := base[dash+1:]
	dot := strings.Index(rest, ".")
	return dot >= 8
}

const placeholder = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhiteNet panel</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;
      font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:#0b0f14;color:#e6edf3}
 .box{max-width:620px;padding:2rem}
 h1{font-size:1.3rem;margin:0 0 1rem}
 code{background:#11171f;border:1px solid #1e2630;border-radius:6px;padding:.15rem .4rem}
 pre{background:#11171f;border:1px solid #1e2630;border-radius:10px;padding:1rem;overflow:auto}
 p{color:#8b949e}
</style></head>
<body><div class="box">
 <h1>The admin interface is not in this binary</h1>
 <p>The API is running; only the compiled interface is missing. Build it and
 rebuild the binary:</p>
 <pre>cd web
npm install
npm run build          # writes into internal/panel/webui/dist
cd ..
go build ./cmd/wn-main</pre>
 <p>Or use the published image, which has it built in.</p>
</div></body></html>`
