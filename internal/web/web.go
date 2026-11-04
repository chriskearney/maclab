// Package web serves the lab's browser UI and the Omarchy themes it wears.
package web

import (
	"bufio"
	"embed"
	"encoding/json"
	"html"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed static
var static embed.FS

// Theme is one Omarchy theme's color tokens, from its colors.toml.
type Theme struct {
	Name    string            `json:"name"`
	Title   string            `json:"title"`
	Mode    string            `json:"mode"`
	Colors  map[string]string `json:"colors"`
	Current bool              `json:"current"`
	HasBG   bool              `json:"has_background"`
	dir     string
}

// Omarchy keeps shipped themes in the install and user themes in config;
// a user theme with the same name wins, as it does in Omarchy.
func themeDirs() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".local/share/omarchy/themes"),
		filepath.Join(home, ".config/omarchy/themes"),
	}
}

func currentTheme() string {
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".local/state/omarchy/current/theme.name"))
	return slug(strings.TrimSpace(string(b)))
}

var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	return strings.Trim(reSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func title(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

// parseColors reads the flat `key = "value"` TOML Omarchy uses for colors.
func parseColors(path string) (map[string]string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	colors := map[string]string{}
	mode := "dark"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if i := strings.Index(v, "#"); i > 0 && strings.HasPrefix(v, `"`) && strings.Count(v[:i], `"`) >= 2 {
			v = strings.TrimSpace(v[:i]) // trailing comment
		}
		v = strings.Trim(v, `"'`)
		if k == "mode" {
			mode = v
			continue
		}
		if strings.HasPrefix(v, "#") && (len(v) == 7 || len(v) == 9) {
			colors[k] = v
		}
	}
	return colors, mode, sc.Err()
}

func loadThemes() []*Theme {
	byName := map[string]*Theme{}
	for _, dir := range themeDirs() {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			colors, mode, err := parseColors(filepath.Join(p, "colors.toml"))
			if err != nil || colors["background"] == "" || colors["foreground"] == "" {
				continue
			}
			name := slug(e.Name())
			byName[name] = &Theme{Name: name, Title: title(name), Mode: mode, Colors: colors, dir: p, HasBG: firstBackground(p) != ""}
		}
	}
	cur := currentTheme()
	var out []*Theme
	for _, t := range byName {
		t.Current = t.Name == cur
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func firstBackground(dir string) string {
	ents, _ := os.ReadDir(filepath.Join(dir, "backgrounds"))
	var imgs []string
	for _, e := range ents {
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".png", ".jpg", ".jpeg", ".webp":
			imgs = append(imgs, filepath.Join(dir, "backgrounds", e.Name()))
		}
	}
	sort.Strings(imgs)
	if len(imgs) == 0 {
		return ""
	}
	return imgs[0]
}

// Register adds the UI and theme routes. Themes and wallpapers are public so
// the lock screen can wear them before anyone has signed in. base is the
// path prefix labd is served under, "" for none: the page says it in its
// <base>, and every URL the UI uses is relative to that.
func Register(m *http.ServeMux, base string) {
	sub, _ := fs.Sub(static, "static")
	files := http.FileServer(http.FS(sub))
	m.Handle("GET /ui/", http.StripPrefix("/ui/", cache(files)))
	index := IndexHTML(base)
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(index)
	})
	m.HandleFunc("GET /api/themes", func(w http.ResponseWriter, r *http.Request) {
		themes := loadThemes()
		if themes == nil {
			themes = []*Theme{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(themes)
	})
	m.HandleFunc("GET /api/themes/{name}/background", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var path string
		if name == "current" || name == currentTheme() {
			home, _ := os.UserHomeDir()
			if p, err := filepath.EvalSymlinks(filepath.Join(home, ".local/state/omarchy/current/background")); err == nil {
				path = p
			}
		}
		if path == "" {
			for _, t := range loadThemes() {
				if t.Name == name {
					path = firstBackground(t.dir)
				}
			}
		}
		if path == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, path)
	})
}

func cache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// IndexHTML is the UI's page for a labd served under base: its <base> is
// base/, against which the page's relative URLs resolve.
func IndexHTML(base string) []byte {
	b, _ := static.ReadFile("static/index.html")
	tag := `<base href="` + html.EscapeString(base) + `/">`
	return []byte(strings.Replace(string(b), "<head>\n", "<head>\n"+tag+"\n", 1))
}
