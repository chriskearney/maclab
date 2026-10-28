package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// apiClient bounds every call, so a stream labd wrongly opens fails the
// test instead of holding it up.
var apiClient = &http.Client{Timeout: time.Minute}

var reMaintainerToken = regexp.MustCompile(`^mnt_[0-9a-f]{40}$`)

// as calls labd's HTTP API with the given bearer token ("" sends none).
func (l *lab) as(token, method, path string, body any) (*http.Response, string) {
	l.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, l.url+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(out)
}

// addMaintainer adds a Maintainer as the holder of token and returns what
// labd answered, token included.
func (l *lab) addMaintainer(token, name string) api.NewMaintainer {
	l.t.Helper()
	resp, body := l.as(token, "POST", "/api/maintainers", api.MaintainerRequest{Name: name})
	if resp.StatusCode != 200 {
		l.t.Fatalf("add Maintainer %s: %s %s", name, resp.Status, body)
	}
	var m api.NewMaintainer
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		l.t.Fatalf("add Maintainer %s: %v in %s", name, err, body)
	}
	var raw struct{ Added string }
	json.Unmarshal([]byte(body), &raw)
	if at, err := time.Parse(time.RFC3339, raw.Added); err != nil || l.s.now().Sub(at) > time.Hour {
		l.t.Fatalf("add Maintainer %s: added %q: %v", name, raw.Added, err)
	}
	return m
}

// maintainers lists the Maintainers as the holder of token.
func (l *lab) maintainers(token string) ([]api.Maintainer, string) {
	l.t.Helper()
	resp, body := l.as(token, "GET", "/api/maintainers", nil)
	if resp.StatusCode != 200 {
		l.t.Fatalf("list Maintainers: %s %s", resp.Status, body)
	}
	var ms []api.Maintainer
	if err := json.Unmarshal([]byte(body), &ms); err != nil {
		l.t.Fatalf("list Maintainers: %v in %s", err, body)
	}
	return ms, body
}

func maintainerNames(ms []api.Maintainer) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// waitLog waits for labd to log a line containing want.
func (l *lab) waitLog(want string) {
	l.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.logs.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	l.t.Fatalf("labd's log lacks %q:\n%s", want, l.logs.String())
}

func TestFirstMaintainerIsListedButNotTheirToken(t *testing.T) {
	l := newLab(t, false)
	ms, body := l.maintainers(harnessToken)
	if len(ms) != 1 || ms[0].Name != harnessMaintainer || ms[0].AddedBy != "" {
		t.Fatalf("Maintainers: %s", body)
	}
	var raw []map[string]any
	json.Unmarshal([]byte(body), &raw)
	added, _ := raw[0]["added"].(string)
	if at, err := time.Parse(time.RFC3339, added); err != nil || l.s.now().Sub(at) > time.Hour {
		t.Fatalf("added %q: %v", added, err)
	}
	if _, ok := raw[0]["token"]; ok || strings.Contains(body, `"`+harnessToken+`"`) || strings.Contains(body, sha256Hex(harnessToken)) {
		t.Fatalf("the list shows a token: %s", body)
	}
}

func TestAddedMaintainersTokenIsShownOnceAndWorks(t *testing.T) {
	l := newLab(t, false)
	grace := l.addMaintainer(harnessToken, "grace")
	if grace.Name != "grace" || grace.AddedBy != harnessMaintainer || !reMaintainerToken.MatchString(grace.Token) {
		t.Fatalf("new Maintainer: %+v", grace)
	}
	l.waitLog("Maintainer grace added by " + harnessMaintainer)

	if resp, body := l.as(grace.Token, "GET", "/api/devices", nil); resp.StatusCode != 200 {
		t.Fatalf("grace's token on a Maintainer route: %s %s", resp.Status, body)
	}
	l.addMaintainer(harnessToken, "Aaron") // sorts first by name, but was added last
	ms, body := l.maintainers(grace.Token)
	if got := strings.Join(maintainerNames(ms), ","); got != harnessMaintainer+",grace,Aaron" || ms[1].AddedBy != harnessMaintainer {
		t.Fatalf("Maintainers, oldest first: %s", body)
	}
	if strings.Contains(body, grace.Token) || strings.Contains(body, `"token"`) {
		t.Fatalf("the list shows a token: %s", body)
	}

	// any Maintainer can add one, and the new one's added_by is the acting Maintainer
	linus := l.addMaintainer(grace.Token, "linus")
	if linus.AddedBy != "grace" || linus.Token == grace.Token {
		t.Fatalf("Maintainer added by grace: %+v", linus)
	}
	l.waitLog("Maintainer linus added by grace")
}

func TestMaintainerTokenIsNotKeptInTheClear(t *testing.T) {
	l := newLab(t, false)
	grace := l.addMaintainer(harnessToken, "grace")
	filepath.WalkDir(l.s.cfg.DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(grace.Token)) {
			t.Errorf("%s holds grace's token", p)
		}
		return nil
	})
	if strings.Contains(l.logs.String(), grace.Token) {
		t.Error("labd logged grace's token")
	}
}

func TestMaintainerNamesAreChecked(t *testing.T) {
	l := newLab(t, false)
	for _, bad := range []string{"", "-grace", ".grace", "_grace", "grace hopper", "grace/hopper", "grâce", "grace\n", strings.Repeat("g", 65)} {
		if resp, body := l.as(harnessToken, "POST", "/api/maintainers", api.MaintainerRequest{Name: bad}); resp.StatusCode != 400 {
			t.Errorf("name %q: %s %s", bad, resp.Status, body)
		}
	}
	for _, good := range []string{"Grace.Hopper_1-x", "9", strings.Repeat("g", 64)} {
		if resp, body := l.as(harnessToken, "POST", "/api/maintainers", api.MaintainerRequest{Name: good}); resp.StatusCode != 200 {
			t.Errorf("name %q: %s %s", good, resp.Status, body)
		}
	}
	if resp, body := l.as(harnessToken, "POST", "/api/maintainers", api.MaintainerRequest{Name: "Grace.Hopper_1-x"}); resp.StatusCode != 409 {
		t.Errorf("an existing name again: %s %s", resp.Status, body)
	}
	if resp, body := l.as(harnessToken, "POST", "/api/maintainers", api.MaintainerRequest{Name: harnessMaintainer}); resp.StatusCode != 409 {
		t.Errorf("the first Maintainer's name again: %s %s", resp.Status, body)
	}
	if ms, body := l.maintainers(harnessToken); len(ms) != 4 {
		t.Errorf("refused names were added: %s", body)
	}
}

func TestRemovedMaintainersTokenIsRefused(t *testing.T) {
	l := newLab(t, false)
	grace := l.addMaintainer(harnessToken, "grace")
	if resp, _ := l.as(grace.Token, "GET", "/api/jobs", nil); resp.StatusCode != 200 {
		t.Fatalf("grace's token before removal: %s", resp.Status)
	}
	resp, body := l.as(harnessToken, "DELETE", "/api/maintainers/grace", nil)
	var removed map[string]string
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &removed) != nil || removed["removed"] != "grace" {
		t.Fatalf("remove grace: %s %s", resp.Status, body)
	}
	l.waitLog("Maintainer grace removed by " + harnessMaintainer)
	if resp, body := l.as(grace.Token, "GET", "/api/jobs", nil); resp.StatusCode != 401 || !strings.Contains(body, "not a Maintainer's token") {
		t.Fatalf("grace's token right after removal: %s %s", resp.Status, body)
	}
	if ms, body := l.maintainers(harnessToken); strings.Join(maintainerNames(ms), ",") != harnessMaintainer {
		t.Fatalf("Maintainers after removal: %s", body)
	}
	// a name freed by removal can be added again, with a new token
	again := l.addMaintainer(harnessToken, "grace")
	if again.Token == grace.Token {
		t.Fatal("re-added grace got her old token back")
	}
	if resp, _ := l.as(grace.Token, "GET", "/api/jobs", nil); resp.StatusCode != 401 {
		t.Fatalf("grace's old token after she was re-added: %s", resp.Status)
	}
}

func TestAnyMaintainerCanRemoveAnother(t *testing.T) {
	l := newLab(t, false)
	grace := l.addMaintainer(harnessToken, "grace")
	l.addMaintainer(harnessToken, "linus")
	if resp, body := l.as(grace.Token, "DELETE", "/api/maintainers/linus", nil); resp.StatusCode != 200 {
		t.Fatalf("grace removes linus: %s %s", resp.Status, body)
	}
	l.waitLog("Maintainer linus removed by grace")
}

func TestRemovingAnUnknownMaintainerIsNotFound(t *testing.T) {
	l := newLab(t, false)
	if resp, body := l.as(harnessToken, "DELETE", "/api/maintainers/nobody", nil); resp.StatusCode != 404 {
		t.Fatalf("remove nobody: %s %s", resp.Status, body)
	}
}

func TestLastMaintainerCannotBeRemoved(t *testing.T) {
	l := newLab(t, false)
	if resp, body := l.as(harnessToken, "DELETE", "/api/maintainers/"+harnessMaintainer, nil); resp.StatusCode != 409 {
		t.Fatalf("remove the only Maintainer: %s %s", resp.Status, body)
	}
	if resp, _ := l.as(harnessToken, "GET", "/api/devices", nil); resp.StatusCode != 200 {
		t.Fatalf("the only Maintainer's token after a refused removal: %s", resp.Status)
	}
	// with two, one can go; then the other is the last one
	grace := l.addMaintainer(harnessToken, "grace")
	if resp, body := l.as(grace.Token, "DELETE", "/api/maintainers/"+harnessMaintainer, nil); resp.StatusCode != 200 {
		t.Fatalf("grace removes %s: %s %s", harnessMaintainer, resp.Status, body)
	}
	if resp, body := l.as(grace.Token, "DELETE", "/api/maintainers/grace", nil); resp.StatusCode != 409 {
		t.Fatalf("remove grace, now the only Maintainer: %s %s", resp.Status, body)
	}
	if ms, body := l.maintainers(grace.Token); strings.Join(maintainerNames(ms), ",") != "grace" {
		t.Fatalf("Maintainers: %s", body)
	}
}

func TestRemovedMaintainersOpenRequestsAreClosed(t *testing.T) {
	l := newLab(t, true)
	l.baseline()
	// a build nobody takes, and a job waiting on it: both stay open
	src := gitRepo(t)
	resp, body := l.post("/api/builds", api.BuildRequest{Source: src, Device: l.name})
	var b api.Build
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &b) != nil || b.ID == "" {
		t.Fatalf("create build: %s %s", resp.Status, body)
	}
	j, _, err := l.s.Submit(api.JobSpec{Device: l.name, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	grace := l.addMaintainer(harnessToken, "grace")

	// cancelled before the harness closes its server, so a request labd
	// leaves open can't hold the test up
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	open := map[string]string{
		"stream":         "/api/stream",
		"console":        "/api/devices/" + l.name + "/console",
		"job wait":       "/api/jobs/" + j.ID + "/wait?timeout=3600",
		"build-log tail": "/api/builds/" + b.ID + "/log?follow=1",
	}
	type ended struct {
		what string
		code int
		body string
	}
	done := make(chan ended, len(open))
	for what, path := range open {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, "GET", l.url+path, nil)
			req.Header.Set("Authorization", "Bearer "+grace.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				done <- ended{what, 0, err.Error()}
				return
			}
			out, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			done <- ended{what, resp.StatusCode, string(out)}
		}()
	}
	select {
	case e := <-done:
		t.Fatalf("%s ended before grace was removed: %d %s", e.what, e.code, e.body)
	case <-time.After(time.Second):
	}

	if resp, body := l.as(harnessToken, "DELETE", "/api/maintainers/grace", nil); resp.StatusCode != 200 {
		t.Fatalf("remove grace: %s %s", resp.Status, body)
	}
	deadline := time.After(3 * time.Second)
	for len(open) > 0 {
		select {
		case e := <-done:
			delete(open, e.what)
			if e.what == "job wait" && e.code == 200 && strings.Contains(e.body, `"id"`) {
				var got api.Job
				if json.Unmarshal([]byte(e.body), &got) == nil && got.State != api.JobDone {
					t.Errorf("job wait answered grace with the unfinished job after her removal: %s", e.body)
				}
			}
		case <-deadline:
			t.Fatalf("grace's open requests were still open 3s after her removal: %v", open)
		}
	}
}
