package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// builderLab is a labd with no Macs, for builder tests: the shared builder
// token is "bld", the first Maintainer's token "mtok".
type builderLab struct {
	t   *testing.T
	ctx context.Context
	dir string
	s   *Server
	url string
	n   int
}

func newBuilderLab(t *testing.T) *builderLab {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b := &builderLab{t: t, ctx: ctx, dir: t.TempDir()}
	b.start()
	return b
}

// start (re)starts labd on b.dir.
func (b *builderLab) start() {
	s, err := New(b.ctx, Config{DataDir: b.dir, FirstMaintainer: harnessMaintainer, FirstMaintainerToken: "mtok", BuilderToken: "bld"},
		log.New(io.Discard, "", 0))
	if err != nil {
		b.t.Fatal(err)
	}
	hs := httptest.NewServer(s.Handler())
	b.t.Cleanup(hs.Close)
	b.s, b.url = s, hs.URL
}

// do sends a request with a bearer token and returns the status and body.
func (b *builderLab) do(ctx context.Context, method, path, token string, body io.Reader) (int, []byte) {
	req, _ := http.NewRequestWithContext(ctx, method, b.url+path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (b *builderLab) call(method, path, token string, body any, out any) int {
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	code, data := b.do(b.ctx, method, path, token, rd)
	if out != nil {
		json.Unmarshal(data, out)
	}
	return code
}

func (b *builderLab) addBuilder(name string, kinds ...string) string {
	var nb api.NewBuilder
	if code := b.call("POST", "/api/builders", "mtok", api.BuilderRequest{Name: name, Kinds: kinds}, &nb); code != 200 {
		b.t.Fatalf("add builder %s: %d", name, code)
	}
	return nb.Token
}

// queue queues a build of kind ("" kernel, "package") with an input artifact
// of its own.
func (b *builderLab) queue(kind string) *api.Build {
	b.n++
	in, _, err := b.s.storeArtifact(strings.NewReader(fmt.Sprintf("input %d", b.n)))
	if err != nil {
		b.t.Fatal(err)
	}
	bd := &api.Build{ID: fmt.Sprintf("b%04d", b.n), Key: fmt.Sprintf("key%04d", b.n), Kind: kind,
		Source: api.Source{Repo: "https://example.invalid/linux", SHA: strings.Repeat("a", 40)}, State: api.BuildQueued, Created: b.s.now()}
	if kind == api.BuildPackage {
		bd.Recipe = in
	} else {
		bd.ConfigSHA = in
	}
	if _, err := b.s.queueBuild(bd, true); err != nil {
		b.t.Fatal(err)
	}
	return bd
}

// poll polls once as token, giving up after wait.
func (b *builderLab) poll(token, query string, wait time.Duration) (api.BuildAssignment, int) {
	ctx, cancel := context.WithTimeout(b.ctx, wait)
	defer cancel()
	var a api.BuildAssignment
	code, data := b.do(ctx, "POST", "/api/builder/poll?"+query, token, nil)
	json.Unmarshal(data, &a)
	return a, code
}

func (b *builderLab) build(id string) *api.Build {
	bd, err := b.s.getBuild(id)
	if err != nil {
		b.t.Fatal(err)
	}
	return bd
}

func (b *builderLab) upload(token, build, content string) (string, int) {
	var up struct{ SHA256 string }
	code, data := b.do(b.ctx, "POST", "/api/builder/artifacts?build="+build, token, strings.NewReader(content))
	json.Unmarshal(data, &up)
	return up.SHA256, code
}

func (b *builderLab) done(token, build string, res api.BuildResult) int {
	return b.call("POST", "/api/builder/builds/"+build+"/done", token, res, nil)
}

func TestAddingANamedBuilder(t *testing.T) {
	b := newBuilderLab(t)
	tok := b.addBuilder("m5mbp")
	if !strings.HasPrefix(tok, "bldr_") || len(tok) != 45 {
		t.Fatalf("token %q", tok)
	}
	// labd keeps only the token's hash.
	for _, f := range []string{"labd.db", "labd.db-wal"} {
		if raw, _ := os.ReadFile(filepath.Join(b.dir, f)); bytes.Contains(raw, []byte(tok)) {
			t.Fatalf("%s holds the token", f)
		}
	}
	var me api.BuilderSelf
	if code := b.call("GET", "/api/builder/self", tok, nil, &me); code != 200 || me.Name != "m5mbp" || me.Shared ||
		strings.Join(me.Kinds, ",") != "kernel" {
		t.Fatalf("self: %d %+v", code, me)
	}
	if code := b.call("GET", "/api/builder/self", "bld", nil, &me); code != 200 || !me.Shared {
		t.Fatalf("shared self: %d %+v", code, me)
	}
	var l []api.BuilderStatus
	if b.call("GET", "/api/builders", "mtok", nil, &l); len(l) != 1 || l[0].Host != "m5mbp" || !l[0].Registered ||
		l[0].AddedBy != harnessMaintainer || l[0].Alive || !l[0].LastSeen.IsZero() {
		t.Fatalf("list %+v", l)
	}
	for _, c := range []struct {
		req  api.BuilderRequest
		code int
	}{
		{api.BuilderRequest{Name: "m5mbp"}, 409},
		{api.BuilderRequest{Name: "../x"}, 400},
		{api.BuilderRequest{Name: ""}, 400},
		{api.BuilderRequest{Name: "ok", Kinds: []string{"kernel", "root"}}, 400},
	} {
		if code := b.call("POST", "/api/builders", "mtok", c.req, nil); code != c.code {
			t.Errorf("%+v: %d, want %d", c.req, code, c.code)
		}
	}
	// Only a Maintainer adds or removes builders.
	for _, token := range []string{"", tok, "bld", "bldr_" + strings.Repeat("0", 40)} {
		if code := b.call("POST", "/api/builders", token, api.BuilderRequest{Name: "x"}, nil); code != 401 {
			t.Errorf("add with %q: %d", token, code)
		}
		if code := b.call("DELETE", "/api/builders/m5mbp", token, nil, nil); code != 401 {
			t.Errorf("remove with %q: %d", token, code)
		}
	}
}

// A named token works on the builder routes only.
func TestNamedBuilderTokenOpensNothingElse(t *testing.T) {
	b := newBuilderLab(t)
	tok := b.addBuilder("m5mbp", "kernel", "package")
	for _, r := range []struct{ method, path string }{
		{"GET", "/api/devices"}, {"GET", "/api/jobs"}, {"POST", "/api/jobs"}, {"POST", "/api/artifacts"},
		{"POST", "/api/builds"}, {"GET", "/api/builds"}, {"GET", "/api/builders"}, {"GET", "/api/maintainers"},
		{"POST", "/api/maintainers"}, {"POST", "/api/enroll-tokens"}, {"POST", "/api/agent/checkin"},
		{"GET", "/api/agent/artifacts/" + strings.Repeat("a", 64)}, {"GET", "/api/join/terms"},
	} {
		if code, _ := b.do(b.ctx, r.method, r.path, tok, strings.NewReader("{}")); code < 400 {
			t.Errorf("%s %s with a named builder's token: %d", r.method, r.path, code)
		}
	}
}

func TestNamedBuilderWorksOnlyOnItsOwnBuild(t *testing.T) {
	b := newBuilderLab(t)
	a, other := b.addBuilder("a"), b.addBuilder("b")
	k := b.queue("")
	stray := b.queue("") // another queued build's input
	got, code := b.poll(a, "host=evil&kinds=kernel", 5*time.Second)
	if code != 200 || got.Build.ID != k.ID || got.Build.Builder != "a" || b.build(k.ID).Builder != "a" {
		t.Fatalf("poll: %d %+v", code, got.Build)
	}
	// The other builder can't touch it.
	if code := b.call("POST", "/api/builder/builds/"+k.ID+"/progress", other, api.BuildProgress{Lines: []string{"x"}}, nil); code != 403 {
		t.Errorf("other's progress: %d", code)
	}
	if code := b.done(other, k.ID, api.BuildResult{Error: "x"}); code != 403 {
		t.Errorf("other's done: %d", code)
	}
	if _, code := b.upload(other, k.ID, "x"); code != 403 {
		t.Errorf("other's upload: %d", code)
	}
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+k.ConfigSHA, other, nil); code != 404 {
		t.Errorf("other read the input: %d", code)
	}
	// Its builder reads its own input and nothing else.
	if code, body := b.do(b.ctx, "GET", "/api/builder/artifacts/"+k.ConfigSHA, a, nil); code != 200 || !strings.HasPrefix(string(body), "input") {
		t.Errorf("own input: %d %q", code, body)
	}
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+stray.ConfigSHA, a, nil); code != 404 {
		t.Errorf("read another build's input: %d", code)
	}
	// An upload must name the build.
	if _, code := b.upload(a, "", "x"); code != 403 {
		t.Errorf("upload naming no build: %d", code)
	}
	if code := b.call("POST", "/api/builder/builds/"+k.ID+"/progress", a, api.BuildProgress{Lines: []string{"@@stage build", "CC x.o"}}, nil); code != 200 {
		t.Errorf("progress: %d", code)
	}
	sha, code := b.upload(a, k.ID, "kernel bytes")
	if code != 200 {
		t.Fatalf("upload: %d", code)
	}
	if code := b.done(a, k.ID, api.BuildResult{Release: "7.2-x", Artifact: sha, Seconds: 1}); code != 204 {
		t.Fatalf("done: %d", code)
	}
	if bd := b.build(k.ID); bd.State != api.BuildDone || bd.Artifact != sha || bd.Builder != "a" {
		t.Fatalf("finished: %+v", bd)
	}
	// Once done, the build and its input are no longer its.
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+k.ConfigSHA, a, nil); code != 404 {
		t.Errorf("input after done: %d", code)
	}
	if _, code := b.upload(a, k.ID, "more"); code != 403 {
		t.Errorf("upload after done: %d", code)
	}
}

// done may name only what the builder uploaded for that build.
func TestNamedBuilderCantNameOthersOutputs(t *testing.T) {
	b := newBuilderLab(t)
	a := b.addBuilder("a")
	k1, k2 := b.queue(""), b.queue("")
	b.poll(a, "", 5*time.Second)
	b.poll(a, "", 5*time.Second)
	own1, _ := b.upload(a, k1.ID, "k1 kernel")
	elsewhere, _, _ := b.s.storeArtifact(strings.NewReader("someone else's kernel"))
	for _, c := range []struct {
		name string
		res  api.BuildResult
		id   string
	}{
		{"an artifact it never uploaded", api.BuildResult{Artifact: elsewhere}, k2.ID},
		{"its upload for another build", api.BuildResult{Artifact: own1}, k2.ID},
	} {
		k := b.queue("")
		b.poll(a, "", 5*time.Second)
		own, _ := b.upload(a, k.ID, "own "+c.name)
		res := c.res
		res.Files = []api.BuildFile{{Name: "x.pkg", SHA256: own}}
		if code := b.done(a, k.ID, res); code != 204 {
			t.Fatalf("%s: done %d", c.name, code)
		}
		if bd := b.build(k.ID); bd.State != api.BuildFailed || !strings.Contains(bd.Error, "did not upload") {
			t.Errorf("%s: %s %q", c.name, bd.State, bd.Error)
		}
	}
}

func TestNamedBuilderKinds(t *testing.T) {
	b := newBuilderLab(t)
	kernelOnly, pkgOnly := b.addBuilder("k", "kernel"), b.addBuilder("p", "package")
	pkg := b.queue(api.BuildPackage)
	if a, code := b.poll(kernelOnly, "kinds=kernel,package", 1500*time.Millisecond); code == 200 {
		t.Fatalf("kernel-only builder got %+v", a.Build)
	}
	if a, code := b.poll(pkgOnly, "kinds=kernel,package", 5*time.Second); code != 200 || a.Build.ID != pkg.ID {
		t.Fatalf("package builder: %d %+v", code, a.Build)
	}
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+pkg.Recipe, pkgOnly, nil); code != 200 {
		t.Errorf("recipe: %d", code)
	}
	k := b.queue("")
	if a, code := b.poll(pkgOnly, "kinds=kernel,package", 1500*time.Millisecond); code == 200 {
		t.Fatalf("package-only builder got kernel build %+v", a.Build)
	}
	if a, code := b.poll(kernelOnly, "", 5*time.Second); code != 200 || a.Build.ID != k.ID {
		t.Fatalf("kernel builder: %d %+v", code, a.Build)
	}
}

func TestRemovingABuilder(t *testing.T) {
	b := newBuilderLab(t)
	a := b.addBuilder("a")
	k := b.queue("")
	b.poll(a, "", 5*time.Second)
	// An open long poll ends when the builder is removed.
	polled := make(chan int, 1)
	go func() { _, code := b.poll(a, "", 30*time.Second); polled <- code }()
	time.Sleep(300 * time.Millisecond)
	var rm api.RemovedBuilder
	if code := b.call("DELETE", "/api/builders/a", "mtok", nil, &rm); code != 200 || rm.Removed != "a" ||
		strings.Join(rm.FailedBuilds, ",") != k.ID {
		t.Fatalf("remove: %d %+v", code, rm)
	}
	select {
	case code := <-polled:
		if code == 200 {
			t.Fatal("a removed builder's poll got a build")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open poll outlived its builder")
	}
	if bd := b.build(k.ID); bd.State != api.BuildFailed || bd.Error != "builder a was removed by "+harnessMaintainer {
		t.Fatalf("its build: %s %q", bd.State, bd.Error)
	}
	if code := b.call("GET", "/api/builder/self", a, nil, nil); code != 401 {
		t.Errorf("removed token: %d", code)
	}
	if code := b.call("DELETE", "/api/builders/a", "mtok", nil, nil); code != 404 {
		t.Errorf("remove again: %d", code)
	}
	var l []api.BuilderStatus
	if b.call("GET", "/api/builders", "mtok", nil, &l); len(l) != 0 {
		t.Errorf("a removed builder is still listed: %+v", l)
	}
	// The same name again is a new builder: the old token stays dead, and the
	// new one inherits nothing, not even a build recorded under its name.
	a2 := b.addBuilder("a")
	if code := b.call("GET", "/api/builder/self", a, nil, nil); code != 401 {
		t.Errorf("old token after re-adding the name: %d", code)
	}
	ghost := b.queue("")
	ghost.State, ghost.Builder = api.BuildRunning, "a"
	b.s.saveBuild(ghost)
	if code := b.call("POST", "/api/builder/builds/"+ghost.ID+"/progress", a2, api.BuildProgress{Lines: []string{"x"}}, nil); code != 403 {
		t.Errorf("new builder reported on a build it never took: %d", code)
	}
	if code := b.done(a2, ghost.ID, api.BuildResult{Error: "x"}); code != 403 {
		t.Errorf("new builder finished a build it never took: %d", code)
	}
	if code := b.done(a2, k.ID, api.BuildResult{Error: "x"}); code != 403 {
		t.Errorf("new builder finished the old one's build: %d", code)
	}
}

// Removing a builder ends its upload at once, even one whose sender has
// stalled mid-body and sends nothing more, and records nothing.
func TestRemovingABuilderMidUpload(t *testing.T) {
	b := newBuilderLab(t)
	a := b.addBuilder("a")
	k := b.queue("")
	b.poll(a, "", 5*time.Second)
	pr, pw := io.Pipe()
	defer pw.Close()
	answered := make(chan int, 1)
	go func() {
		code, _ := b.do(b.ctx, "POST", "/api/builder/artifacts?build="+k.ID, a, pr)
		answered <- code
	}()
	pw.Write(bytes.Repeat([]byte("k"), 1<<16))
	time.Sleep(300 * time.Millisecond) // labd has read that and waits for more
	if code := b.call("DELETE", "/api/builders/a", "mtok", nil, nil); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	select {
	case code := <-answered:
		if code == 200 {
			t.Fatal("a removed builder's upload was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled upload outlived its builder")
	}
	b.s.builds.state.Lock()
	cl := b.s.builds.claims[k.ID]
	b.s.builds.state.Unlock()
	if cl != nil {
		t.Fatalf("claim survived removal: %+v", cl)
	}
	if bd := b.build(k.ID); bd.State != api.BuildFailed {
		t.Fatalf("build %s", bd.State)
	}
}

// Removing by generation removes only that generation, never a builder
// added under the same name since.
func TestRemovingABuilderByGeneration(t *testing.T) {
	b := newBuilderLab(t)
	var first api.NewBuilder
	b.call("POST", "/api/builders", "mtok", api.BuilderRequest{Name: "a"}, &first)
	if len(first.Generation) != 32 {
		t.Fatalf("generation %q", first.Generation)
	}
	b.call("DELETE", "/api/builders/a", "mtok", nil, nil)
	second := b.addBuilder("a")
	if code := b.call("DELETE", "/api/builders/a?generation="+first.Generation, "mtok", nil, nil); code != 409 {
		t.Fatalf("stale generation: %d", code)
	}
	if code := b.call("GET", "/api/builder/self", second, nil, nil); code != 200 {
		t.Fatalf("the newer builder after a stale removal: %d", code)
	}
	if code := b.call("DELETE", "/api/builders/zz?generation="+first.Generation, "mtok", nil, nil); code != 404 {
		t.Fatalf("no such builder: %d", code)
	}
	var nb api.NewBuilder
	b.call("POST", "/api/builders", "mtok", api.BuilderRequest{Name: "c"}, &nb)
	if code := b.call("DELETE", "/api/builders/c?generation="+nb.Generation, "mtok", nil, nil); code != 200 {
		t.Fatalf("own generation: %d", code)
	}
	if code := b.call("GET", "/api/builder/self", nb.Token, nil, nil); code != 401 {
		t.Fatalf("removed by generation, token still works: %d", code)
	}
}

// A builder removed while it polls never ends up holding a build.
func TestRemoveRacesClaim(t *testing.T) {
	b := newBuilderLab(t)
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("r%d", i)
		tok := b.addBuilder(name)
		k := b.queue("")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); b.poll(tok, "", 3*time.Second) }()
		go func() { defer wg.Done(); b.call("DELETE", "/api/builders/"+name, "mtok", nil, nil) }()
		wg.Wait()
		if bd := b.build(k.ID); bd.State == api.BuildRunning {
			t.Fatalf("round %d: build %s runs on removed builder %s", i, bd.ID, bd.Builder)
		}
		b.s.builds.state.Lock()
		n := len(b.s.builds.claims)
		b.s.builds.state.Unlock()
		if n != 0 {
			t.Fatalf("round %d: %d claims left", i, n)
		}
		if bd := b.build(k.ID); bd.State == api.BuildQueued {
			bd.State = api.BuildCanceled // out of the next round's way
			b.s.saveBuild(bd)
		}
	}
}

// Builders polling at once never take the same build twice.
func TestConcurrentClaimsTakeEachBuildOnce(t *testing.T) {
	b := newBuilderLab(t)
	toks := []string{b.addBuilder("x"), b.addBuilder("y"), "bld"}
	const n = 12
	for i := 0; i < n; i++ {
		b.queue("")
	}
	var mu sync.Mutex
	took := map[string]int{}
	var wg sync.WaitGroup
	for i, tok := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				a, code := b.poll(tok, fmt.Sprintf("host=shared%d", i), 1500*time.Millisecond)
				if code != 200 {
					return
				}
				mu.Lock()
				took[a.Build.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(took) != n {
		t.Fatalf("%d builds taken, want %d", len(took), n)
	}
	for id, c := range took {
		if c != 1 {
			t.Errorf("%s taken %d times", id, c)
		}
	}
}

func TestNamedUploadCap(t *testing.T) {
	old := builderUploadMax
	builderUploadMax = 1024
	defer func() { builderUploadMax = old }()
	b := newBuilderLab(t)
	a := b.addBuilder("a")
	k := b.queue("")
	b.poll(a, "", 5*time.Second)
	// No Content-Length: the cap holds while the body streams.
	pr, pw := io.Pipe()
	go func() { pw.Write(bytes.Repeat([]byte("x"), 4096)); pw.Close() }()
	if code, _ := b.do(b.ctx, "POST", "/api/builder/artifacts?build="+k.ID, a, pr); code != 413 {
		t.Fatalf("over the cap: %d", code)
	}
	b.s.builds.state.Lock()
	n := len(b.s.builds.claims[k.ID].uploads)
	b.s.builds.state.Unlock()
	if n != 0 {
		t.Fatalf("%d uploads recorded", n)
	}
	if _, code := b.upload(a, k.ID, "small"); code != 200 {
		t.Fatalf("under the cap: %d", code)
	}
}

// A named builder's claim does not survive a labd restart; the shared
// token's builds keep running, as before.
func TestNamedClaimsEndOnRestart(t *testing.T) {
	b := newBuilderLab(t)
	a := b.addBuilder("a")
	named, shared := b.queue(""), b.queue("")
	b.poll(a, "", 5*time.Second)
	b.poll("bld", "host=controller", 5*time.Second)
	b.start()
	// Settled before labd serves: no later pass can touch a new claim.
	if bd := b.build(named.ID); bd.State != api.BuildFailed || !strings.Contains(bd.Error, "labd restarted") {
		t.Fatalf("named build after restart: %s %q", bd.State, bd.Error)
	}
	fresh := b.queue("")
	if got, code := b.poll(a, "", 5*time.Second); code != 200 || got.Build.ID != fresh.ID {
		t.Fatalf("claim after restart: %d %+v", code, got.Build)
	}
	time.Sleep(300 * time.Millisecond)
	if bd := b.build(fresh.ID); bd.State != api.BuildRunning {
		t.Fatalf("a claim made after the restart: %s %q", bd.State, bd.Error)
	}
	if code := b.call("POST", "/api/builder/builds/"+fresh.ID+"/progress", a, api.BuildProgress{Lines: []string{"x"}}, nil); code != 200 {
		t.Fatalf("progress on the fresh claim: %d", code)
	}
	if bd := b.build(shared.ID); bd.State != api.BuildRunning {
		t.Fatalf("shared build after restart: %s %q", bd.State, bd.Error)
	}
	if code := b.call("POST", "/api/builder/builds/"+named.ID+"/progress", a, api.BuildProgress{Lines: []string{"x"}}, nil); code != 403 {
		t.Errorf("progress after restart: %d", code)
	}
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+named.ConfigSHA, a, nil); code != 404 {
		t.Errorf("input after restart: %d", code)
	}
}

// The shared builder.token keeps its e92 rights, but may not pass itself off
// as a named builder.
func TestSharedTokenUnchanged(t *testing.T) {
	b := newBuilderLab(t)
	b.addBuilder("m5mbp")
	if _, code := b.poll("bld", "host=m5mbp", 1500*time.Millisecond); code != 409 {
		t.Fatalf("shared token as a named builder: %d", code)
	}
	k := b.queue("")
	a, code := b.poll("bld", "host=controller", 5*time.Second)
	if code != 200 || a.Build.ID != k.ID || b.build(k.ID).Builder != "controller" {
		t.Fatalf("shared poll: %d %+v", code, a.Build)
	}
	other, _, _ := b.s.storeArtifact(strings.NewReader("any artifact"))
	if code, _ := b.do(b.ctx, "GET", "/api/builder/artifacts/"+other, "bld", nil); code != 200 {
		t.Errorf("shared fetch: %d", code)
	}
	sha, code := b.upload("bld", "", "kernel")
	if code != 200 {
		t.Fatalf("shared upload: %d", code)
	}
	if code := b.done("bld", k.ID, api.BuildResult{Artifact: sha, Release: "7.2-x"}); code != 204 || b.build(k.ID).State != api.BuildDone {
		t.Fatalf("shared done: %d %s", code, b.build(k.ID).State)
	}
	var l []api.BuilderStatus
	b.call("GET", "/api/builders", "mtok", nil, &l)
	if len(l) != 2 || l[0].Host != "controller" || !l[0].Shared || !l[0].Alive || l[1].Host != "m5mbp" || !l[1].Registered {
		t.Fatalf("list %+v", l)
	}
}

// After a restart labd cleans up every Mac but one demonstrably never used.
func TestNeverUsed(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "lab.db"))
	if err != nil {
		t.Fatal(err)
	}
	pristine := api.Device{ID: "d1", Name: "m1", State: api.StateNew}
	if !neverUsed(st, pristine) {
		t.Fatal("a pristine enrollment counts as used")
	}
	for _, c := range []struct {
		name string
		d    func(*api.Device)
	}{
		{"active job", func(d *api.Device) { d.ActiveJob = "j1" }},
		{"known-good kernel", func(d *api.Device) { d.KnownGood = "7.2.11" }},
		{"ready", func(d *api.Device) { d.State = api.StateReady }},
		{"busy", func(d *api.Device) { d.State = api.StateBusy }},
		{"recovering", func(d *api.Device) { d.State = api.StateRecovering }},
		{"offline", func(d *api.Device) { d.State = api.StateOffline }},
		{"no name", func(d *api.Device) { d.Name = "" }},
	} {
		d := pristine
		c.d(&d)
		if neverUsed(st, d) {
			t.Errorf("%s: counts as never used", c.name)
		}
	}
	for i, j := range []api.Job{
		{State: api.JobDone, Outcome: api.OutcomePass},
		{State: api.JobDone, Outcome: api.OutcomeCanceled},
		{State: api.JobQueued},
	} {
		st2, _ := openStore(filepath.Join(t.TempDir(), "lab.db"))
		j.ID, j.Spec.Device, j.Created = fmt.Sprintf("j%d", i), "m1", time.Now()
		st2.saveJob(&j)
		if neverUsed(st2, pristine) {
			t.Errorf("history %s/%s: counts as never used", j.State, j.Outcome)
		}
	}
	st.db.Close()
	if neverUsed(st, pristine) {
		t.Error("a failed lookup counts as never used")
	}
}

// labd's startup decides from the stored record, before it clears the active
// job and turns busy Macs offline.
func TestStartupCleanupSkipsOnlyNeverUsedMacs(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "labd.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []api.Device{
		{ID: "1", Name: "pristine", State: api.StateNew},
		{ID: "2", Name: "midjob", State: api.StateBusy, ActiveJob: "j9"},
		{ID: "3", Name: "newwithjob", State: api.StateNew, ActiveJob: "j8"},
		{ID: "4", Name: "ready", State: api.StateReady, KnownGood: "7.2"},
		{ID: "5", Name: "history", State: api.StateNew},
	} {
		st.saveDevice(&d, "h"+d.ID)
	}
	st.saveJob(&api.Job{ID: "j1", Spec: api.JobSpec{Device: "history"}, State: api.JobDone, Outcome: api.OutcomeCanceled, Created: time.Now()})
	st.db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Config{DataDir: dir, FirstMaintainer: harnessMaintainer, FirstMaintainerToken: "mtok"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"pristine": false, "midjob": true, "newwithjob": true, "ready": true, "history": true} {
		v := s.dev(name)
		v.mu.Lock()
		got := v.dirty
		v.mu.Unlock()
		if got != want {
			t.Errorf("%s: dirty %v, want %v", name, got, want)
		}
	}
}
