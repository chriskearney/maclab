// Package client is the Go client for labd's Maintainer API, used by the lab CLI and MCP server.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/labhttp"
)

type Client struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	// CAFile is a PEM file of extra CA certificates for an https labd whose
	// certificate the system doesn't trust: a private CA, or labd's own
	// self-signed certificate (lab login --ca-file, MACLAB_CA_FILE).
	CAFile string `json:"ca_file,omitempty"`
	// AllowPlainHTTP lets an http:// URL reach labd on another machine (lab
	// login --allow-plain-http, MACLAB_ALLOW_PLAIN_HTTP=1). Without it plain
	// http reaches loopback only: the token would cross the network in the
	// clear. See labhttp.
	AllowPlainHTTP bool `json:"allow_plain_http,omitempty"`
	http           *http.Client
}

func ConfigPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "maclab", "client.json")
}

// Load reads MACLAB_URL / MACLAB_TOKEN / MACLAB_CA_FILE /
// MACLAB_ALLOW_PLAIN_HTTP, falling back to the saved config.
func Load() (*Client, error) {
	c := &Client{}
	if b, err := os.ReadFile(ConfigPath()); err == nil {
		json.Unmarshal(b, c)
	}
	if v := os.Getenv("MACLAB_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("MACLAB_TOKEN"); v != "" {
		c.Token = v
	}
	if v := os.Getenv("MACLAB_CA_FILE"); v != "" {
		c.CAFile = v
	}
	if os.Getenv("MACLAB_ALLOW_PLAIN_HTTP") == "1" {
		c.AllowPlainHTTP = true
	}
	if c.URL == "" || c.Token == "" {
		return nil, fmt.Errorf("not configured: run `lab login <labd-url> <your-maintainer-token>` or set MACLAB_URL and MACLAB_TOKEN")
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

// connect sets up c's HTTP client with labhttp's policy for c.URL.
func (c *Client) connect() error {
	if err := labhttp.CheckServer(c.URL, c.AllowPlainHTTP); err != nil {
		return err
	}
	p := labhttp.Policy{AllowPlainHTTP: c.AllowPlainHTTP}
	if c.CAFile != "" {
		b, err := labhttp.ReadCAFile(c.CAFile)
		if err != nil {
			return err
		}
		p.CAPEM = b
	}
	hc, err := p.Client(0)
	if err != nil {
		return err
	}
	c.http = hc
	return nil
}

func (c *Client) Save() error {
	b, _ := json.MarshalIndent(c, "", "  ")
	os.MkdirAll(filepath.Dir(ConfigPath()), 0o700)
	return os.WriteFile(ConfigPath(), b, 0o600)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return &StatusError{Code: resp.StatusCode, Msg: strings.TrimSpace(string(b))}
	}
	switch o := out.(type) {
	case nil:
	case *string:
		*o = string(b)
	default:
		return json.Unmarshal(b, out)
	}
	return nil
}

// StatusError is labd turning a request down: the HTTP status, and what labd said.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// Device mirrors labd's DeviceView.
type Device struct {
	api.Device
	Tier   int               `json:"tier"`
	Alive  bool              `json:"alive"`
	Queued int               `json:"queued"`
	Events []api.KernelEvent `json:"recent_events,omitempty"`
}

func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out []Device
	return out, c.do(ctx, "GET", "/api/devices", nil, &out)
}

func (c *Client) Device(ctx context.Context, name string) (*Device, error) {
	var out Device
	return &out, c.do(ctx, "GET", "/api/devices/"+url.PathEscape(name), nil, &out)
}

func (c *Client) PatchDevice(ctx context.Context, name string, p api.DevicePatch) (*Device, error) {
	var out Device
	return &out, c.do(ctx, "PATCH", "/api/devices/"+url.PathEscape(name), jsonBody(p), &out)
}

func (c *Client) EnrollToken(ctx context.Context, req api.EnrollTokenRequest) (*api.EnrollTokenResponse, error) {
	var out api.EnrollTokenResponse
	return &out, c.do(ctx, "POST", "/api/enroll-tokens", jsonBody(req), &out)
}

// RevokeEnrollTokens revokes a name's enrollment tokens, used or not, and
// says how many there were.
func (c *Client) RevokeEnrollTokens(ctx context.Context, name string) (int, error) {
	var out struct {
		Revoked int `json:"revoked"`
	}
	return out.Revoked, c.do(ctx, "DELETE", "/api/enroll-tokens/"+url.PathEscape(name), nil, &out)
}

func (c *Client) Maintainers(ctx context.Context) ([]api.Maintainer, error) {
	var out []api.Maintainer
	return out, c.do(ctx, "GET", "/api/maintainers", nil, &out)
}

// AddMaintainer returns the new Maintainer's token, which labd shows only this once.
func (c *Client) AddMaintainer(ctx context.Context, name string) (*api.NewMaintainer, error) {
	var out api.NewMaintainer
	return &out, c.do(ctx, "POST", "/api/maintainers", jsonBody(api.MaintainerRequest{Name: name}), &out)
}

func (c *Client) RemoveMaintainer(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", "/api/maintainers/"+url.PathEscape(name), nil, nil)
}

func (c *Client) Builders(ctx context.Context) ([]api.BuilderStatus, error) {
	var out []api.BuilderStatus
	return out, c.do(ctx, "GET", "/api/builders", nil, &out)
}

// AddBuilder returns the new builder's token, which labd shows only this once.
func (c *Client) AddBuilder(ctx context.Context, name string, kinds []string) (*api.NewBuilder, error) {
	var out api.NewBuilder
	return &out, c.do(ctx, "POST", "/api/builders", jsonBody(api.BuilderRequest{Name: name, Kinds: kinds}), &out)
}

// RemoveBuilder stops a named builder's token and fails the builds it was running.
func (c *Client) RemoveBuilder(ctx context.Context, name string) (*api.RemovedBuilder, error) {
	return c.RemoveBuilderGeneration(ctx, name, "")
}

// RemoveBuilderGeneration removes a named builder only while it is still the
// generation AddBuilder returned; "" removes whatever builder has the name.
func (c *Client) RemoveBuilderGeneration(ctx context.Context, name, generation string) (*api.RemovedBuilder, error) {
	var out api.RemovedBuilder
	path := "/api/builders/" + url.PathEscape(name)
	if generation != "" {
		path += "?generation=" + url.QueryEscape(generation)
	}
	return &out, c.do(ctx, "DELETE", path, nil, &out)
}

// EndEnrollment ends a Mac's enrollment: labd forgets it and revokes its device secret at once.
func (c *Client) EndEnrollment(ctx context.Context, name string) error {
	return c.do(ctx, "POST", "/api/devices/"+url.PathEscape(name)+"/end-enrollment", nil, nil)
}

func (c *Client) Lease(ctx context.Context, name, holder string, ttl time.Duration) (*api.Lease, error) {
	var out api.Lease
	return &out, c.do(ctx, "POST", "/api/devices/"+url.PathEscape(name)+"/lease", jsonBody(api.LeaseRequest{Holder: holder, TTLSec: int(ttl.Seconds())}), &out)
}

// ForgetDevice takes a Mac out of the lab; its jobs stay. force forgets it
// even while someone other than holder holds a lease on it, or its agent
// still checks in.
func (c *Client) ForgetDevice(ctx context.Context, name, holder string, force bool) error {
	q := url.Values{"holder": {holder}}
	if force {
		q.Set("force", "1")
	}
	return c.do(ctx, "DELETE", "/api/devices/"+url.PathEscape(name)+"?"+q.Encode(), nil, nil)
}

func (c *Client) Release(ctx context.Context, name, holder string) error {
	return c.do(ctx, "DELETE", "/api/devices/"+url.PathEscape(name)+"/lease?holder="+url.QueryEscape(holder), nil, nil)
}

func (c *Client) Reset(ctx context.Context, name, by string) (string, error) {
	var out string
	return out, c.do(ctx, "POST", "/api/devices/"+url.PathEscape(name)+"/reset?by="+url.QueryEscape(by), nil, &out)
}

func (c *Client) Serial(ctx context.Context, name string, lines int) (string, error) {
	var out string
	return out, c.do(ctx, "GET", fmt.Sprintf("/api/devices/%s/serial?lines=%d", url.PathEscape(name), lines), nil, &out)
}

// Audit is labd's copy of a Volunteer Mac's Audit log.
func (c *Client) Audit(ctx context.Context, name string) ([]api.AuditEntry, error) {
	var out []api.AuditEntry
	return out, c.do(ctx, "GET", "/api/devices/"+url.PathEscape(name)+"/audit", nil, &out)
}

func (c *Client) OOBStatus(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, "GET", "/api/devices/"+url.PathEscape(name)+"/oob", nil, &out)
}

// Upload sends a file to labd's artifact store and returns its sha256.
func (c *Client) Upload(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", c.URL+"/api/artifacts", f)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct{ SHA256 string }
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("upload: %s", strings.TrimSpace(string(b)))
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	return out.SHA256, nil
}

func (c *Client) Submit(ctx context.Context, spec api.JobSpec) (*api.Job, error) {
	if err := c.requireRecoveryMode(ctx, spec.RecoveryMode); err != nil {
		return nil, err
	}
	if spec.RecoveryTransaction != "" {
		var caps api.RecoveryCapabilities
		if e := c.do(ctx, "GET", "/api/recovery", nil, &caps); e != nil || !caps.TransactionIsolation {
			return nil, fmt.Errorf("controller lacks transaction recovery isolation; no job submitted")
		}
	}
	var out api.Job
	if spec.Mesa != nil {
		var caps api.MesaCapabilities
		if err := c.do(ctx, "GET", "/api/mesa", nil, &caps); err != nil {
			return nil, fmt.Errorf("controller does not support first-class Mesa; no job submitted: %w", err)
		}
		if caps.Schema != 1 || !caps.Staged || (spec.Mesa.OfficialGPU && !caps.OfficialGPU) {
			return nil, fmt.Errorf("controller Mesa capability/mode unavailable; no job submitted")
		}
	}
	route := "/api/jobs"
	if spec.Mesa != nil {
		route = "/api/mesa/jobs"
	}
	if err := c.do(ctx, "POST", route, jsonBody(spec), &out); err != nil {
		return nil, err
	}
	if out.Spec.RecoveryMode != spec.RecoveryMode || out.Spec.RecoveryTransaction != spec.RecoveryTransaction {
		return &out, fmt.Errorf("job %s returned different recovery_mode; do not retry blindly", out.ID)
	}
	if spec.Mesa != nil && out.Spec.Mesa == nil {
		return nil, fmt.Errorf("controller omitted Mesa request identity; job is not valid Mesa evidence")
	}
	return &out, nil
}

func (c *Client) Job(ctx context.Context, id string) (*api.Job, error) {
	var out api.Job
	return &out, c.do(ctx, "GET", "/api/jobs/"+url.PathEscape(id), nil, &out)
}

func (c *Client) Jobs(ctx context.Context, device string, limit int) ([]*api.Job, error) {
	var out []*api.Job
	return out, c.do(ctx, "GET", fmt.Sprintf("/api/jobs?device=%s&limit=%d", url.QueryEscape(device), limit), nil, &out)
}

// Wait long-polls until the job is done or timeout passes, returning its latest state.
// waitSlice is the longest one wait request lasts. A reverse proxy in front of
// labd may cut a request that sends nothing for a minute (nginx's default),
// so Wait asks again until timeout instead of holding one request open.
const waitSlice = 50 * time.Second

func (c *Client) Wait(ctx context.Context, id string, timeout time.Duration) (*api.Job, error) {
	deadline := time.Now().Add(timeout)
	for {
		slice := min(time.Until(deadline), waitSlice)
		var out api.Job
		err := c.do(ctx, "GET", fmt.Sprintf("/api/jobs/%s/wait?timeout=%d", url.PathEscape(id), max(int(slice.Seconds()), 1)), nil, &out)
		if err != nil || out.State == api.JobDone || time.Until(deadline) <= 0 {
			return &out, err
		}
	}
}

// Publish uploads a job's omarchy-m-test report and returns its page.
func (c *Client) Publish(ctx context.Context, id string) (string, error) {
	var out struct {
		ReportURL string `json:"report_url"`
	}
	err := c.do(ctx, "POST", "/api/jobs/"+url.PathEscape(id)+"/publish", nil, &out)
	return out.ReportURL, err
}

func (c *Client) Cancel(ctx context.Context, id string) (string, error) {
	var out string
	return out, c.do(ctx, "POST", "/api/jobs/"+url.PathEscape(id)+"/cancel", nil, &out)
}

// Retry queues a finished job again as a new job, held by holder.
func (c *Client) Retry(ctx context.Context, id, holder string) (*api.Job, error) {
	var out api.Job
	return &out, c.do(ctx, "POST", "/api/jobs/"+url.PathEscape(id)+"/retry?holder="+url.QueryEscape(holder), nil, &out)
}

// Exclude sets a finished job aside in every lab gate report, with the
// reason and who asks, until ClearExclusion clears it.
func (c *Client) Exclude(ctx context.Context, id, reason, by string) (*api.Job, error) {
	var out api.Job
	return &out, c.do(ctx, "POST", "/api/jobs/"+url.PathEscape(id)+"/exclude", jsonBody(api.ExcludeRequest{Reason: reason, By: by}), &out)
}

// ClearExclusion counts a job Exclude set aside in lab gate again.
func (c *Client) ClearExclusion(ctx context.Context, id string) (*api.Job, error) {
	var out api.Job
	return &out, c.do(ctx, "DELETE", "/api/jobs/"+url.PathEscape(id)+"/exclude", nil, &out)
}

func (c *Client) File(ctx context.Context, id, name string) ([]byte, error) {
	var out string
	err := c.do(ctx, "GET", "/api/jobs/"+url.PathEscape(id)+"/files/"+name, nil, &out)
	return []byte(out), err
}

// Gate reports whether a kernel (build id or sha256 prefix) passed on every
// required chip family; no families means all of them. volunteers counts
// volunteers' Macs too, and exclude sets those jobs of the kernel aside for
// this report only, besides those Exclude set aside.
func (c *Client) Gate(ctx context.Context, kernel string, families []string, volunteers bool, exclude []string) (*api.GateReport, error) {
	var out api.GateReport
	q := "?families=" + url.QueryEscape(strings.Join(families, ","))
	if volunteers {
		q += "&volunteers=1"
	}
	if len(exclude) > 0 {
		q += "&exclude=" + url.QueryEscape(strings.Join(exclude, ","))
	}
	return &out, c.do(ctx, "GET", "/api/gate/"+url.PathEscape(kernel)+q, nil, &out)
}

// ConsoleArm puts the Mac's debug UART into serial mode.
func (c *Client) ConsoleArm(ctx context.Context, name string) error {
	return c.do(ctx, "POST", "/api/devices/"+url.PathEscape(name)+"/console/arm", nil, nil)
}

// ConsoleWrite types bytes into the Mac's serial console.
func (c *Client) ConsoleWrite(ctx context.Context, name string, b []byte) error {
	req, _ := http.NewRequestWithContext(ctx, "POST", c.URL+"/api/devices/"+url.PathEscape(name)+"/console", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		m, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", strings.TrimSpace(string(m)))
	}
	return nil
}

// ConsoleRaw streams console bytes to w until ctx ends.
func (c *Client) ConsoleRaw(ctx context.Context, name string, w io.Writer) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.URL+"/api/devices/"+url.PathEscape(name)+"/console", nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		m, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", strings.TrimSpace(string(m)))
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (c *Client) Build(ctx context.Context, req api.BuildRequest) (*api.Build, error) {
	var out api.Build
	return &out, c.do(ctx, "POST", "/api/builds", jsonBody(req), &out)
}

func (c *Client) GetBuild(ctx context.Context, id string) (*api.Build, error) {
	var out api.Build
	return &out, c.do(ctx, "GET", "/api/builds/"+url.PathEscape(id), nil, &out)
}

func (c *Client) Builds(ctx context.Context, limit int) ([]*api.Build, error) {
	var out []*api.Build
	return out, c.do(ctx, "GET", fmt.Sprintf("/api/builds?limit=%d", limit), nil, &out)
}

// BuildLog writes the build log to w; with follow it streams until the build ends.
func (c *Client) BuildLog(ctx context.Context, id string, follow bool, w io.Writer) error {
	q := ""
	if follow {
		q = "?follow=1"
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.URL+"/api/builds/"+url.PathEscape(id)+"/log"+q, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		m, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", strings.TrimSpace(string(m)))
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// BuildFile downloads one output of a package build into dst and returns its sha256.
func (c *Client) BuildFile(ctx context.Context, id, name, dst string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.URL+"/api/builds/"+url.PathEscape(id)+"/files/"+url.PathEscape(name), nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		m, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%s: %s", name, strings.TrimSpace(string(m)))
	}
	f, err := os.Create(dst + ".part")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(dst + ".part")
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), os.Rename(dst+".part", dst)
}

// Installed sends one of the installed-release Maintainer requests
// (/api/installed/<release>[/<what>]) and decodes the reply into out.
func (c *Client) Installed(ctx context.Context, method, release, what string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	p := "/api/installed/" + url.PathEscape(release)
	if what != "" {
		p += "/" + what
	}
	return c.do(ctx, method, p, r, out)
}

func (c *Client) CancelBuild(ctx context.Context, id string) error {
	return c.do(ctx, "POST", "/api/builds/"+url.PathEscape(id)+"/cancel", nil, nil)
}

func (c *Client) Exec(ctx context.Context, device string, a api.ExecArgs) (*api.ExecResult, error) {
	var out api.ExecResult
	return &out, c.do(ctx, "POST", "/api/devices/"+url.PathEscape(device)+"/exec", jsonBody(a), &out)
}
