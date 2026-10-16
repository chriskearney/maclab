// Package client is the Go client for labd's admin API, used by the lab CLI and MCP server.
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
)

type Client struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	http  *http.Client
}

func ConfigPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "maclab", "client.json")
}

// Load reads MACLAB_URL / MACLAB_TOKEN, falling back to the saved config.
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
	if c.URL == "" || c.Token == "" {
		return nil, fmt.Errorf("not configured: run `lab login <labd-url> <admin-token>` or set MACLAB_URL and MACLAB_TOKEN")
	}
	c.URL = strings.TrimRight(c.URL, "/")
	c.http = &http.Client{}
	return c, nil
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
	var out api.Job
	return &out, c.do(ctx, "POST", "/api/jobs", jsonBody(spec), &out)
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
func (c *Client) Wait(ctx context.Context, id string, timeout time.Duration) (*api.Job, error) {
	var out api.Job
	return &out, c.do(ctx, "GET", fmt.Sprintf("/api/jobs/%s/wait?timeout=%d", url.PathEscape(id), int(timeout.Seconds())), nil, &out)
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

func (c *Client) File(ctx context.Context, id, name string) ([]byte, error) {
	var out string
	err := c.do(ctx, "GET", "/api/jobs/"+url.PathEscape(id)+"/files/"+name, nil, &out)
	return []byte(out), err
}

// Gate reports whether a kernel (build id or sha256 prefix) passed on every
// required chip family; no families means all of them. volunteers counts
// volunteers' Macs too, and exclude sets those jobs of the kernel aside for
// this report only.
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

// Installed sends one of the installed-release admin requests
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
