package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func TestOMTPublicationRequiresPositivePackageIdentity(t *testing.T) {
	cases := []struct {
		name, kernel, status    string
		baseline, publish, good bool
		extra                   string
		wantPost                bool
	}{
		{name: "custom baseline", kernel: "7.2-custom", status: "fail", baseline: true, good: true},
		{name: "custom scheduled known good", kernel: "7.2-custom", status: "fail", good: true},
		{name: "custom manual publish", kernel: "7.2-custom", status: "fail", publish: true, good: true},
		{name: "skipped ownership", kernel: "7.2-custom", status: "skip", good: true},
		{name: "duplicate ownership", kernel: "7.2-custom", status: "pass", good: true, extra: `,{"id":"boot.kernel-package","status":"pass"}`},
		{name: "missing ownership", kernel: "7.2-custom", status: "missing", good: true},
		{name: "package-looking custom name", kernel: "7.2.11-6-1-ARCH", status: "fail", good: true},
		{name: "packaged baseline", kernel: "7.2.11-6-1-ARCH", status: "pass", baseline: true, good: true, wantPost: true},
		{name: "packaged scheduled", kernel: "7.2.11-6-1-ARCH", status: "pass", good: true, wantPost: true},
		{name: "valid packaged name contains lab", kernel: "7.2-lab-package", status: "pass", good: true, wantPost: true},
		{name: "candidate cannot publish even ownership pass", kernel: "7.2-candidate", status: "pass", good: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			posts := 0
			site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"report_url":"https://example.test/report/1"}`)
			}))
			defer site.Close()
			root := t.TempDir()
			s := &Server{cfg: Config{DataDir: root, OMTSite: site.URL, OMTPublish: true}, devs: map[string]*dev{"m": {d: api.Device{Name: "m", KnownGood: c.kernel}}}}
			j := &api.Job{ID: "j1", Spec: api.JobSpec{Device: "m", Baseline: c.baseline, Publish: c.publish}, Result: api.JobResult{BootKernel: c.kernel, OMT: &api.OMTResult{KnownGood: c.good, Kernel: c.kernel, Report: "report.json"}}}
			dir := s.jobDir(j.ID)
			os.MkdirAll(dir, 0755)
			check := fmt.Sprintf(`{"id":"boot.kernel-package","status":%q}`, c.status)
			if c.status == "missing" {
				check = `{"id":"unrelated","status":"pass"}`
			}
			body := []byte(fmt.Sprintf(`{"machine":{"kernel":%q},"checks":[%s%s]}`, c.kernel, check, c.extra))
			os.WriteFile(filepath.Join(dir, "report.json"), body, 0644)
			_, err := s.publishOMT(context.Background(), j)
			if c.wantPost {
				if err != nil || posts != 1 {
					t.Fatalf("real package rejected: posts=%d err=%v", posts, err)
				}
			} else if err == nil || posts != 0 {
				t.Fatalf("custom report escaped: posts=%d err=%v", posts, err)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "report.json"))
			if string(after) != string(body) {
				t.Fatal("publication changed private evidence")
			}
		})
	}
}
func TestPackagedOMTReportRejectsMalformedOrWrongKernel(t *testing.T) {
	for _, body := range []string{`no JSON`, `{}`, `{"machine":{"kernel":"wrong"},"checks":[{"id":"boot.kernel-package","status":"pass"}]}`} {
		if err := packagedOMTReport([]byte(body), "current"); err == nil {
			t.Fatal(body)
		}
	}
	// Guard consumes exactly the report identity used by the existing reader.
	var rep omtReport
	if err := json.Unmarshal([]byte(`{"machine":{"kernel":"current"},"checks":[{"id":"boot.kernel-package","status":"pass"}]}`), &rep); err != nil || !strings.Contains(rep.Machine.Kernel, "current") {
		t.Fatal(err)
	}
}
