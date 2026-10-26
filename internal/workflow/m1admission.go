package workflow

// This optional adapter runs only in the standalone client process. It changes
// no server/agent policy and never treats a retained phase output as current
// technical recovery readiness. The generic Backend.Submit path is unchanged.
import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

type M1SubmissionAdmission struct {
	BootID          Value `json:"boot_id"`
	MinimumLeaseSec int   `json:"minimum_lease_sec"`
}
type M1AdmittingBackend interface {
	SubmitM1(context.Context, api.JobSpec, string, int) (*api.Job, error)
}
type M1SubmissionClient interface {
	Submit(context.Context, api.JobSpec) (*api.Job, error)
	Device(context.Context, string) (*client.Device, error)
	OOBStatus(context.Context, string) (map[string]any, error)
}

// M1Backend embeds the existing authenticated client for uploads/job reads.
// The explicit per-submit admission calls SubmitM1, not the generic method.
type M1Backend struct {
	Backend
	Client M1SubmissionClient
	Now    func() time.Time
}

func (b *M1Backend) SubmitM1(ctx context.Context, spec api.JobSpec, boot string, minimum int) (*api.Job, error) {
	if spec.Device != "m1" || spec.Holder == "" || spec.InstalledManifest == "" || minimum < 2700 || minimum > 7200 || boot == "" {
		return nil, errors.New("invalid reviewed M1 installed submission admission")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	check := func(d *client.Device) error {
		if d == nil || d.Name != "m1" || d.State != api.StateReady || !d.Alive || d.ActiveJob != "" || d.Queued != 0 || d.BootID != boot || d.Kernel != "7.2.11-6-1-ARCH" || strings.Contains(d.Cmdline, "maclab.job=") {
			return errors.New("M1 submit-time ordinary boot/readiness drift")
		}
		if d.Facts.Machine != "aarch64" || len(d.Facts.Compatible) == 0 || d.Facts.Compatible[0] != "apple,j293" || d.Tier < 2 {
			return errors.New("M1 submit-time model/recovery tier mismatch")
		}
		if d.Lease == nil || d.Lease.Holder != spec.Holder || d.Lease.Expires.Sub(now()) < time.Duration(minimum)*time.Second {
			return errors.New("M1 submit-time lease does not cover job and cleanup")
		}
		return nil
	}
	d, err := b.Client.Device(ctx, "m1")
	if err != nil {
		return nil, err
	}
	if err = check(d); err != nil {
		return nil, err
	}
	oob, err := b.Client.OOBStatus(ctx, "m1")
	if err != nil {
		return nil, fmt.Errorf("M1 live recovery route: %w", err)
	}
	controller, cok := oob["controller"].(string)
	status, sok := oob["status"].(string)
	failure := oob["error"]
	if !cok || !strings.HasPrefix(controller, "oobd ") || !sok || strings.TrimSpace(status) == "" || (failure != nil && failure != "") {
		return nil, errors.New("M1 live OOB route is unhealthy; no job submitted")
	}
	// A slow status call or a boot/lease change during it cannot authorize POST.
	d, err = b.Client.Device(ctx, "m1")
	if err != nil {
		return nil, err
	}
	if err = check(d); err != nil {
		return nil, err
	}
	if now().Sub(start) > 20*time.Second {
		return nil, errors.New("M1 technical observation exceeded freshness bound; no job submitted")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return b.Client.Submit(ctx, spec)
}
