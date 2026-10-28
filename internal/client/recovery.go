package client

import (
	"context"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"net/url"
)

func (c *Client) requireRecoveryMode(ctx context.Context, mode string) error {
	if !api.ValidRecoveryMode(mode) {
		return fmt.Errorf("invalid recovery_mode; no job submitted")
	}
	if mode == "" {
		return nil
	}
	var caps api.RecoveryCapabilities
	if err := c.do(ctx, "GET", "/api/recovery", nil, &caps); err != nil {
		return fmt.Errorf("controller recovery-mode capability unavailable; no job submitted: %w", err)
	}
	if caps.Schema != 1 || !caps.PerJobOOBIsolation {
		return fmt.Errorf("controller lacks per-job OOB isolation; no job submitted")
	}
	for _, m := range caps.Modes {
		if m == mode {
			return nil
		}
	}
	return fmt.Errorf("controller does not support requested recovery mode; no job submitted")
}

func (c *Client) SelectRecoveryMode(ctx context.Context, device string, q api.RecoveryModeRequest) (*api.RecoveryModeSelection, error) {
	if q.Mode == "" || q.Holder == "" || q.Transaction == "" {
		return nil, fmt.Errorf("explicit recovery transaction required")
	}
	if e := c.requireRecoveryMode(ctx, q.Mode); e != nil {
		return nil, e
	}
	var caps api.RecoveryCapabilities
	if e := c.do(ctx, "GET", "/api/recovery", nil, &caps); e != nil || !caps.TransactionIsolation {
		return nil, fmt.Errorf("controller lacks transaction recovery isolation; no mode change requested")
	}
	var out api.RecoveryModeSelection
	if e := c.do(ctx, "POST", "/api/devices/"+url.PathEscape(device)+"/recovery-mode", jsonBody(q), &out); e != nil {
		return nil, e
	}
	if out.Schema != 1 || out.Device != device || out.Mode != q.Mode || out.Holder != q.Holder || out.Transaction != q.Transaction || !out.Quiescent {
		return &out, fmt.Errorf("recovery selection response drift; inspect state before any helper execution")
	}
	return &out, nil
}
