package loop

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// flakyLab is a fakeLab whose Wait can fail: wait, when set, runs first and
// either returns an error or hands over to the fakeLab.
type flakyLab struct {
	*fakeLab
	waits int
	wait  func(ctx context.Context, n int) error
}

func (f *flakyLab) Wait(ctx context.Context, id string, timeout time.Duration) (*api.Job, error) {
	f.waits++
	if f.wait != nil {
		if err := f.wait(ctx, f.waits); err != nil {
			return nil, err
		}
	}
	return f.fakeLab.Wait(ctx, id, timeout)
}

type countJudge struct{ calls int }

func (j *countJudge) Judge(context.Context, string, string) (*Verdict, error) {
	j.calls++
	return &Verdict{Fault: None}, nil
}

func TestAWaitThatErrorsThenSucceedsGivesANormalEntry(t *testing.T) {
	lab := &flakyLab{fakeLab: &fakeLab{outcome: asPredicted}, wait: func(_ context.Context, n int) error {
		if n <= 2 {
			return errors.New("connection reset")
		}
		return nil
	}}
	n, path := night(t, lab.fakeLab, map[Mode]int{None: 1})
	n.Lab = lab
	j := &countJudge{}
	n.Judge = j
	if err := n.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	es := readLedger(t, path)
	if len(es) != 1 || es[0].Outcome != api.OutcomePass || es[0].Error != "" || es[0].Score == nil {
		t.Fatalf("entries %+v", es)
	}
	if lab.waits != 3 || j.calls != 1 {
		t.Errorf("%d waits, %d judge calls", lab.waits, j.calls)
	}
}

func TestAJobThatNeverFinishesStopsTheNight(t *testing.T) {
	lab := &flakyLab{fakeLab: &fakeLab{outcome: asPredicted}, wait: func(context.Context, int) error {
		return errors.New("connection refused")
	}}
	n, path := night(t, lab.fakeLab, map[Mode]int{None: 3})
	n.Lab, n.JobTimeout = lab, 50*time.Millisecond
	j := &countJudge{}
	n.Judge = j
	err := n.Run(context.Background())
	if !IsStop(err) || !strings.Contains(err.Error(), "never finished") {
		t.Fatalf("got %v", err)
	}
	es := readLedger(t, path)
	if len(es) != 1 || es[0].Outcome != api.OutcomeInfra || !strings.Contains(es[0].Error, "connection refused") {
		t.Fatalf("entries %+v", es)
	}
	if lab.waits < 2 || j.calls != 0 {
		t.Errorf("%d waits, %d judge calls", lab.waits, j.calls)
	}
}

func TestCancelingMidWaitAppendsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lab := &flakyLab{fakeLab: &fakeLab{outcome: asPredicted}, wait: func(ctx context.Context, n int) error {
		if n == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	}}
	n, path := night(t, lab.fakeLab, map[Mode]int{None: 3})
	n.Lab = lab
	j := &countJudge{}
	n.Judge = j
	if err := n.Run(ctx); !errors.Is(err, context.Canceled) || IsStop(err) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if es := readLedger(t, path); len(es) != 1 || j.calls != 1 {
		t.Errorf("%d entries, %d judge calls, want the first boot only", len(es), j.calls)
	}
}
