package agent

import (
	"bytes"
	"context"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

func jobsCfg(t *testing.T, kind string) *Config {
	t.Helper()
	return &Config{WorkDir: t.TempDir(), Enrollment: api.AgentEnrollment{Enrollment: api.Enrollment{Kind: kind}}}
}

func TestNotifyJobsIsOffUntilTheVolunteerTurnsItOn(t *testing.T) {
	cfg := jobsCfg(t, api.KindVolunteer)
	if on, err := loadJobNotices(cfg); on || err != nil {
		t.Fatalf("job notices = %v, %v before anyone asked; want off", on, err)
	}
	var out bytes.Buffer
	if err := notifyCmd(context.Background(), cfg, nil, []string{"--jobs", "on"}, &out); err != nil {
		t.Fatalf("notify --jobs on: %v", err)
	}
	if on, err := loadJobNotices(cfg); !on || err != nil {
		t.Fatalf("job notices = %v, %v after notify --jobs on", on, err)
	}
	if err := notifyCmd(context.Background(), cfg, nil, []string{"--jobs", "off"}, &out); err != nil {
		t.Fatalf("notify --jobs off: %v", err)
	}
	if on, _ := loadJobNotices(cfg); on {
		t.Fatal("notify --jobs off left the notices on")
	}
}

func TestNotifyJobsTakesOnlyOnOrOffAndLeavesTheChoiceAlone(t *testing.T) {
	cfg := jobsCfg(t, api.KindVolunteer)
	if err := notifyCmd(context.Background(), cfg, nil, []string{"--jobs", "on"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"--jobs"}, {"--jobs", "maybe"}, {"--jobs", ""}, {"--jobs", "ON"}, {"--jobs", "on", "extra"}, {}} {
		if err := notifyCmd(context.Background(), cfg, nil, bad, &bytes.Buffer{}); err == nil {
			t.Errorf("notify %v was accepted", bad)
		}
	}
	if on, _ := loadJobNotices(cfg); !on {
		t.Fatal("a refused notify changed the choice")
	}
}

func TestALabOwnedMacCannotAskForJobNotices(t *testing.T) {
	cfg := jobsCfg(t, api.KindLabOwned)
	if err := notifyCmd(context.Background(), cfg, nil, []string{"--jobs", "on"}, &bytes.Buffer{}); err == nil {
		t.Fatal("a Lab-owned Mac accepted notify --jobs on")
	}
	if on, _ := loadJobNotices(cfg); on {
		t.Fatal("a Lab-owned Mac got job notices turned on")
	}
}
