package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

func TestEveryTestEntryCmdlineCarriesTheLabBootParams(t *testing.T) {
	want := labBootParams(0)
	if len(want) == 0 {
		t.Fatal("no Lab boot params")
	}
	for _, a := range []api.StageArgs{
		{},
		{CmdlineBase: "default", Serial: true, Cmdline: "foo=1"},
		{CmdlineStrip: []string{"asahi.*", "*.dyndbg"}},
		{CmdlineBase: "root=/dev/sda2 ro", Verbose: true},
	} {
		got, err := stageCmdline(m3KnownGood, stock, a, "j1")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(got)
		for _, p := range want {
			if n := countField(fields, p); n != 1 {
				t.Errorf("%+v: %q appears %d times in %s", a, p, n, got)
			}
		}
		if !IsLabBoot(got) {
			t.Errorf("%+v: no Lab boot marker in %s", a, got)
		}
	}
}

func countField(fields []string, p string) int {
	n := 0
	for _, f := range fields {
		if f == p {
			n++
		}
	}
	return n
}

func TestLabBootParamsAreThePanicTimeoutTheWatchdogOpenTimeoutAndTheMarker(t *testing.T) {
	p := labBootParams(150 * time.Second)
	if !slices.Contains(p, "panic=10") {
		t.Errorf("no panic=10: %v", p)
	}
	if !slices.Contains(p, "watchdog.open_timeout=150") {
		t.Errorf("no watchdog.open_timeout=150: %v", p)
	}
	if !IsLabBoot(strings.Join(p, " ")) {
		t.Errorf("no Lab boot marker: %v", p)
	}
}

func TestWatchdogOpenTimeoutDefaultsToBetweenTwoAndThreeMinutes(t *testing.T) {
	if defaultWatchdogOpenTimeout < 120*time.Second || defaultWatchdogOpenTimeout > 180*time.Second {
		t.Fatalf("default watchdog.open_timeout %s, want 120-180 s", defaultWatchdogOpenTimeout)
	}
	want := fmt.Sprintf("watchdog.open_timeout=%d", int(defaultWatchdogOpenTimeout/time.Second))
	if p := labBootParams(0); !slices.Contains(p, want) {
		t.Fatalf("unconfigured params %v lack %s", p, want)
	}
}

func TestOwnBootsAreNotLabBoots(t *testing.T) {
	for _, c := range []string{m3KnownGood, m3Stock, "root=UUID=x rw panic=10", ""} {
		if IsLabBoot(c) {
			t.Errorf("%q is taken for a Lab boot", c)
		}
	}
}

func TestDeadlineRecordAllowsTwiceTheBootTimeoutAndEndsWithTheJob(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	jobEnd := now.Add(time.Hour)
	d := newLabBootDeadlines(now, 5*time.Minute, jobEnd)
	if !d.NoContact.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("no-contact deadline %s, want %s", d.NoContact, now.Add(10*time.Minute))
	}
	if !d.Ceiling.Equal(jobEnd) {
		t.Errorf("hard ceiling %s, want the job's end %s", d.Ceiling, jobEnd)
	}
}

func TestDeadlineUnitRebootsOnEitherDeadline(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	d := labBootDeadlines{NoContact: now.Add(10 * time.Minute), Ceiling: now.Add(time.Hour)}
	for _, c := range []struct {
		name      string
		at        time.Duration
		contacted bool
		reboot    bool
	}{
		{"before both, no contact yet", 5 * time.Minute, false, false},
		{"before both, in contact", 5 * time.Minute, true, false},
		{"no-contact deadline passed without contact", 11 * time.Minute, false, true},
		{"no-contact deadline passed in contact", 11 * time.Minute, true, false},
		{"hard ceiling passed in contact", 61 * time.Minute, true, true},
		{"hard ceiling passed without contact", 61 * time.Minute, false, true},
	} {
		if got := rebootDue(d, now.Add(c.at), c.contacted); got != c.reboot {
			t.Errorf("%s: reboot %v, want %v", c.name, got, c.reboot)
		}
	}
}

func TestDeadlineRecordSurvivesOnDisk(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	d := labBootDeadlines{NoContact: now.Add(10 * time.Minute), Ceiling: now.Add(time.Hour)}
	p := filepath.Join(t.TempDir(), "deadlines")
	if err := writeLabBootDeadlines(p, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("no record on disk: %v", err)
	}
	got, err := readLabBootDeadlines(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NoContact.Equal(d.NoContact) || !got.Ceiling.Equal(d.Ceiling) {
		t.Fatalf("read back %+v, wrote %+v", got, d)
	}
}

func TestDeadlineUnitStartsEarlyWithNoNetworkDependency(t *testing.T) {
	u := labBootDeadlineUnit()
	if !strings.Contains(u, "[Unit]") || !strings.Contains(u, "ExecStart=") || !strings.Contains(u, "[Install]") {
		t.Fatalf("not a systemd unit:\n%s", u)
	}
	if strings.Contains(strings.ToLower(u), "network") {
		t.Errorf("the unit depends on the network:\n%s", u)
	}
	early := strings.Contains(u, "DefaultDependencies=no")
	for _, target := range []string{"sysinit.target", "basic.target", "local-fs.target"} {
		early = early || strings.Contains(u, "WantedBy="+target)
	}
	if !early {
		t.Errorf("the unit doesn't start early:\n%s", u)
	}
}

func TestTestKernelWithoutAppleWDTIsFlagged(t *testing.T) {
	for _, c := range []struct {
		config string
		has    bool
	}{
		{"CONFIG_ARM64=y\nCONFIG_APPLE_WATCHDOG=y\n", true},
		{"CONFIG_ARM64=y\nCONFIG_APPLE_WATCHDOG=m\n", true},
		{"CONFIG_ARM64=y\n# CONFIG_APPLE_WATCHDOG is not set\n", false},
		{"CONFIG_ARM64=y\n", false},
	} {
		if got := kernelHasAppleWDT(c.config); got != c.has {
			t.Errorf("kernelHasAppleWDT(%q) = %v, want %v", c.config, got, c.has)
		}
	}
}

func TestPstoreRecordsOfTheLostBootAreCollected(t *testing.T) {
	pstore, out := t.TempDir(), t.TempDir()
	records := map[string]string{
		"dmesg-ramoops-0":   "Panic#1 Part1\nKernel panic - not syncing: VFS\n",
		"console-ramoops-0": "[    1.0] Booting Linux\n",
	}
	for name, body := range records {
		os.WriteFile(filepath.Join(pstore, name), []byte(body), 0o644)
	}
	files, err := collectPstore(pstore, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(records) {
		t.Fatalf("collected %v, want %d records", files, len(records))
	}
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatalf("collected %s: %v", f, err)
		}
		for name, body := range records {
			if string(b) == body && strings.Contains(f, name) {
				seen[name] = true
			}
		}
	}
	if len(seen) != len(records) {
		t.Fatalf("collected %v, missing records (seen %v)", files, seen)
	}
}

func TestNoPstoreRecordsIsNotAnError(t *testing.T) {
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "absent")} {
		files, err := collectPstore(dir, t.TempDir())
		if err != nil || len(files) != 0 {
			t.Errorf("collectPstore(%s) = %v, %v", dir, files, err)
		}
	}
}

// withoutLabBootAdditions drops what #30 adds to a test entry's command line
// (watchdog.open_timeout=N and the Lab boot marker), so tests that pin the rest
// hold before and after it.
func withoutLabBootAdditions(cmdline string) string {
	var keep []string
	for _, f := range strings.Fields(cmdline) {
		if isWatchdogOpenTimeout(f) || IsLabBoot(f) && !strings.HasPrefix(f, "maclab.job=") {
			continue
		}
		keep = append(keep, f)
	}
	return strings.Join(keep, " ")
}

func isWatchdogOpenTimeout(f string) bool {
	v, ok := strings.CutPrefix(f, "watchdog.open_timeout=")
	if !ok || v == "" {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
