package agent

import (
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// The m3pro's known-good and stock cmdlines, 2026-10-03.
const (
	m3KnownGood = "root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ zswap.enabled=0 rootfstype=btrfs loglevel=4 log_buf_len=16M rd.log=kmsg thunderbolt.dyndbg=+p apple_rtkit.dyndbg=+p appledrm.dcpext_probe=1 apple_t6030_display.dcpext=1 apple_t6030_display.enable=1 asahi.m3_backend=runtime asahi.m3_initdata=adt dcpext_eryk1_autostart=1"
	m3Stock     = "root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ zswap.enabled=0 rootfstype=btrfs quiet loglevel=3 splash"
)

func stock() (string, error) { return m3Stock, nil }

func TestStageCmdlineDefaultBase(t *testing.T) {
	got, err := stageCmdline(m3KnownGood, stock, api.StageArgs{CmdlineBase: "default", Serial: true, Cmdline: "foo=1"}, "j1")
	if err != nil {
		t.Fatal(err)
	}
	want := "root=UUID=4f4d5801-524f-4f54-8000-000000000001 rw rootflags=subvol=@ zswap.enabled=0 rootfstype=btrfs loglevel=7 panic=10 systemd.watchdog_sec=0 watchdog.open_timeout=120 console=ttySAC0,115200 console=tty0 foo=1 maclab.job=j1"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestStageCmdlineStrip(t *testing.T) {
	got, err := stageCmdline(m3KnownGood, stock, api.StageArgs{CmdlineStrip: []string{"asahi.*", "apple_t6030_display.*", "appledrm.*", "dcpext_*", "*.dyndbg"}}, "j2")
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"asahi.", "apple_t6030", "appledrm.", "dcpext_", "dyndbg"} {
		if strings.Contains(got, gone) {
			t.Fatalf("%q left in %s", gone, got)
		}
	}
	for _, kept := range []string{"root=UUID=", "rootflags=subvol=@", "log_buf_len=16M", "rd.log=kmsg", "maclab.job=j2"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("%q missing from %s", kept, got)
		}
	}
}

func TestStageCmdlineRefusesNoRoot(t *testing.T) {
	if _, err := stageCmdline(m3KnownGood, stock, api.StageArgs{CmdlineStrip: []string{"root*"}}, "j3"); err == nil {
		t.Fatal("stripping root= should be refused")
	}
	if _, err := stageCmdline(m3KnownGood, stock, api.StageArgs{CmdlineBase: "quiet splash"}, "j4"); err == nil {
		t.Fatal("a literal base without root= should be refused")
	}
	got, err := stageCmdline(m3KnownGood, stock, api.StageArgs{CmdlineBase: "root=/dev/sda2 ro"}, "j5")
	if err != nil || !strings.HasPrefix(got, "root=/dev/sda2 ro panic=10") {
		t.Fatalf("literal base: %q %v", got, err)
	}
}

func TestStockCmdlineRegexp(t *testing.T) {
	conf := "ESP_PATH=\"/boot/efi\"\nKERNEL_CMDLINE[default]=\"" + m3Stock + "\"\nKERNEL_CMDLINE[\"linux-m3-eryk\"]=\"" + m3KnownGood + "\"\n"
	m := reStockCmdline.FindStringSubmatch(conf)
	if m == nil || m[2] != m3Stock {
		t.Fatalf("got %q", m)
	}
}

func TestRecordable(t *testing.T) {
	for _, c := range []struct {
		kernel, running, cmdline string
		ok                       bool
	}{
		{"7.1.12-2-12.0-sep-ARCH", "7.1.12-2-12.0-sep-ARCH", "root=UUID=x rw quiet splash", true},
		{"7.1.12-2-12.0-sep-ARCH", "7.1.12-2-11.31-sep-ARCH", "root=UUID=x rw quiet splash", false},
		{"7.1.12-2-12.0-sep-ARCH", "7.1.12-2-12.0-sep-ARCH", "root=UUID=x rw maclab.job=j1006-1 panic=10", false},
		{"", "", "root=UUID=x rw", false},
	} {
		if err := recordable(c.kernel, c.running, c.cmdline); (err == nil) != c.ok {
			t.Errorf("recordable(%q, %q, %q) = %v", c.kernel, c.running, c.cmdline, err)
		}
	}
}
