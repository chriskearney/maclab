package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// testEDID is a monitor's base block: manufacturer DEL, product 0xa0c3,
// numeric serial 0x4c4b4a49, made 2021, a 2560x1440@60 preferred timing
// sized 597x336 mm, a name and a serial-number descriptor, one extension.
func testEDID(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 128)
	copy(b, edidHeader)
	m := uint16('D'-'@')<<10 | uint16('E'-'@')<<5 | uint16('L'-'@')
	b[8], b[9] = byte(m>>8), byte(m)
	b[10], b[11] = 0xc3, 0xa0
	b[12], b[13], b[14], b[15] = 0x49, 0x4a, 0x4b, 0x4c
	b[16], b[17] = 12, 31 // week 12 of 2021
	b[18], b[19] = 1, 4
	b[21], b[22] = 60, 34
	// Detailed timing: 241.5 MHz, 2560+160 x 1440+41 -> 60 Hz, 597x336 mm.
	d := b[54:72]
	clock := 24150
	d[0], d[1] = byte(clock), byte(clock>>8)
	d[2], d[3], d[4] = 2560&0xff, 160, byte(2560>>8)<<4|0
	d[5], d[6], d[7] = 1440&0xff, 41, byte(1440>>8)<<4|0
	d[12], d[13], d[14] = 597&0xff, 336&0xff, byte(597>>8)<<4|byte(336>>8)
	name := b[72:90]
	name[3] = 0xfc
	copy(name[5:], "DELL U2721DE\n ")
	ser := b[90:108]
	ser[3] = 0xff
	copy(ser[5:], "SECRETSN0042\n")
	txt := b[108:126]
	txt[3] = 0xfe
	copy(txt[5:], "ALSOSECRET\n")
	b[126] = 1
	var sum byte
	for _, c := range b[:127] {
		sum += c
	}
	b[127] = -sum
	return b
}

func TestParseEDIDRedactsSerials(t *testing.T) {
	e := parseEDID(testEDID(t))
	want := edidInfo{Present: true, Bytes: 128, Valid: true, Manufacturer: "DEL", ProductCode: "0xa0c3",
		MonitorName: "DELL U2721DE", Year: 2021, Version: "1.4", WidthMM: 597, HeightMM: 336,
		PreferredMode: "2560x1440@60", Extensions: 1, SerialRedacted: true}
	if e != want {
		t.Errorf("parseEDID:\n got %+v\nwant %+v", e, want)
	}
	j, _ := json.Marshal(e)
	for _, leak := range []string{"SECRETSN0042", "ALSOSECRET", "1280002633", "4c4b4a49", "IJKL"} {
		if strings.Contains(string(j), leak) {
			t.Errorf("the record carries the serial %q: %s", leak, j)
		}
	}
}

func TestParseEDIDBroken(t *testing.T) {
	b := testEDID(t)
	b[127]++
	if e := parseEDID(b); e.Valid || e.Problem != "bad base block checksum" || e.Manufacturer != "DEL" {
		t.Errorf("bad checksum: %+v", e)
	}
	if e := parseEDID(b[:64]); e.Valid || !e.Present || !strings.Contains(e.Problem, "short") {
		t.Errorf("short: %+v", e)
	}
	if e := parseEDID(nil); e.Present || e.Valid {
		t.Errorf("none: %+v", e)
	}
	// No serial anywhere: nothing to redact.
	b = testEDID(t)
	b[12], b[13], b[14], b[15] = 0, 0, 0, 0
	b[93] = 0x10 // the serial descriptor becomes a dummy one
	if e := parseEDID(b); e.SerialRedacted {
		t.Errorf("no serial, but redacted: %+v", e)
	}
}

// writeFiles makes a tree of files under root; a value starting with "->"
// is a symlink to the rest.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, v := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		var err error
		if target, ok := strings.CutPrefix(v, "->"); ok {
			err = os.Symlink(target, p)
		} else {
			err = os.WriteFile(p, []byte(v), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadConnectors(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"card0-DP-1/status":    "connected\n",
		"card0-DP-1/enabled":   "enabled\n",
		"card0-DP-1/modes":     "2560x1440\n1920x1080\n1920x1080\n",
		"card0-DP-1/edid":      string(testEDID(t)),
		"card0-eDP-1/status":   "connected\n",
		"card0-eDP-1/enabled":  "enabled\n",
		"card0-eDP-1/modes":    "3024x1964\n",
		"card0-eDP-1/edid":     "",
		"card0-DP-2/status":    "disconnected\n",
		"card0-DP-2/enabled":   "disabled\n",
		"card0-DP-2/modes":     "",
		"card0/dev":            "226:0\n",
		"renderD128/dev":       "226:128\n",
		"card1-Writeback-1/xx": "",
	})
	cs := readConnectors(root)
	var got []string
	for _, c := range cs {
		got = append(got, c.Card+"-"+c.Name+" "+c.Status+" "+strings.Join(c.Modes, ","))
	}
	want := []string{"card0-eDP-1 connected 3024x1964", "card0-DP-1 connected 2560x1440,1920x1080", "card0-DP-2 disconnected "}
	if !slices.Equal(got, want) {
		t.Errorf("connectors:\n got %q\nwant %q", got, want)
	}
	if !cs[0].Internal || cs[1].Internal || !cs[1].Enabled || cs[2].Enabled {
		t.Errorf("internal/enabled wrong: %+v", cs)
	}
	if cs[0].EDID.Present || cs[1].EDID.MonitorName != "DELL U2721DE" || !cs[1].EDID.SerialRedacted {
		t.Errorf("EDIDs: %+v / %+v", cs[0].EDID, cs[1].EDID)
	}
}

// testKernelLog is a boot's kernel log as journalctl -o cat prints it: one
// DCP crash (RTKit's line and the DCP's own), DART faults from two DARTs and
// lines that only look like them.
const testKernelLog = `apple-dcp 231c00000.dcp: DCP booted
apple-dcp 31ac00000.dcp: RTKit: co-processor has crashed
apple-dcp 31ac00000.dcp: RTKit: Crash time: 1234
apple-dcp 31ac00000.dcp: DCP has crashed
apple-dart 31a304000.iommu: translation fault: status:0x1 stream:2 code:0x1 (READ FAULT) at 0xdead0000
apple-dart 31a304000.iommu: translation fault: SID:2 read NO PTE at 0x1000 (status 0x00000001)
apple-dart 382f00000.dart: block exception: status:0x00000004
apple-dart 382f00000.dart: stale exception latched before probe: SID:0 read x at 0x0
apple-nvme 393cc0000.nvme: RTKit: co-processor has crashed
some-driver foo: translation fault: not a DART
  apple-dcp 231c00000.dcp: RTKit: adopted co-processor crashed without a readable log
`

func TestCountDisplayFaults(t *testing.T) {
	f := countDisplayFaults(testKernelLog)
	if f.crashes() != 2 || f.DCPCrashes["31ac00000.dcp"] != 1 || f.DCPCrashes["231c00000.dcp"] != 1 {
		t.Errorf("DCP crashes: %v", f.DCPCrashes)
	}
	if f.darts() != 3 || f.DARTFaults["31a304000.iommu"] != 2 || f.DARTFaults["382f00000.dart"] != 1 {
		t.Errorf("DART faults: %v", f.DARTFaults)
	}
	if f := countDisplayFaults(""); f.crashes()+f.darts() != 0 {
		t.Errorf("empty log: %+v", f)
	}
}

func TestReadDCPs(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"231c00000.dcp/of_node/compatible":     "apple,t8122-dcp\x00apple,dcp\x00",
		"231c00000.dcp/driver":                 "->../../../bus/platform/drivers/apple-dcp",
		"31ac00000.dcp/of_node/compatible":     "apple,t8122-dcpext\x00apple,dcpext\x00",
		"382f00000.dart/of_node/compatible":    "apple,t8110-dart\x00",
		"382f00000.dart/driver":                "->../../../bus/platform/drivers/apple-dart",
		"display-subsystem/of_node/compatible": "apple,display-subsystem\x00",
	})
	ds := readDCPs(root)
	if len(ds) != 2 {
		t.Fatalf("DCPs: %+v", ds)
	}
	if ds[0].Device != "231c00000.dcp" || ds[0].External || !ds[0].Bound || ds[0].Driver != "apple-dcp" {
		t.Errorf("dcp: %+v", ds[0])
	}
	if ds[1].Device != "31ac00000.dcp" || !ds[1].External || ds[1].Bound {
		t.Errorf("dcpext: %+v", ds[1])
	}
}

func TestAwaitExternal(t *testing.T) {
	defer func(p, e time.Duration) { displayPoll, displayEnableWait = p, e }(displayPoll, displayEnableWait)
	displayPoll, displayEnableWait = time.Millisecond, 20*time.Millisecond
	logf := func(string, ...any) {}
	panel := displayConnector{Name: "eDP-1", Internal: true, Status: "connected", Enabled: true}
	n := 0
	seq := func() []displayConnector {
		n++
		dp := displayConnector{Name: "DP-1", Status: "disconnected"}
		hdmi := displayConnector{Name: "HDMI-A-1", Status: "connected"}
		if n >= 3 {
			dp.Status = "connected"
		}
		if n >= 5 {
			dp.Enabled = true
		}
		return []displayConnector{panel, dp, hdmi}
	}
	w := awaitExternal(context.Background(), "DP-*", time.Second, seq, logf)
	if w.Connected != "DP-1" || !w.Enabled {
		t.Errorf("DP-*: %+v", w)
	}
	// Only the panel: the wait runs out.
	w = awaitExternal(context.Background(), "any", 30*time.Millisecond, func() []displayConnector { return []displayConnector{panel} }, logf)
	if w.Connected != "" {
		t.Errorf("panel only: %+v", w)
	}
	// Connected but never enabled: it stops waiting for the modeset.
	start := time.Now()
	w = awaitExternal(context.Background(), "HDMI-A-1", time.Minute, seq, logf)
	if w.Connected != "HDMI-A-1" || w.Enabled || time.Since(start) > 10*time.Second {
		t.Errorf("never enabled: %+v after %s", w, time.Since(start))
	}
}

// fakeDisplays points display-check at a fixture: an internal panel, DP-1
// and the kernel logs it reads before and after.
func fakeDisplays(t *testing.T, logs ...string) {
	t.Helper()
	oldClass, oldPlat, oldLog, oldCards, oldDRI := drmClassDir, platformDevicesDir, displayKernelLog, listDisplayCards, debugDRI
	t.Cleanup(func() {
		drmClassDir, platformDevicesDir, displayKernelLog, listDisplayCards, debugDRI = oldClass, oldPlat, oldLog, oldCards, oldDRI
	})
	drmClassDir, platformDevicesDir, debugDRI = t.TempDir(), t.TempDir(), t.TempDir()
	writeFiles(t, drmClassDir, map[string]string{
		"card0-eDP-1/status": "connected\n", "card0-eDP-1/enabled": "enabled\n", "card0-eDP-1/modes": "3024x1964\n",
		"card0-DP-1/status": "connected\n", "card0-DP-1/enabled": "enabled\n", "card0-DP-1/modes": "2560x1440\n",
		"card0-DP-1/edid": string(testEDID(t)),
	})
	writeFiles(t, platformDevicesDir, map[string]string{
		"31ac00000.dcp/of_node/compatible": "apple,t8122-dcpext\x00apple,dcpext\x00",
		"31ac00000.dcp/driver":             "->../drivers/apple-dcp",
	})
	writeFiles(t, debugDRI, map[string]string{"0/state": testDRMState})
	listDisplayCards = func() []string { return []string{"/dev/dri/card0"} }
	n := 0
	displayKernelLog = func(context.Context) (string, error) {
		l := logs[min(n, len(logs)-1)]
		n++
		return l, nil
	}
}

func readReport(t *testing.T, dir string) displayReport {
	t.Helper()
	var r displayReport
	b, err := os.ReadFile(filepath.Join(dir, "display.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDisplayCheck(t *testing.T) {
	fakeDisplays(t, "apple-dart 382f00000.dart: block exception: status:0x4\n")
	out := t.TempDir()
	spec := api.TestSpec{Name: "display-check", Builtin: api.DisplayCheckTest, Display: &api.DisplayCheck{Expect: "DP-1", WaitSec: 1}}
	res := displayCheck(context.Background(), spec, "7.2.11-ARCH", out)
	if !res.Passed || res.ExitCode != 0 {
		t.Fatalf("result %+v", res)
	}
	r := readReport(t, out)
	if len(r.Connectors) != 2 || r.Connectors[1].Name != "DP-1" || r.Connectors[1].CurrentMode != "2560x1440@60" || r.Connectors[1].CRTC != "crtc-1" {
		t.Errorf("connectors: %+v", r.Connectors)
	}
	if !r.DCPextBound || r.DARTFaults != 1 || r.NewDARTFaults != 0 || r.Wait == nil || r.Wait.Connected != "DP-1" || len(r.Outputs) != 2 {
		t.Errorf("report: %+v", r)
	}
	sum, _ := os.ReadFile(filepath.Join(out, "summary.txt"))
	for _, w := range []string{"card0 DP-1: connected, enabled, mode 2560x1440@60 on crtc-1", `DEL, product 0xa0c3, "DELL U2721DE"`, "serial redacted", "dcpext 31ac00000.dcp: bound to apple-dcp", "PASS"} {
		if !strings.Contains(string(sum), w) {
			t.Errorf("summary lacks %q:\n%s", w, sum)
		}
	}
	for _, f := range []string{"display.json", "summary.txt", "log.txt"} {
		b, _ := os.ReadFile(filepath.Join(out, f))
		if strings.Contains(string(b), "SECRETSN0042") {
			t.Errorf("%s carries the EDID serial", f)
		}
	}
}

func TestDisplayCheckFails(t *testing.T) {
	crash := "apple-dcp 31ac00000.dcp: RTKit: co-processor has crashed\n"
	fault := "apple-dart 31a304000.iommu: translation fault: SID:2 read NO PTE at 0x1000 (status 0x1)\n"
	for _, c := range []struct {
		name    string
		logs    []string
		display *api.DisplayCheck
		want    string // "" passes
	}{
		{"quiet", []string{""}, nil, ""},
		{"fault before the check is informational", []string{fault, fault}, nil, ""},
		{"fault during the check", []string{"", fault}, nil, "1 DART fault(s) during the check"},
		{"crash this boot", []string{crash}, nil, "1 DCP crash(es) this boot"},
		{"expected connector absent", []string{""}, &api.DisplayCheck{Expect: "HDMI-*", WaitSec: 1}, "expected external connector HDMI-* did not connect in time"},
		{"waiting without expecting", []string{""}, &api.DisplayCheck{WaitSec: 1}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func(p time.Duration) { displayPoll = p }(displayPoll)
			displayPoll = 10 * time.Millisecond
			fakeDisplays(t, c.logs...)
			// Only the panel is connected, so a wait finds nothing.
			os.WriteFile(filepath.Join(drmClassDir, "card0-DP-1/status"), []byte("disconnected\n"), 0o644)
			out := t.TempDir()
			res := displayCheck(context.Background(), api.TestSpec{Name: "display-check", Builtin: api.DisplayCheckTest, Display: c.display}, "k", out)
			r := readReport(t, out)
			if c.want == "" {
				if !res.Passed || !r.Passed || len(r.Failures) > 0 {
					t.Errorf("want a pass: %+v %v", res, r.Failures)
				}
				return
			}
			if res.Passed || res.ExitCode != 1 || !slices.Contains(r.Failures, c.want) {
				t.Errorf("want %q: %+v %v", c.want, res, r.Failures)
			}
		})
	}
}
