// lab-esp is a standalone, explicitly reviewed rotation helper; it does not run
// as a daemon. Applying a plan requires authorization outside this program.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	esp "github.com/iconidentify/maclab/internal/esprotation"
	"os"
	"path/filepath"
	"time"
)

func fail(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "lab-esp:", e)
		os.Exit(1)
	}
}
func load(path string, v any) []byte {
	b, e := esp.ReadFile(path, 16<<20)
	fail(e)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	fail(d.Decode(v))
	return b
}
func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: lab-esp plan|controller-retain|apply|restore [flags]"))
	}
	if os.Geteuid() != 0 {
		fail(fmt.Errorf("root required"))
	}
	op := os.Args[1]
	f := flag.NewFlagSet(op, flag.ExitOnError)
	planPath := f.String("plan", "", "frozen JSON plan (all operations except plan)")
	planSHA := f.String("plan-sha256", "", "reviewed exact plan bytes SHA256")
	kind := f.String("kind", "uki-leaf", "uki-leaf or unreferenced-m1n1-backup")
	retireOnly := f.Bool("retire-only", false, "retire explicit artifact without claiming capacity to stage next UKI")
	transaction := f.String("transaction", "", "unique transaction name")
	espRoot := f.String("esp", "/boot", "exact directly mounted ESP")
	menu := f.String("menu", "", "exact active limine.conf")
	entry := f.String("entry", "", "exact canonical top-level menu entry, including /")
	uki := f.String("uki", "", "exact UKI absolute path")
	kernel := f.String("kernel", "", "expected UKI .uname")
	sha := f.String("uki-sha256", "", "reviewed UKI SHA256")
	size := f.Int64("uki-size", 0, "exact UKI file size")
	extra := f.Uint64("additional-esp-bytes", 0, "distinct additional live allocations, e.g. exact old6 fallback size; rounded separately")
	next := f.Uint64("next-uki-bytes", 0, "exact privately built next UKI size or reviewed conservative ceiling")
	copies := f.Uint64("next-esp-temporary-copies", 0, "maximum simultaneous NEW UKI allocations on ESP (1 or 2)")
	work := f.String("work-dir", "/var/lib/maclab", "agent work directory")
	archive := f.String("archive-root", "/var/lib/maclab/esp-archives", "non-ESP private local archive (controller-retain uses this on controller)")
	source := f.String("source", "", "controller source copied via authenticated lab channel")
	retention := f.String("retention", "", "fresh controller-retain receipt")
	retentionSHA := f.String("retention-sha256", "", "reviewed exact controller retention receipt SHA256")
	fail(f.Parse(os.Args[2:]))
	env := esp.LiveEnv(*work)
	var p esp.Plan
	if op == "plan" {
		if *menu == "" {
			*menu = filepath.Join(*espRoot, "limine.conf")
		}
		before, e := esp.ReadFile(*menu, 4<<20)
		fail(e)
		after := append([]byte{}, before...)
		if *kind == "uki-leaf" {
			after, e = esp.PrepareMenu(before, *entry)
			fail(e)
		}
		p = esp.Plan{Version: esp.Version, Kind: *kind, RetireOnly: *retireOnly, Transaction: *transaction, ESP: *espRoot, Menu: *menu, Entry: *entry, UKI: *uki, Kernel: *kernel, File: esp.File{SHA256: *sha, Size: *size}, Before: before, After: after, NextUKIBytes: *next, AdditionalESPBytes: *extra, NextESPTemporaryCopies: *copies, Created: time.Now().UTC()}
		p, e = esp.NewPlan(p, env)
		fail(e)
		os.Stdout.Write(esp.JSON(p))
		return
	}
	raw := load(*planPath, &p)
	if esp.Digest(raw) != *planSHA || esp.PlanHash(p) != *planSHA {
		fail(fmt.Errorf("exact reviewed canonical plan SHA required"))
	}
	switch op {
	case "controller-retain":
		id, e := os.ReadFile("/etc/machine-id")
		fail(e)
		r, e := esp.RetainController(p, *source, *archive, string(bytes.TrimSpace(id)), env)
		fail(e)
		os.Stdout.Write(esp.JSON(r))
	case "apply":
		var r esp.Retention
		raw := load(*retention, &r)
		if esp.Digest(raw) != *retentionSHA {
			fail(fmt.Errorf("retention file SHA mismatch"))
		}
		fail(esp.Apply(p, r, *retentionSHA, *archive, env))
	case "restore":
		fail(esp.Restore(p, *archive, env))
	default:
		fail(fmt.Errorf("unknown operation %q", op))
	}
}
