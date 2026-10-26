package server

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

var gcMu sync.Mutex

func (s *Server) gcLoop() {
	s.gcArtifacts()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.gcArtifacts()
		}
	}
}

// pinRows marks every sha256 a one-column query returns as kept and pinned.
// Any query, scan or iteration error is returned, so the GC can stop.
func (s *Server) pinRows(query string, keep, pinned map[string]bool) error {
	rows, err := s.store.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return err
		}
		keep[sha] = true
		pinned[sha] = true
	}
	return rows.Err()
}

// gcArtifacts keeps the artifact store bounded. Anything a recent job, a
// recent build or a device config refers to is kept; everything else is
// deleted once it is a day old. If the store is still over budget, the
// oldest artifacts go first, except those in use by unfinished work, device
// configs and package recipes.
func (s *Server) gcArtifacts() {
	gcMu.Lock()
	defer gcMu.Unlock()
	budget := s.cfg.ArtifactBudget
	if budget <= 0 {
		budget = 20 << 30
	}
	pinned := map[string]bool{} // never deleted: unfinished work
	keep := map[string]bool{}   // deleted only when over budget
	// The references decide what may be deleted, so a reference that cannot
	// be read stops this pass: nothing is deleted on an incomplete picture.
	skip := func(what string, err error) {
		s.log.Printf("artifact gc: skipped, cannot read %s: %v (nothing deleted)", what, err)
	}
	jobs, err := s.store.jobs("", 300, false)
	if err != nil {
		skip("recent jobs", err)
		return
	}
	// Unfinished work is pinned however old it is: the recent window above
	// must never decide whether a queued job still has its artifacts.
	open, err := s.store.jobs("", -1, true)
	if err != nil {
		skip("unfinished jobs", err)
		return
	}
	for _, j := range append(jobs, open...) {
		refs := append([]string{j.Spec.Kernel}, mesaRefs(j.Spec)...)
		for _, t := range j.Spec.Tests {
			refs = append(refs, t.Script)
		}
		for _, r := range refs {
			if r == "" {
				continue
			}
			keep[r] = true
			if j.State != api.JobDone {
				pinned[r] = true
			}
		}
	}
	builds, err := s.store.builds(`1=1 ORDER BY created DESC LIMIT 200`)
	if err != nil {
		skip("builds", err)
		return
	}
	for i, b := range builds {
		if b.ConfigSHA != "" {
			keep[b.ConfigSHA] = true
		}
		if b.Recipe != "" {
			keep[b.Recipe] = true
		}
		if b.State == api.BuildQueued || b.State == api.BuildRunning {
			pinned[b.ConfigSHA] = true
			pinned[b.Recipe] = true
		}
		if i < 20 || time.Since(b.Created) < 14*24*time.Hour {
			if b.Artifact != "" {
				keep[b.Artifact] = true
			}
			for _, f := range b.Files {
				keep[f.SHA256] = true
			}
		}
	}
	// A package recipe is small and is the only record of what a release was
	// built from, so it stays for as long as any build refers to it.
	for _, q := range []struct{ what, sql string }{
		{"build recipes", `SELECT DISTINCT json_extract(data, '$.recipe') FROM builds WHERE json_extract(data, '$.recipe') != ''`},
		{"device configs", `SELECT sha FROM configs`},
	} {
		if err := s.pinRows(q.sql, keep, pinned); err != nil {
			skip(q.what, err)
			return
		}
	}

	type art struct {
		sha  string
		size int64
		mod  time.Time
	}
	dir := filepath.Join(s.cfg.DataDir, "artifacts")
	ents, _ := os.ReadDir(dir)
	var all []art
	var total int64
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if strings.HasPrefix(e.Name(), ".upload-") {
			if time.Since(info.ModTime()) > 24*time.Hour {
				os.Remove(filepath.Join(dir, e.Name()))
			}
			continue
		}
		all = append(all, art{e.Name(), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod.Before(all[j].mod) })
	var freed int64
	var n int
	remove := func(a art) {
		if os.Remove(filepath.Join(dir, a.sha)) == nil {
			total -= a.size
			freed += a.size
			n++
		}
	}
	for _, a := range all {
		if !keep[a.sha] && time.Since(a.mod) > 24*time.Hour {
			remove(a)
		}
	}
	for _, a := range all {
		if total <= budget {
			break
		}
		if !pinned[a.sha] && time.Since(a.mod) > time.Hour {
			if _, err := os.Stat(filepath.Join(dir, a.sha)); err == nil {
				remove(a)
			}
		}
	}
	if n > 0 {
		s.log.Printf("artifact gc: removed %d (%d MB); store now %d MB of %d MB budget", n, freed>>20, total>>20, budget>>20)
	}
}
