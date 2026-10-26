package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var officialExportFiles = []string{"signature.sshsig", "allowed-signers", "report.json", "unit-start.json", "unit-before-stop.json", "journal-final.jsonl", "observer-final.json", "child.stdout", "child.stderr", "unit-terminal.json", "observations.json", "identity.json", "source-closure.json", "cleanup.json"}

func validateOfficialExport(out, job, boot, kernel, manifest string, result *api.MesaOfficialResult) error {
	if result == nil || result.Status != "PASS" || result.NativeInvocations != 65 || !result.SignatureVerified || result.SourceCommit != mesa.OfficialCommit || result.ArchiveSHA256 != mesa.OfficialArchiveSHA || result.ReportPath != "official/report.json" || result.SealPath != "official/seal.json" {
		return errors.New("official suite/export incomplete")
	}
	dir := filepath.Join(out, "official")
	path := filepath.Join(dir, "seal.json")
	data, err := readOfficialExport(path, 256<<10)
	if err != nil {
		return err
	}
	if mesa.Sum(data) != result.SealSHA256 {
		return errors.New("official seal bytes mismatch")
	}
	var seal struct {
		Schema      int    `json:"schema"`
		Status      string `json:"status"`
		Job         string `json:"job"`
		BootID      string `json:"boot_id"`
		Kernel      string `json:"kernel"`
		Manifest    string `json:"manifest_sha256"`
		Source      string `json:"source_commit"`
		Archive     string `json:"archive_sha256"`
		Invocations int    `json:"native_invocations"`
		Verified    bool   `json:"signature_verified"`
		Report      string `json:"report_sha256"`
		Files       map[string]struct {
			SHA   string `json:"sha256"`
			Bytes int64  `json:"bytes"`
		} `json:"files"`
	}
	if err = json.Unmarshal(data, &seal); err != nil {
		return err
	}
	if seal.Schema != 1 || seal.Status != "PASS" || seal.Job != job || seal.BootID != boot || seal.Kernel != kernel || seal.Manifest != manifest || seal.Source != mesa.OfficialCommit || seal.Archive != mesa.OfficialArchiveSHA || seal.Invocations != 65 || !seal.Verified || seal.Report != result.ReportSHA256 || len(seal.Files) != len(officialExportFiles) {
		return errors.New("official seal job/protocol/identity mismatch")
	}
	var total int64
	for _, name := range officialExportFiles {
		pin, ok := seal.Files[name]
		if !ok || pin.Bytes < 0 || pin.Bytes > 4<<20 {
			return errors.New("official export file set/size mismatch")
		}
		total += pin.Bytes
		if total > 32<<20 {
			return errors.New("official export total budget")
		}
		b, e := readOfficialExport(filepath.Join(dir, name), 4<<20)
		if e != nil {
			return e
		}
		if int64(len(b)) != pin.Bytes || mesa.Sum(b) != pin.SHA {
			return fmt.Errorf("official export %s drift", name)
		}
	}
	if seal.Files["report.json"].SHA != result.ReportSHA256 {
		return errors.New("official report pin mismatch")
	}
	return nil
}

// Reopen the sealed root producer's files independently. Production runs as
// root; CPU fixtures use their own UID and never adopt another user's output.
func readOfficialExport(path string, limit int64) ([]byte, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		st, err := os.Lstat(parent)
		if err != nil || !st.IsDir() {
			return nil, errors.New("official export ancestry type")
		}
		raw, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (raw.Uid != 0 && raw.Uid != uint32(os.Geteuid())) || (st.Mode().Perm()&0022 != 0 && !(raw.Uid == 0 && st.Mode()&os.ModeSticky != 0)) {
			return nil, errors.New("official export ancestry ownership")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	f, err := mesa.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pin, ok := before.Sys().(*syscall.Stat_t)
	if !ok || pin.Uid != uint32(os.Geteuid()) || before.Mode().Perm()&0022 != 0 || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("official export ownership/mode/size")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	live, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	same := func(st os.FileInfo) bool {
		now, ok := st.Sys().(*syscall.Stat_t)
		return ok && st.Mode().IsRegular() && now.Dev == pin.Dev && now.Ino == pin.Ino && now.Mode == pin.Mode && now.Uid == pin.Uid && now.Gid == pin.Gid && now.Size == pin.Size && now.Mtim == pin.Mtim && now.Ctim == pin.Ctim
	}
	if int64(len(body)) != before.Size() || !same(after) || !same(live) {
		return nil, errors.New("official export read/path drift")
	}
	return body, nil
}
