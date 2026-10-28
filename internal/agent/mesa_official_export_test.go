package agent

import (
	"encoding/json"
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
	"os"
	"path/filepath"
	"testing"
)

func TestOfficialSealedExportRereadsAndRejectsPartialOrDriftedFiles(t *testing.T) {
	for _, bad := range []string{"", "missing", "file-drift", "seal-drift", "other-boot", "partial", "unsigned", "extra-path", "symlink", "writable-file", "writable-directory"} {
		t.Run(bad, func(t *testing.T) {
			out := t.TempDir()
			dir := filepath.Join(out, "official")
			os.Mkdir(dir, 0700)
			files := map[string]map[string]any{}
			for _, name := range officialExportFiles {
				data := []byte("CPU export envelope fixture:" + name)
				os.WriteFile(filepath.Join(dir, name), data, 0600)
				files[name] = map[string]any{"sha256": mesa.Sum(data), "bytes": len(data)}
			}
			result := &api.MesaOfficialResult{Status: "PASS", NativeInvocations: 65, SignatureVerified: true, SourceCommit: mesa.OfficialCommit, ArchiveSHA256: mesa.OfficialArchiveSHA, ReportPath: "official/report.json", SealPath: "official/seal.json", ReportSHA256: files["report.json"]["sha256"].(string)}
			seal := map[string]any{"schema": 1, "status": "PASS", "job": "job", "boot_id": "actual-boot", "kernel": "kernel7", "manifest_sha256": "manifest", "source_commit": mesa.OfficialCommit, "archive_sha256": mesa.OfficialArchiveSHA, "native_invocations": 65, "signature_verified": true, "report_sha256": result.ReportSHA256, "files": files}
			switch bad {
			case "missing":
				os.Remove(filepath.Join(dir, "observations.json"))
			case "file-drift":
				os.WriteFile(filepath.Join(dir, "report.json"), []byte("drift"), 0600)
			case "other-boot":
				seal["boot_id"] = "old"
			case "partial":
				result.NativeInvocations = 64
			case "unsigned":
				result.SignatureVerified = false
			case "extra-path":
				delete(files, "cleanup.json")
				files["../foreign"] = map[string]any{"sha256": "foreign", "bytes": 1}
			case "writable-file":
				os.Chmod(filepath.Join(dir, "report.json"), 0666)
			case "writable-directory":
				os.Chmod(dir, 0777)
			case "symlink":
				os.Remove(filepath.Join(dir, "report.json"))
				os.Symlink("../foreign", filepath.Join(dir, "report.json"))
			}
			data, _ := json.Marshal(seal)
			os.WriteFile(filepath.Join(dir, "seal.json"), data, 0600)
			result.SealSHA256 = mesa.Sum(data)
			if bad == "seal-drift" {
				result.SealSHA256 = "drift"
			}
			err := validateOfficialExport(out, "job", "actual-boot", "kernel7", "manifest", result)
			if (bad == "") != (err == nil) {
				t.Fatalf("case=%q err=%v", bad, err)
			}
		})
	}
}
