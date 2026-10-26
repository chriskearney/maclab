package agent

import (
	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/mesa"
)

var officialExportFiles = mesa.OfficialExportNames()

func validateOfficialExport(out, job, boot, kernel, manifest string, result *api.MesaOfficialResult) error {
	return mesa.ValidateOfficialExport(out, job, boot, kernel, manifest, result)
}
