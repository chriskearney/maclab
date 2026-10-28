package api

const (
	RecoveryNetworkOnly    = "network-only"
	RecoverySerialAssisted = "serial-assisted"
)

func ValidRecoveryMode(mode string) bool {
	return mode == "" || mode == RecoveryNetworkOnly || mode == RecoverySerialAssisted
}

type RecoveryCapabilities struct {
	Schema               int      `json:"schema"`
	Modes                []string `json:"modes"`
	PerJobOOBIsolation   bool     `json:"per_job_oob_isolation"`
	TransactionIsolation bool     `json:"transaction_isolation"`
}

type RecoveryModeRequest struct {
	Mode        string `json:"mode"`
	Holder      string `json:"holder"`
	Transaction string `json:"transaction"`
}
type RecoveryModeSelection struct {
	Schema      int    `json:"schema"`
	Device      string `json:"device"`
	Mode        string `json:"mode"`
	Holder      string `json:"holder"`
	Transaction string `json:"transaction"`
	Quiescent   bool   `json:"quiescent"`
}
