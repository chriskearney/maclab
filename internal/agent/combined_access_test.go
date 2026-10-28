package agent

import (
	"encoding/json"
	"github.com/iconidentify/maclab/internal/api"
	"testing"
)

func TestCombinedMesaCommandsRequireFullOnVolunteer(t *testing.T) {
	probe := api.TestSpec{Name: "mesa-provider", Builtin: "mesa-provider"}
	raw, _ := json.Marshal(probe)
	boot, _ := json.Marshal(api.BootOnceArgs{Tests: []api.TestSpec{probe}})
	for _, c := range []api.Command{
		{Kind: api.CmdMesaStage},
		{Kind: api.CmdRunTest, Args: raw},
		{Kind: api.CmdBootOnce, Args: boot},
	} {
		if !needsFull(c) {
			t.Fatalf("new Mesa command escaped volunteer access gate: %s", c.Kind)
		}
	}
}
