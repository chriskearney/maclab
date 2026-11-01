package loop

import _ "embed"

// ChaosCheckScript is the chaos-check script test every boot of the night
// runs.
//
//go:embed chaos-check.sh
var ChaosCheckScript []byte
