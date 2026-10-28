package server

import "testing"

func TestVersionAtLeastBuildMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, have, want string
		ok               bool
	}{
		{"installed GUI agent", "0.7.5+gui-workspace", "0.7.2", true},
		{"metadata at minimum", "0.7.2+gui-workspace", "0.7.2", true},
		{"dotted metadata", "0.7.5+gui.workspace.12", "0.7.2", true},
		{"numeric metadata", "0.7.2+001", "0.7.2", true},
		{"metadata on minimum", "0.7.2", "0.7.2+release.1", true},
		{"different metadata same version", "0.7.2+local.2", "0.7.2+release.9", true},
		{"older patch stays old", "0.7.1+gui-workspace", "0.7.2", false},
		{"older minor stays old", "0.6.99+gui-workspace", "0.7.2", false},
		{"promotion minimum stays enforced", "0.7.2+gui-workspace", "0.7.3", false},
		{"newer patch", "0.7.5", "0.7.2", true},
		{"exact release", "0.7.2", "0.7.2", true},
		{"missing agent", "", "0.7.2", false},
		{"development sentinel", "dev", "0.7.2", false},
		{"empty metadata is not stripped", "0.7.2+", "0.7.2", false},
		{"empty metadata identifier is not stripped", "0.7.2+gui..1", "0.7.2", false},
		{"invalid metadata is not stripped", "0.7.2+gui_workspace", "0.7.2", false},
		{"duplicate plus is not stripped", "0.7.2+gui+1", "0.7.2", false},
		{"malformed core is not stripped", "broken.7.5+gui", "0.7.2", false},
		{"leading zero core is not stripped", "0.7.02+gui", "0.7.2", false},
		{"prerelease is not a release", "0.7.2-rc.1+gui", "0.7.2", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionAtLeast(tt.have, tt.want); got != tt.ok {
				t.Fatalf("versionAtLeast(%q, %q) = %t; want %t", tt.have, tt.want, got, tt.ok)
			}
		})
	}
}
