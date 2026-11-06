package agent

import (
	"slices"
	"strings"
	"testing"
)

// testDRMState is drm_state_dump's text for an Apple card with the internal
// panel on crtc-0 and an external monitor on crtc-1 (the dcpext), plus an
// overlay plane above the external's primary and a disconnected DP-2.
const testDRMState = "plane[31]: plane-0\n" +
	"\tcrtc=crtc-0\n\tfb=60\n\t\tallocated by = Hyprland\n\t\trefcount=2\n\t\tformat=XR24 little-endian (0x34325258)\n\t\tsize=3024x1964\n" +
	"\tcrtc-pos=3024x1964+0+0\n\tsrc-pos=3024.000000x1964.000000+0.000000+0.000000\n\trotation=1\n\tnormalized-zpos=0\n\tcolor-encoding=ITU-R BT.601 YCbCr\n" +
	"plane[32]: plane-1\n\tcrtc=(null)\n\tfb=0\n\tcrtc-pos=0x0+0+0\n\tnormalized-zpos=0\n" +
	"plane[37]: plane-3\n\tcrtc=crtc-1\n\tfb=64\n\t\tsize=256x256\n\tnormalized-zpos=1\n" +
	"plane[36]: plane-2\n\tcrtc=crtc-1\n\tfb=62\n\t\tsize=2560x1440\n\tnormalized-zpos=0\n" +
	"crtc[33]: crtc-0\n\tenable=1\n\tactive=1\n\tself_refresh_active=0\n\tplane_mask=1\n\tconnector_mask=1\n\tencoder_mask=1\n" +
	"\tmode: \"3024x1964\": 120 741870 3024 3056 3088 3120 1964 1967 1970 1980 0x48 0x9\n\tbackground_color=0\n" +
	"crtc[38]: crtc-1\n\tenable=1\n\tactive=1\n\tplane_mask=c\n" +
	"\tmode: \"2560x1440\": 60 241500 2560 2608 2640 2720 1440 1443 1448 1481 0x48 0x9\n" +
	"crtc[40]: crtc-2\n\tenable=0\n\tactive=0\n\tmode: \"\": 0 0 0 0 0 0 0 0 0 0 0x0 0x0\n" +
	"connector[35]: eDP-1\n\tcrtc=crtc-0\n\tself_refresh_aware=0\n\tmax_requested_bpc=0\n\tcolorspace=Default\n" +
	"connector[39]: DP-1\n\tcrtc=crtc-1\n\tself_refresh_aware=0\n" +
	"connector[41]: DP-2\n\tcrtc=(null)\n" +
	"resource mapping:\n\tcrtc=crtc-9\n"

func TestActiveOutputs(t *testing.T) {
	s := parseDRMState(testDRMState)
	if len(s.Planes) != 4 || len(s.CRTCs) != 3 || len(s.Connectors) != 3 {
		t.Fatalf("parsed %d planes, %d crtcs, %d connectors", len(s.Planes), len(s.CRTCs), len(s.Connectors))
	}
	got := activeOutputs("card0", s)
	want := []drmOutput{
		{Card: "card0", Connector: "eDP-1", CRTCID: 33, CRTC: "crtc-0", PlaneID: 31, Mode: "3024x1964@120", FBSize: "3024x1964"},
		{Card: "card0", Connector: "DP-1", CRTCID: 38, CRTC: "crtc-1", PlaneID: 36, Mode: "2560x1440@60", FBSize: "2560x1440"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("outputs:\n got %+v\nwant %+v", got, want)
	}
	// The external's CRTC switched off: only the panel is left.
	off := strings.Replace(testDRMState, "crtc[38]: crtc-1\n\tenable=1\n\tactive=1", "crtc[38]: crtc-1\n\tenable=1\n\tactive=0", 1)
	if got := activeOutputs("card0", parseDRMState(off)); len(got) != 1 || got[0].Connector != "eDP-1" {
		t.Errorf("inactive CRTC: %+v", got)
	}
	if got := activeOutputs("card0", parseDRMState("")); len(got) != 0 {
		t.Errorf("empty state: %+v", got)
	}
}

func TestOutputLabel(t *testing.T) {
	all := []drmOutput{{Card: "card0", Connector: "eDP-1"}, {Card: "card0", Connector: "DP-1"}, {Card: "card1", Connector: "DP-1"}}
	var got []string
	for _, o := range all {
		got = append(got, outputLabel(o, all))
	}
	if want := []string{"eDP-1", "card0-DP-1", "card1-DP-1"}; !slices.Equal(got, want) {
		t.Errorf("labels %q, want %q", got, want)
	}
}

func TestKmsgrabArgs(t *testing.T) {
	a := strings.Join(kmsgrabArgs("/dev/dri/card0", 36, "/x.jpg"), " ")
	if !strings.Contains(a, "-device /dev/dri/card0 -f kmsgrab -plane_id 36 -i -") || !strings.HasSuffix(a, " /x.jpg") {
		t.Errorf("args: %s", a)
	}
	if a := strings.Join(kmsgrabArgs("/dev/dri/card0", 0, "/x.jpg"), " "); strings.Contains(a, "plane_id") {
		t.Errorf("plane 0 picks a plane: %s", a)
	}
}
