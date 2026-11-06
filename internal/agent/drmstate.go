package agent

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

// drmState is a card's atomic state as debugfs prints it
// (/sys/kernel/debug/dri/<minor>/state): its planes, CRTCs and connectors.
// On Apple Silicon the internal panel's DCP and each dcpext are separate
// CRTCs of one card.
type drmState struct {
	Planes     []drmPlane
	CRTCs      []drmCRTC
	Connectors []drmConnector
}

type drmPlane struct {
	ID     int
	Name   string
	CRTC   string // the CRTC's name, "" when the plane is off
	FB     int    // framebuffer id, 0 when nothing is scanned out
	FBSize string // WxH of the framebuffer
	ZPos   int    // normalized-zpos: 0 is the bottom (primary) plane
}

type drmCRTC struct {
	ID     int
	Name   string
	Enable bool
	Active bool
	Mode   string // "3024x1964@120"; "" with no mode
}

type drmConnector struct {
	ID   int
	Name string
	CRTC string // "" when the connector drives nothing
}

// drmOutput is one active display: a connector, the CRTC driving it, and the
// bottom plane with a framebuffer on that CRTC, which kmsgrab captures.
type drmOutput struct {
	Card      string `json:"card"`
	Connector string `json:"connector"`
	CRTCID    int    `json:"crtc_id"`
	CRTC      string `json:"crtc"`
	PlaneID   int    `json:"plane_id"`
	Mode      string `json:"mode,omitempty"`
	FBSize    string `json:"fb_size,omitempty"`
}

var (
	reStateHead = regexp.MustCompile(`^(plane|crtc|connector)\[(\d+)\]: (.+)$`)
	// DRM_MODE_FMT: "name": vrefresh clock hdisplay ...
	reStateMode = regexp.MustCompile(`^mode: "([^"]*)": (\d+)`)
)

// parseDRMState reads drm_state_dump's text. Anything it doesn't know (a
// driver's own lines, private objects) is skipped.
func parseDRMState(text string) drmState {
	var s drmState
	kind := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := reStateHead.FindStringSubmatch(line); m != nil {
			id, _ := strconv.Atoi(m[2])
			kind = m[1]
			switch kind {
			case "plane":
				s.Planes = append(s.Planes, drmPlane{ID: id, Name: m[3]})
			case "crtc":
				s.CRTCs = append(s.CRTCs, drmCRTC{ID: id, Name: m[3]})
			case "connector":
				s.Connectors = append(s.Connectors, drmConnector{ID: id, Name: m[3]})
			}
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			kind = "" // a top-level line this parser doesn't know
			continue
		}
		depth := len(line) - len(strings.TrimLeft(line, "\t"))
		key, val, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch kind {
		case "plane":
			p := &s.Planes[len(s.Planes)-1]
			switch {
			case depth == 1 && key == "crtc":
				p.CRTC = nullName(val)
			case depth == 1 && key == "fb":
				p.FB, _ = strconv.Atoi(val)
			case depth == 2 && key == "size":
				p.FBSize = val
			case depth == 1 && key == "normalized-zpos":
				z, _ := strconv.ParseInt(val, 16, 32)
				p.ZPos = int(z)
			}
		case "crtc":
			c := &s.CRTCs[len(s.CRTCs)-1]
			switch {
			case depth == 1 && key == "enable":
				c.Enable = val == "1"
			case depth == 1 && key == "active":
				c.Active = val == "1"
			case depth == 1:
				if m := reStateMode.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] != "" {
					c.Mode = m[1] + "@" + m[2]
				}
			}
		case "connector":
			if depth == 1 && key == "crtc" {
				s.Connectors[len(s.Connectors)-1].CRTC = nullName(val)
			}
		}
	}
	return s
}

func nullName(v string) string {
	if v == "(null)" {
		return ""
	}
	return v
}

// activeOutputs lists the connectors driven by an active CRTC that scans
// out a framebuffer, internal panels first, then by name. Each gets the
// bottom plane with a framebuffer on its CRTC.
func activeOutputs(card string, s drmState) []drmOutput {
	var outs []drmOutput
	for _, conn := range s.Connectors {
		if conn.CRTC == "" {
			continue
		}
		i := slices.IndexFunc(s.CRTCs, func(c drmCRTC) bool { return c.Name == conn.CRTC })
		if i < 0 || !s.CRTCs[i].Active {
			continue
		}
		crtc := s.CRTCs[i]
		var plane *drmPlane
		for j := range s.Planes {
			p := &s.Planes[j]
			if p.CRTC != crtc.Name || p.FB == 0 {
				continue
			}
			if plane == nil || p.ZPos < plane.ZPos || p.ZPos == plane.ZPos && p.ID < plane.ID {
				plane = p
			}
		}
		if plane == nil {
			continue
		}
		outs = append(outs, drmOutput{Card: card, Connector: conn.Name, CRTCID: crtc.ID, CRTC: crtc.Name,
			PlaneID: plane.ID, Mode: crtc.Mode, FBSize: plane.FBSize})
	}
	slices.SortStableFunc(outs, func(a, b drmOutput) int {
		if ai, bi := internalConnector(a.Connector), internalConnector(b.Connector); ai != bi {
			if ai {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Connector, b.Connector)
	})
	return outs
}

// internalConnector is a built-in panel's connector type.
func internalConnector(name string) bool {
	for _, p := range []string{"eDP-", "LVDS-", "DSI-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readDRMState reads a card's atomic state from debugfs. ok is false when
// debugfs can't tell (not mounted, or not root).
func readDRMState(card string) (drmState, bool) {
	minor := strings.TrimPrefix(filepath.Base(card), "card")
	b, err := os.ReadFile(filepath.Join(debugDRI, minor, "state"))
	if err != nil {
		return drmState{}, false
	}
	return parseDRMState(string(b)), true
}

// allOutputs lists every card's active outputs. A connector name that two
// cards share is prefixed with its card, so each output has a file name of
// its own.
func allOutputs(cards []string) []drmOutput {
	var outs []drmOutput
	for _, card := range cards {
		if s, ok := readDRMState(card); ok {
			outs = append(outs, activeOutputs(filepath.Base(card), s)...)
		}
	}
	return outs
}

// outputLabel is the output's name in a file name: its connector, or its
// card and connector when another card has a connector of the same name.
func outputLabel(o drmOutput, all []drmOutput) string {
	n := 0
	for _, x := range all {
		if x.Connector == o.Connector {
			n++
		}
	}
	l := o.Connector
	if n > 1 {
		l = o.Card + "-" + o.Connector
	}
	return reUnsafeLabel.ReplaceAllString(l, "_")
}

var reUnsafeLabel = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// shotOutput is one display captured to Path.
type shotOutput struct {
	api.ScreenOutput
	Path string
}

// ScreenshotOutputs captures each active display into dir as
// <connector>.jpg, with kmsgrab on the CRTC's bottom plane. It captures
// nothing (nil, nil) unless two or more displays are active: with one,
// Screenshot has it already. grim, the fallback, captures only one image of
// the whole session, so without kmsgrab there are no per-display captures.
func (l *Linux) ScreenshotOutputs(ctx context.Context, dir string) ([]shotOutput, error) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, nil
	}
	outs := allOutputs(displayCards())
	if len(outs) < 2 {
		return nil, nil
	}
	var shots []shotOutput
	var errs []string
	for _, o := range outs {
		label := outputLabel(o, outs)
		path := filepath.Join(dir, label+".jpg")
		if err := kmsgrabPlane(ctx, "/dev/dri/"+o.Card, o.PlaneID, path); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		b, _ := os.ReadFile(path)
		w, h := jpegSize(b)
		shots = append(shots, shotOutput{ScreenOutput: api.ScreenOutput{Connector: label, Width: w, Height: h}, Path: path})
	}
	if len(errs) > 0 {
		return shots, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return shots, nil
}

// kmsgrabPlane captures one plane's framebuffer.
func kmsgrabPlane(ctx context.Context, card string, plane int, path string) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ffmpeg", kmsgrabArgs(card, plane, path)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(lastLines(string(out), 2)))
	}
	if st, serr := os.Stat(path); serr != nil || st.Size() == 0 {
		return fmt.Errorf("ffmpeg wrote no image")
	}
	return nil
}

// kmsgrabArgs are ffmpeg's arguments for one frame of card's scanout as a
// JPEG: the first plane with a framebuffer when plane is 0, else that plane.
func kmsgrabArgs(card string, plane int, path string) []string {
	args := []string{"-hide_banner", "-loglevel", "error", "-y", "-device", card, "-f", "kmsgrab"}
	if plane > 0 {
		args = append(args, "-plane_id", strconv.Itoa(plane))
	}
	return append(args, "-i", "-", "-frames:v", "1", "-vf", "hwdownload,format=bgr0", "-q:v", "4", path)
}
