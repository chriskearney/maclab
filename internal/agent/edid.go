package agent

import (
	"fmt"
	"strings"
)

// edidInfo is what display-check records of a connector's EDID. It never
// holds the EDID's serial number, neither the numeric one in the base block
// nor a serial-number descriptor: SerialRedacted says one was there. Nor the
// raw EDID, which carries them, or its unspecified-text descriptors, which
// some vendors fill with one.
type edidInfo struct {
	Present bool   `json:"present"`
	Bytes   int    `json:"bytes,omitempty"`
	Valid   bool   `json:"valid"` // a base block with the header and a good checksum
	Problem string `json:"problem,omitempty"`
	// Manufacturer is the PNP ID, e.g. DEL or GSM.
	Manufacturer   string `json:"manufacturer,omitempty"`
	ProductCode    string `json:"product_code,omitempty"` // e.g. 0xa0c3
	MonitorName    string `json:"monitor_name,omitempty"`
	Year           int    `json:"year,omitempty"` // of manufacture, or the model year
	Version        string `json:"version,omitempty"`
	WidthMM        int    `json:"width_mm,omitempty"`
	HeightMM       int    `json:"height_mm,omitempty"`
	PreferredMode  string `json:"preferred_mode,omitempty"` // from the first detailed timing, e.g. 2560x1440@60
	Extensions     int    `json:"extensions,omitempty"`
	SerialRedacted bool   `json:"serial_redacted,omitempty"`
}

var edidHeader = []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}

// parseEDID reads an EDID's base block.
func parseEDID(b []byte) edidInfo {
	e := edidInfo{Present: len(b) > 0, Bytes: len(b)}
	switch {
	case len(b) == 0:
		return e
	case len(b) < 128:
		e.Problem = fmt.Sprintf("short EDID: %d bytes", len(b))
		return e
	case string(b[:8]) != string(edidHeader):
		e.Problem = "no EDID header"
		return e
	}
	var sum byte
	for _, c := range b[:128] {
		sum += c
	}
	e.Valid = sum == 0
	if !e.Valid {
		e.Problem = "bad base block checksum"
	}
	m := uint16(b[8])<<8 | uint16(b[9])
	letters := []byte{byte(m>>10&0x1f) + '@', byte(m>>5&0x1f) + '@', byte(m&0x1f) + '@'}
	if l := string(letters); strings.Trim(l, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
		e.Manufacturer = l
	}
	e.ProductCode = fmt.Sprintf("0x%04x", uint16(b[10])|uint16(b[11])<<8)
	if b[12]|b[13]|b[14]|b[15] != 0 {
		e.SerialRedacted = true
	}
	if b[17] != 0 {
		e.Year = 1990 + int(b[17])
	}
	e.Version = fmt.Sprintf("%d.%d", b[18], b[19])
	e.WidthMM, e.HeightMM = int(b[21])*10, int(b[22])*10
	e.Extensions = int(b[126])
	for i := range 4 {
		d := b[54+18*i : 72+18*i]
		if d[0] == 0 && d[1] == 0 {
			switch d[3] {
			case 0xfc: // display product name
				e.MonitorName += edidText(d[5:])
			case 0xff: // display serial number
				e.SerialRedacted = true
			}
			continue
		}
		if i == 0 { // the preferred timing
			clock := int(d[0]) | int(d[1])<<8 // 10 kHz
			hact, hblank := int(d[2])|int(d[4]&0xf0)<<4, int(d[3])|int(d[4]&0x0f)<<8
			vact, vblank := int(d[5])|int(d[7]&0xf0)<<4, int(d[6])|int(d[7]&0x0f)<<8
			if tot := (hact + hblank) * (vact + vblank); tot > 0 {
				hz := (clock*10000 + tot/2) / tot
				e.PreferredMode = fmt.Sprintf("%dx%d@%d", hact, vact, hz)
			}
			// The timing's image size is in mm, finer than the cm above.
			if w, h := int(d[12])|int(d[14]&0xf0)<<4, int(d[13])|int(d[14]&0x0f)<<8; w > 0 && h > 0 {
				e.WidthMM, e.HeightMM = w, h
			}
		}
	}
	return e
}

// edidText is a descriptor's text: up to a newline, printable ASCII.
func edidText(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c == '\n' {
			break
		}
		if c >= 0x20 && c < 0x7f {
			s.WriteByte(c)
		}
	}
	return strings.TrimSpace(s.String())
}
