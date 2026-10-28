package esprotation

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func bliFixture(s string) []byte {
	b := []byte{7, 0, 0, 0}
	for _, r := range append(utf16.Encode([]rune(s)), 0) {
		b = binary.LittleEndian.AppendUint16(b, r)
	}
	return b
}
func TestReviewedLimineBLIContract(t *testing.T) {
	for _, v := range []string{"Limine 12.9.0", "Limine 12.9.1", "Limine 12.9.3"} {
		t.Run(v, func(t *testing.T) {
			files := map[string]string{}
			err := observeBLI(Plan{Entry: "SiliconForest/old"}, bliFixture(v), func(n string) ([]byte, error) {
				if n == "LoaderEntrySelected" {
					return bliFixture("Omarchy.linux-aurora"), nil
				}
				return nil, nil
			}, files)
			if err != nil {
				t.Fatal(err)
			}
			if files["BLI:LoaderInfo"] != Digest(bliFixture(v)) || files["BLI:LoaderEntrySelected"] != Digest(bliFixture("Omarchy.linux-aurora")) || files["BLI:LoaderEntryDefault"] != Digest(nil) || files["BLI:LoaderEntryOneShot"] != Digest(nil) {
				t.Fatal("BLI identity pins lost")
			}
		})
	}
	for _, v := range []string{"", "Limine 12.9.2", "Limine 12.9.10", "Limine 12.9.1-custom", "limine 12.9.1", "Limine 13.0.0"} {
		if err := observeBLI(Plan{}, bliFixture(v), func(string) ([]byte, error) { t.Fatal("unreviewed version read entry variables"); return nil, nil }, map[string]string{}); err == nil {
			t.Fatalf("unreviewed version admitted: %q", v)
		}
	}
}
func TestLimine1291BLIProtectionRetained(t *testing.T) {
	for _, tc := range []struct{ name, variable, value, want string }{
		{"selected", "LoaderEntrySelected", "SiliconForest.old", "current selected entry is protected"},
		{"default", "LoaderEntryDefault", "SiliconForest.old", "BLI default entry is protected"},
		{"oneshot", "LoaderEntryOneShot", "unrelated.entry", "armed one-shot protected"},
		{"empty-selected", "LoaderEntrySelected", "", "selected BLI entry required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := observeBLI(Plan{Entry: "/SiliconForest/old"}, bliFixture("Limine 12.9.1"), func(n string) ([]byte, error) {
				if n == tc.variable {
					return bliFixture(tc.value), nil
				}
				if n == "LoaderEntrySelected" {
					return bliFixture("Omarchy.linux-aurora"), nil
				}
				return nil, nil
			}, map[string]string{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("protection drift: %v", err)
			}
		})
	}
	sentinel := errors.New("read failed")
	if err := observeBLI(Plan{}, bliFixture("Limine 12.9.1"), func(string) ([]byte, error) { return nil, sentinel }, map[string]string{}); !errors.Is(err, sentinel) {
		t.Fatal("EFI read error swallowed")
	}
}
func TestLimine1291EntryIDAndCollisionRefusal(t *testing.T) {
	for _, tc := range []struct{ path, id string }{
		{"/Omarchy/linux-aurora", "Omarchy.linux-aurora"},
		{"/SiliconForest/old +_@.-", "SiliconForest.old-+_@.-"},
		{"/", "-"}, {"/.", ".-"}, {"/..", "..-"},
		{"/" + strings.Repeat("a", 240), strings.Repeat("a", 232)},
	} {
		if got := entryID(tc.path); got != tc.id {
			t.Fatalf("%q -> %q want %q", tc.path, got, tc.id)
		}
	}
	if _, _, err := parseMenu([]byte("/a b\npath: boot():/one.efi\n/a-b\npath: boot():/two.efi\n")); err == nil {
		t.Fatal("colliding upstream-suffixed IDs must remain conservative refusal")
	}
	if _, _, err := parseMenu([]byte("/one\npath: boot():/one.efi\n/one\npath: boot():/two.efi\n")); err == nil {
		t.Fatal("duplicate ID accepted")
	}
}
