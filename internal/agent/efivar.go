package agent

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unicode/utf16"
)

// efivarsDir is where efivarfs is mounted (a temp dir in tests).
var efivarsDir = "/sys/firmware/efi/efivars"

const (
	// systemd's Boot Loader Interface vendor GUID (LoaderEntryOneShot, LoaderInfo, ...).
	bliGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
	// U-Boot's vendor GUID for RTStorageVolatile and VarToFile.
	ubootVarGUID = "b2ac5fc9-92b7-4acd-aeac-11e818c3130c"

	efiVarNV = 0x1 // non-volatile
	efiVarBS = 0x2 // boot service access
	efiVarRT = 0x4 // runtime access
)

func efivarPath(name, guid string) string {
	return filepath.Join(efivarsDir, name+"-"+guid)
}

// readEfivar returns a variable's attributes and data. efivarfs files hold
// the 4-byte attributes followed by the data.
func readEfivar(name, guid string) (uint32, []byte, error) {
	b, err := os.ReadFile(efivarPath(name, guid))
	if err != nil {
		return 0, nil, err
	}
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("efivar %s: short read", name)
	}
	return binary.LittleEndian.Uint32(b), b[4:], nil
}

// writeEfivar creates or replaces a variable. efivarfs marks most variables
// immutable and takes attributes and data in a single write.
func writeEfivar(name, guid string, attrs uint32, data []byte) error {
	p := efivarPath(name, guid)
	if _, err := os.Stat(p); err == nil {
		exec.Command("chattr", "-i", p).Run()
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("efivar %s: %w", name, err)
	}
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(buf, attrs)
	copy(buf[4:], data)
	_, werr := f.Write(buf)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("efivar %s: %w", name, werr)
	}
	return cerr
}

func deleteEfivar(name, guid string) error {
	p := efivarPath(name, guid)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil
	}
	exec.Command("chattr", "-i", p).Run()
	return os.Remove(p)
}

// utf16z encodes s as the NUL-terminated UTF-16LE string EFI variables carry.
func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u)+2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func fromUTF16z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
