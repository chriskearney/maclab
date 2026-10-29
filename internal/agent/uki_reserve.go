package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Allow for the directory entry, atomic menu update and persisted EFI store,
// in addition to the rounded UKI allocation. Do not spend the retained 120MiB
// reserve on these later steps. Only one UKI copy is created on the ESP.
const ukiMetadataAllowance uint64 = 1 << 20

type ukiSpace struct{ Available, Allocation, Device uint64 }
type ukiWriter struct {
	ScratchRoot string
	Build       func(context.Context, string, string, string, string) error
	Lock        func() (func(), error)
	Space       func(string) (ukiSpace, error)
}

func writeUKI(ctx context.Context, krel, image, cmdline, out string) error {
	return writeUKIWith(ctx, krel, image, cmdline, out, ukiWriter{
		ScratchRoot: "/var/lib/maclab", Build: buildUKIFile,
		Lock: func() (func(), error) { return lockBootPartition(time.Minute) }, Space: measureUKISpace,
	})
}
func measureUKISpace(p string) (ukiSpace, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(p, &fs); err != nil {
		return ukiSpace{}, err
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return ukiSpace{}, err
	}
	if fs.Bsize <= 0 {
		return ukiSpace{}, fmt.Errorf("invalid filesystem allocation size")
	}
	return ukiSpace{uint64(fs.Bavail) * uint64(fs.Bsize), uint64(fs.Bsize), uint64(st.Dev)}, nil
}

func writeUKIWith(ctx context.Context, krel, image, cmdline, out string, w ukiWriter) error {
	// Private scratch is root-owned in production, outside the FAT staging
	// volume. It carries the generator's .tmp and command line, never the ESP.
	if _, err := ukiScratchPath(w.ScratchRoot); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(w.ScratchRoot, "uki-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	scratchSpace, err := w.Space(scratch)
	if err != nil {
		return err
	}
	destinationSpace, err := w.Space(filepath.Dir(out))
	if err != nil {
		return err
	}
	if scratchSpace.Device == destinationSpace.Device {
		return fmt.Errorf("UKI scratch and destination must be on different filesystems")
	}
	built := filepath.Join(scratch, "uki.efi")
	if err := w.Build(ctx, krel, image, cmdline, built); err != nil {
		return err
	}
	st, err := os.Lstat(built)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 {
		return fmt.Errorf("generator did not produce a regular nonempty UKI")
	}
	expected, err := fileSHA256(built)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := w.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	free, err := w.Space(filepath.Dir(out))
	if err != nil {
		return err
	}
	if free.Device != destinationSpace.Device || free.Device == scratchSpace.Device {
		return fmt.Errorf("UKI destination filesystem changed")
	}
	needed, err := ukiRequiredSpace(uint64(st.Size()), free.Allocation)
	if err != nil {
		return err
	}
	if free.Available < needed {
		return fmt.Errorf("ESP reserve: need %d bytes free for UKI allocation plus retained reserve and metadata, have %d", needed, free.Available)
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".maclab-uki-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	src, err := os.Open(built)
	if err != nil {
		tmp.Close()
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), src)
	src.Close()
	if err == nil && n != st.Size() {
		err = fmt.Errorf("UKI changed size while copying")
	}
	if err == nil && hex.EncodeToString(hash.Sum(nil)) != expected {
		err = fmt.Errorf("UKI changed while copying")
	}
	if err == nil {
		err = tmp.Sync()
	}
	if e := tmp.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	got, err := fileSHA256(name)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("ESP UKI readback does not match built bytes")
	}
	// This catches other space consumption before publishing any boot entry.
	// Cooperative boot writers remain excluded through copy/fsync/rename.
	free, err = w.Space(filepath.Dir(out))
	if err != nil {
		return err
	}
	if free.Device != destinationSpace.Device {
		return fmt.Errorf("UKI destination filesystem changed after copy")
	}
	if free.Available < limineMinFree+ukiMetadataAllowance {
		return fmt.Errorf("ESP reserve no longer available after UKI copy")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(name, out); err != nil {
		return err
	}
	if err := syncFile(filepath.Dir(out)); err != nil {
		return err
	}
	got, err = fileSHA256(out)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("published UKI readback mismatch")
	}
	return nil
}
func ukiRequiredSpace(size, allocation uint64) (uint64, error) {
	max := ^uint64(0)
	if size == 0 || allocation == 0 || size > max-(allocation-1) {
		return 0, fmt.Errorf("invalid UKI allocation size")
	}
	rounded := (size + allocation - 1) / allocation * allocation
	overhead := uint64(limineMinFree) + ukiMetadataAllowance
	if rounded > max-overhead {
		return 0, fmt.Errorf("UKI allocation overflow")
	}
	return rounded + overhead, nil
}

// buildUKIFile preserves the existing generator and flags. All generated
// output is now in private non-ESP scratch until its size is known.
func buildUKIFile(ctx context.Context, krel, image, cmdline, out string) error {
	ictx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	f, err := os.CreateTemp(filepath.Dir(out), "cmdline-")
	if err != nil {
		return err
	}
	cmdFile := f.Name()
	defer os.Remove(cmdFile)
	_, err = f.WriteString(cmdline + "\n")
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	if _, err := exec.LookPath("mkinitcpio"); err == nil {
		cmd = exec.CommandContext(ictx, "mkinitcpio", "-k", krel, "-U", out, "--kernelimage", image, "--cmdline", cmdFile)
	} else {
		cmd = exec.CommandContext(ictx, "dracut", "--force", "--uefi", "--kver", krel, "--kernel-image", image, "--kernel-cmdline", cmdline, out)
	}
	if result, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("UKI: %v: %s", err, lastLines(string(result), 15))
	}
	return syncFile(out)
}

// Only the private generator workspace is validated here; this change does not
// relax existing kernel/module admission. Path aliases may redirect writes to
// the ESP and therefore fail before any generator command.
func ukiScratchPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if abs != real {
		return "", fmt.Errorf("refusing UKI scratch alias")
	}
	return abs, nil
}

// ukiSizeGuess is the UKI size preflight assumes when the ESP has none of its
// own to measure. Omarchy's Asahi UKIs are about 60 MiB.
const ukiSizeGuess uint64 = 64 << 20

// largestUKI is the biggest UKI under <esp>/EFI/Linux, where Limine's tools
// put the Mac's own. A staged test kernel is built from the known-good kernel
// and an initramfs like theirs, so it is about that size. "" and 0: none.
func largestUKI(esp string) (string, uint64) {
	var name string
	var size uint64
	filepath.WalkDir(filepath.Join(esp, "EFI", "Linux"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".efi") {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() && uint64(info.Size()) > size {
			name, size = p, uint64(info.Size())
		}
		return nil
	})
	return name, size
}

// limineStageProblem says why the ESP can't take a staged test kernel, or ""
// if it can. free is what staging may use (staged jobs count as free: a job
// cleans them up first); allocation is the ESP's allocation unit. The need is
// what writeUKIWith checks before it copies a UKI: the UKI, rounded up, plus
// the retained reserve and the metadata allowance.
func limineStageProblem(esp, stage string, free, allocation uint64) string {
	name, size := largestUKI(esp)
	what := "the size of " + name
	if size == 0 {
		size, what = ukiSizeGuess, "a guess: there is no UKI in "+filepath.Join(esp, "EFI", "Linux")+" to measure"
	}
	need, err := ukiRequiredSpace(size, allocation)
	if err != nil {
		return fmt.Sprintf("can't work out the space staging a test kernel needs in %s: %v", stage, err)
	}
	if free >= need {
		return ""
	}
	return fmt.Sprintf("not enough free space on the ESP to stage a test kernel in %s: staging needs %.1f MiB "+
		"(a UKI of about %.1f MiB, %s, plus the %d MiB reserve and %d MiB for metadata), and %.1f MiB is free",
		stage, mib(need), mib(size), what, limineMinFree>>20, ukiMetadataAllowance>>20, mib(free))
}

func mib(n uint64) float64 { return float64(n) / (1 << 20) }
