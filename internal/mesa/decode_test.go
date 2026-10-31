package mesa

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func compressTest(t *testing.T, raw []byte) []byte {
	t.Helper()
	cmd := exec.Command("zstd", "-q", "-c")
	cmd.Stdin = bytes.NewReader(raw)
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func expandTest(t *testing.T, data []byte) []byte {
	t.Helper()
	cmd := exec.Command("zstd", "-q", "-d", "-c")
	cmd.Stdin = bytes.NewReader(data)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestStageZstdFrameAndTarTailAdmission(t *testing.T) {
	for _, which := range []string{"valid-large-pad", "valid-max-pad", "nonzero", "unaligned-pad", "excess-pad", "second-tar", "second-zstd-frame", "skippable-frame", "malformed-zstd"} {
		t.Run(which, func(t *testing.T) {
			root, spec, fetch, tools, store := fixture(t)
			original := store[spec.Packages[0].SHA256]
			raw := expandTest(t, original)
			data := original
			good := false
			switch which {
			case "valid-large-pad":
				data = compressTest(t, append(raw, make([]byte, 128<<10)...))
				good = true
			case "valid-max-pad":
				data = compressTest(t, append(raw, make([]byte, maxTarPadding)...))
				good = true
			case "nonzero":
				data = compressTest(t, append(raw, []byte("hidden payload")...))
			case "unaligned-pad":
				data = compressTest(t, append(raw, 0))
			case "excess-pad":
				data = compressTest(t, append(raw, make([]byte, maxTarPadding+512)...))
			case "second-tar":
				data = compressTest(t, append(raw, raw...))
			case "second-zstd-frame":
				data = append(append([]byte(nil), original...), compressTest(t, nil)...)
			case "skippable-frame":
				var header [8]byte
				binary.LittleEndian.PutUint32(header[:4], 0x184d2a50)
				data = append(append([]byte(nil), original...), header[:]...)
			case "malformed-zstd":
				data = append([]byte(nil), original[:len(original)-1]...)
			}
			spec.Packages[0].SHA256 = Sum(data)
			store[Sum(data)] = data
			// Generous for a loaded CI runner under -race. A real hang
			// runs to this deadline, past the limit checked below.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			started := time.Now()
			_, err := stageWith(ctx, root, "j1026-010203-abcd", spec, fetch, tools)
			if good && err != nil {
				t.Fatal("valid padding deadlocked/refused", err)
			}
			if !good && err == nil {
				t.Fatal("malformed/concatenated/excessive data admitted")
			}
			if time.Since(started) > 15*time.Second {
				t.Fatal("archive handling did not promptly consume/refuse tail")
			}
		})
	}
}
func TestDecodeDeadlineReapsActualStalledProcessBeforeAndAfterTarEnd(t *testing.T) {
	for _, afterEnd := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-header", true: "after-tar-end"}[afterEnd], func(t *testing.T) {
			root, spec, _, _, store := fixture(t)
			p := spec.Packages[0]
			packed := filepath.Join(root, "package.zst")
			rawfile := filepath.Join(root, "raw.tar")
			os.WriteFile(packed, store[p.SHA256], 0600)
			os.WriteFile(rawfile, expandTest(t, store[p.SHA256]), 0600)
			staged := filepath.Join(root, "root")
			os.Mkdir(staged, 0700)
			m := Manifest{Root: staged, Files: map[string]File{}}
			u := unpacker{m: &m, links: map[string]string{}}
			var child *exec.Cmd
			command := func(ctx context.Context, name string, args ...string) *exec.Cmd {
				if len(args) > 0 && args[0] == "--list" {
					return exec.CommandContext(ctx, name, args...)
				}
				script := "exec /usr/bin/sleep 30"
				if afterEnd {
					script = "/usr/bin/cat \"$1\"; exec /usr/bin/sleep 30"
				}
				child = exec.CommandContext(ctx, "/bin/sh", "-c", script, "decode-fixture", rawfile)
				return child
			}
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := decodePackageWith(ctx, packed, &u, p, command)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("missing actual deadline error: %v", err)
			}
			if child == nil || child.ProcessState == nil || syscall.Kill(child.Process.Pid, 0) != syscall.ESRCH {
				t.Fatal("stalled child not reaped")
			}
			if time.Since(started) > time.Second {
				t.Fatal("decompression/tail deadline ineffective")
			}
		})
	}
}
func TestStageOwnDeadlineExistsAndHonorsEarlierCaller(t *testing.T) {
	for _, early := range []bool{false, true} {
		root, spec, _, tools, _ := fixture(t)
		ctx := context.Background()
		cancel := func() {}
		if early {
			ctx, cancel = context.WithTimeout(ctx, time.Second)
		}
		defer cancel()
		expected := errors.New("stop after observing fetch budget")
		seen := false
		started := time.Now()
		fetch := func(c context.Context, _, _ string) error {
			d, ok := c.Deadline()
			if !ok {
				t.Fatal("agent stage has no independent deadline")
			}
			if d.Sub(started) > stageTimeout+time.Second || (early && d.Sub(started) > 2*time.Second) {
				t.Fatal("deadline not bounded by stage/caller", d)
			}
			seen = true
			return expected
		}
		_, err := stageWith(ctx, root, "j1026-010203-abcd", spec, fetch, tools)
		if !seen || !errors.Is(err, expected) {
			t.Fatal(err)
		}
	}
}
func TestDrainPaddingReadFailureAndUnknownFrameListingFailClosed(t *testing.T) {
	if err := drainTarPadding(ioFailure{}); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatal(err)
	}
	command := func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/printf", "unknown frame schema\\n")
	}
	if err := singleZstdFrame(context.Background(), "unused", command); err == nil {
		t.Fatal("unknown zstd listing accepted")
	}
}

type ioFailure struct{}

func (ioFailure) Read([]byte) (int, error) { return 0, errors.New("read failed") }
