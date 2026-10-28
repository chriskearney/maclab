package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUKIRequiredSpace(t *testing.T) {
	n, err := ukiRequiredSpace(4097, 4096)
	if err != nil || n != limineMinFree+ukiMetadataAllowance+8192 {
		t.Fatal(n, err)
	}
	for _, p := range [][2]uint64{{0, 4096}, {1, 0}, {^uint64(0), 4096}, {^uint64(0) - 4095, 4096}} {
		if _, err := ukiRequiredSpace(p[0], p[1]); err == nil {
			t.Fatal(p)
		}
	}
	// Real retained M3 numbers: old-default archival is not performed here.
	needed, err := ukiRequiredSpace(63985152, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if 132947968 >= needed || 195676672 < needed {
		t.Fatal("wrong retained M3 capacity decisions", needed)
	}
}
func TestUKIReservePrivateBuildAndBoundary(t *testing.T) {
	for _, test := range []string{"fits", "one byte too small", "post-copy space loss", "same filesystem", "build failure", "empty build", "symlink build", "cancel before copy", "lock failure"} {
		t.Run(test, func(t *testing.T) {
			root := t.TempDir()
			scratch := filepath.Join(root, "private")
			esp := filepath.Join(root, "esp")
			os.Mkdir(scratch, 0700)
			os.Mkdir(esp, 0700)
			out := filepath.Join(esp, "uki.efi")
			old := []byte("old owned staged UKI preserved until commit")
			os.WriteFile(out, old, 0600)
			image := bytes.Repeat([]byte{'k'}, 4097)
			needed, _ := ukiRequiredSpace(uint64(len(image)), 4096)
			held, built := false, false
			dstCalls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := ukiWriter{ScratchRoot: scratch}
			w.Build = func(_ context.Context, krel, kimage, cmdline, p string) error {
				built = true
				if held || !strings.HasPrefix(p, scratch+string(os.PathSeparator)) {
					t.Fatal("generator touched ESP or held boot lock")
				}
				if krel != "test-release" || kimage != "kernel-image" || cmdline != "root=test" {
					t.Fatal("generator args changed")
				}
				if mode, _ := os.Stat(filepath.Dir(p)); mode.Mode().Perm() != 0700 {
					t.Fatal("scratch not private")
				}
				if test == "build failure" {
					return errors.New("build failed")
				}
				if test == "empty build" {
					return os.WriteFile(p, nil, 0600)
				}
				if test == "symlink build" {
					return os.Symlink(out, p)
				}
				if test == "cancel before copy" {
					cancel()
				}
				return os.WriteFile(p, image, 0600)
			}
			w.Lock = func() (func(), error) {
				if test == "lock failure" {
					return nil, errors.New("lock unavailable")
				}
				if !built {
					t.Fatal("locked before private build")
				}
				held = true
				return func() { held = false }, nil
			}
			w.Space = func(p string) (ukiSpace, error) {
				if strings.HasPrefix(p, scratch) {
					return ukiSpace{Available: 1 << 30, Allocation: 4096, Device: 1}, nil
				}
				if p != esp {
					t.Fatal("unexpected space probe", p)
				}
				dstCalls++
				dev := uint64(2)
				if test == "same filesystem" {
					dev = 1
				}
				available := needed
				if dstCalls >= 2 && !held {
					t.Fatal("reserve measured outside boot locks")
				}
				if test == "one byte too small" {
					available = needed - 1
				}
				if dstCalls >= 3 {
					available = limineMinFree + ukiMetadataAllowance
					if test == "post-copy space loss" {
						available--
					}
				}
				return ukiSpace{Available: available, Allocation: 4096, Device: dev}, nil
			}
			err := writeUKIWith(ctx, "test-release", "kernel-image", "root=test", out, w)
			got, _ := os.ReadFile(out)
			if test == "fits" {
				if err != nil || !bytes.Equal(got, image) {
					t.Fatal(err, string(got))
				}
			} else if err == nil || !bytes.Equal(got, old) {
				t.Fatalf("unsafe or clobbered on %s: %v", test, err)
			}
			if held {
				t.Fatal("boot lock leaked")
			}
			dirs, _ := os.ReadDir(scratch)
			if len(dirs) != 0 {
				t.Fatal("scratch not cleaned")
			}
			files, _ := os.ReadDir(esp)
			if len(files) != 1 || files[0].Name() != "uki.efi" {
				t.Fatal("ESP temporary file leaked")
			}
		})
	}
}
