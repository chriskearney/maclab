package mesa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
)

const stageTimeout = 3 * time.Minute
const packageDecodeTimeout = 60 * time.Second
const maxTarPadding = 1 << 20

type commandFactory func(context.Context, string, ...string) *exec.Cmd

var frameCount = regexp.MustCompile(`(?m)^# Zstandard Frames: ([0-9]+)$`)
var skipCount = regexp.MustCompile(`(?m)^# Skippable Frames: ([0-9]+)$`)

// zstd accepts concatenated frames by default. A package is exactly one zstd
// frame, without skippable containers or compressed trailing garbage. Inspect
// with the installed tool's C-locale frame listing; unknown output fails shut.
func singleZstdFrame(ctx context.Context, archive string, command commandFactory) error {
	cmd := command(ctx, "/usr/bin/zstd", "--list", "--verbose", archive)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var out, errout strings.Builder
	stdout := &limitedWriter{W: &out, N: 8192}
	stderr := &limitedWriter{W: &errout, N: 8192}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zstd frame inspection: %w: %s", errors.Join(err, ctx.Err()), errout.String())
	}
	matches := frameCount.FindAllStringSubmatch(out.String(), -1)
	skips := skipCount.FindAllStringSubmatch(out.String(), -1)
	if stdout.Truncated || len(matches) != 1 || matches[0][1] != "1" || len(skips) > 1 || (len(skips) == 1 && skips[0][1] != "0") {
		return errors.New("Mesa package must contain one zstd frame and no skippable frames")
	}
	return nil
}

// archive/tar stops at its end marker without consuming its input. Drain the
// remaining output before Wait so zstd cannot block on a full pipe; only a
// finite, block-aligned zero tar pad is allowed, never a second tar or payload.
func drainTarPadding(r io.Reader) error {
	var buf [32 << 10]byte
	n := 0
	for {
		got, err := r.Read(buf[:])
		n += got
		if n > maxTarPadding {
			return errors.New("tar trailing padding exceeds1MiB")
		}
		for _, v := range buf[:got] {
			if v != 0 {
				return errors.New("nonzero data after tar end marker")
			}
		}
		if err == io.EOF {
			if n%512 != 0 {
				return errors.New("tar trailing padding is not block aligned")
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}
func decodePackage(ctx context.Context, archive string, u *unpacker, p api.MesaPackage) error {
	return decodePackageWith(ctx, archive, u, p, exec.CommandContext)
}
func decodePackageWith(ctx context.Context, archive string, u *unpacker, p api.MesaPackage, command commandFactory) error {
	ctx, cancel := context.WithTimeout(ctx, packageDecodeTimeout)
	defer cancel()
	if err := singleZstdFrame(ctx, archive, command); err != nil {
		return err
	}
	cmd := command(ctx, "/usr/bin/zstd", "-d", "--stdout", "--memory=256MB", archive)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer out.Close()
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{W: &stderr, N: 8192}
	if err = cmd.Start(); err != nil {
		return err
	}
	err = u.unpack(out, p)
	if err == nil {
		err = drainTarPadding(out)
	}
	if err != nil {
		cmd.Process.Kill()
		out.Close()
	}
	wait := cmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("Mesa decompression deadline/cancel: %w", errors.Join(ctx.Err(), err, wait))
	}
	if err != nil {
		return err
	}
	if wait != nil {
		return fmt.Errorf("zstd: %w: %s", wait, stderr.String())
	}
	return nil
}
