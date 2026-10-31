package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilderToken(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("bldr_abc\n"), 0o600)
	open := filepath.Join(dir, "open")
	os.WriteFile(open, []byte("bldr_abc"), 0o644)
	os.Chmod(open, 0o644)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for _, c := range []struct {
		name, flag, file, env, want string
		err                         bool
	}{
		{name: "file", file: good, flag: "ignored", env: "ignored", want: "bldr_abc"},
		{name: "readable by others", file: open, err: true},
		{name: "empty file", file: empty, err: true},
		{name: "missing file", file: filepath.Join(dir, "none"), err: true},
		{name: "flag", flag: "bldr_flag", env: "ignored", want: "bldr_flag"},
		{name: "env", env: " bldr_env\n", want: "bldr_env"},
	} {
		got, err := builderToken(c.flag, c.file, c.env)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "bldr_abc") {
			t.Errorf("%s: the error shows the token: %v", c.name, err)
		}
	}
}

// Nothing lab-builder starts gets a MACLAB_ variable, the token among them.
func TestChildEnvDropsMaclabVariables(t *testing.T) {
	env := childEnv([]string{"HOME=/var/root", "MACLAB_BUILDER_TOKEN=bldr_x", "MACLAB_URL=https://x", "PATH=/usr/bin"})
	if strings.Join(env, " ") != "HOME=/var/root PATH=/usr/bin" {
		t.Fatalf("env %q", env)
	}
	t.Setenv("MACLAB_BUILDER_TOKEN", "bldr_secret")
	cmd := (&builder{}).container(context.Background(), "list")
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "MACLAB_") || strings.Contains(e, "bldr_secret") {
			t.Fatalf("container command env has %q", e)
		}
	}
}

func TestContainerPrefix(t *testing.T) {
	for p, ok := range map[string]bool{"maclab": true, "maclabhttps": true, "lab.2_x": true, "": false, "-x": false,
		"a b": false, "x/y": false, strings.Repeat("a", 33): false} {
		if rePrefix.MatchString(p) != ok {
			t.Errorf("%q: %v", p, !ok)
		}
	}
}

// A build VM shares the scratch dir and may leave links to files of this
// host there: none is ever read or uploaded, wherever it points.
func TestOutputsReadNoLinks(t *testing.T) {
	host := t.TempDir()
	secret := filepath.Join(host, "builder.token")
	os.WriteFile(secret, []byte("bldr_host_secret"), 0o600)
	os.Mkdir(filepath.Join(host, "dir"), 0o700)
	os.WriteFile(filepath.Join(host, "dir", "x.pkg.tar.zst"), []byte("host file"), 0o600)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "kernel.tar.zst"), []byte("kernel"), 0o644)
	os.WriteFile(filepath.Join(dir, "inside"), []byte("in"), 0o644)
	os.Mkdir(filepath.Join(dir, "out"), 0o755)
	os.WriteFile(filepath.Join(dir, "out", "linux-x-1-1-aarch64.pkg.tar.zst"), []byte("pkg"), 0o644)
	os.Symlink(secret, filepath.Join(dir, "release"))                             // to a host file
	os.Symlink(secret, filepath.Join(dir, "out", "evil-1-1-aarch64.pkg.tar.zst")) // listed output, to a host file
	os.Symlink("inside", filepath.Join(dir, "kernel"))                            // a link that stays inside
	os.Symlink(filepath.Join(host, "dir"), filepath.Join(dir, "outlink"))         // an outputs dir that is a link
	os.WriteFile(filepath.Join(dir, "big"), make([]byte, 5000), 0o644)

	o, err := openOutputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if f, st, err := o.regular("kernel.tar.zst"); err != nil || st.Size() != 6 {
		t.Fatalf("regular file: %v", err)
	} else {
		f.Close()
	}
	if f, _, err := o.regular("out/linux-x-1-1-aarch64.pkg.tar.zst"); err != nil {
		t.Fatalf("regular package: %v", err)
	} else {
		f.Close()
	}
	for _, name := range []string{"release", "out/evil-1-1-aarch64.pkg.tar.zst", "kernel", "outlink/x.pkg.tar.zst"} {
		if f, _, err := o.regular(name); err == nil {
			f.Close()
			t.Errorf("%s: read through a link", name)
		}
		if s, err := o.small(name); err == nil || strings.Contains(s, "secret") {
			t.Errorf("%s: small read %q %v", name, s, err)
		}
	}
	if _, err := o.list("outlink"); err == nil {
		t.Error("listed a linked outputs dir")
	}
	ents, err := o.list("out")
	if err != nil || len(ents) != 2 {
		t.Fatalf("list out: %v %v", ents, err)
	}
	if _, err := o.small("big"); err == nil {
		t.Error("an oversized short output was read")
	}
	// A second name for the same file is refused too.
	os.Link(filepath.Join(dir, "kernel.tar.zst"), filepath.Join(dir, "hardlink"))
	if f, _, err := o.regular("hardlink"); err == nil {
		f.Close()
		t.Error("read a hard-linked output")
	}
}
