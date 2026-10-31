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
