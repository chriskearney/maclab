package agent

import (
	"os"
	"strings"
	"testing"

	"github.com/iconidentify/maclab/internal/api"
)

// m1air: /boot lives on the btrfs root in subvolume @, the ESP is FAT at /boot/efi.
func m1airLayout() *grubLayout {
	return &grubLayout{
		Dir:       "/boot/grub",
		ESP:       mount{Source: "/dev/nvme0n1p4", Target: "/boot/efi", FSType: "vfat", UUID: "697C-8537"},
		EnvFile:   "/boot/efi/maclab.env",
		Boot:      mount{Source: "/dev/nvme0n1p5[/@]", Target: "/", FSType: "btrfs", UUID: "725346d2-f127-47bc-b464-9dd46155e8d6"},
		prefix:    "/@/boot",
		LoadVideo: true,
	}
}

func TestGrubPaths(t *testing.T) {
	g := m1airLayout()
	if got := g.grubPath("/boot/maclab/j1/vmlinuz"); got != "/@/boot/maclab/j1/vmlinuz" {
		t.Fatal(got)
	}
	if got := g.localPath("/@/boot/vmlinuz-linux-aurora"); got != "/boot/vmlinuz-linux-aurora" {
		t.Fatal(got)
	}
	sep := &grubLayout{prefix: ""} // separate /boot partition
	if got := sep.grubPath("/boot/maclab/j1/vmlinuz"); got != "/maclab/j1/vmlinuz" {
		t.Fatal(got)
	}
}

func TestTestCmdline(t *testing.T) {
	base := "BOOT_IMAGE=/@/boot/vmlinuz-linux-aurora root=UUID=725346d2 rw rootflags=subvol=@ loglevel=3 quiet splash"
	got := testCmdline(base, api.StageArgs{Cmdline: "nvme_apple.flush_interval=0", Serial: true}, "j1")
	want := "root=UUID=725346d2 rw rootflags=subvol=@ loglevel=7 panic=10 systemd.watchdog_sec=0 watchdog.open_timeout=120 maclab.lab_boot=1 console=ttySAC0,115200 console=tty0 nvme_apple.flush_interval=0 maclab.job=j1"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	if jobTag(got) != "j1" || jobTag(base) != "" {
		t.Fatal("jobTag")
	}
	// Without a serial console the boot keeps the user's quiet, splash and loglevel.
	got = testCmdline(base, api.StageArgs{}, "j2")
	want = "root=UUID=725346d2 rw rootflags=subvol=@ loglevel=3 quiet splash panic=10 systemd.watchdog_sec=0 watchdog.open_timeout=120 maclab.lab_boot=1 maclab.job=j2"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	// Unless the job asks for a verbose boot.
	got = testCmdline(base, api.StageArgs{Verbose: true}, "j3")
	want = "root=UUID=725346d2 rw rootflags=subvol=@ loglevel=7 panic=10 systemd.watchdog_sec=0 watchdog.open_timeout=120 maclab.lab_boot=1 maclab.job=j3"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestEntryAndHook(t *testing.T) {
	g := m1airLayout()
	e := g.entryText("j1", "maclab j1: 7.2-rc1", "/@/boot/maclab/j1/vmlinuz", "/@/boot/maclab/j1/initramfs.img", "root=UUID=x rw maclab.job=j1", g.Boot.UUID, g.Boot.FSType)
	for _, want := range []string{"--id maclab-j1 {", "insmod btrfs", "search --no-floppy --fs-uuid --set=root 725346d2-f127-47bc-b464-9dd46155e8d6",
		"linux /@/boot/maclab/j1/vmlinuz root=UUID=x rw maclab.job=j1", "initrd /@/boot/maclab/j1/initramfs.img", "load_video"} {
		if !strings.Contains(e, want) {
			t.Errorf("entry lacks %q:\n%s", want, e)
		}
	}
	h := g.hookText()
	for _, want := range []string{hookMarker, "--set=maclab_esp 697C-8537", "load_env -f ($maclab_esp)/maclab.env maclab_next",
		`set default="$maclab_next"`, "save_env -f ($maclab_esp)/maclab.env maclab_next", "source ${config_directory}/maclab.cfg"} {
		if !strings.Contains(h, want) {
			t.Errorf("hook lacks %q:\n%s", want, h)
		}
	}
	// The flag must be cleared before the entry boots, or a bad kernel boots forever.
	if strings.Index(h, "save_env") < strings.Index(h, "set maclab_next=") {
		t.Error("hook saves before clearing")
	}
}

func TestEntryInitrd(t *testing.T) {
	cfg := t.TempDir() + "/grub.cfg"
	os.WriteFile(cfg, []byte(`menuentry 'other' {
	linux /@/boot-test/other/vmlinuz root=x
	initrd /@/boot-test/other/initramfs.img
}
menuentry 'M3 main' --id m3-main {
    search --no-floppy --fs-uuid --set=root 4f4d5801
    linux /@/boot-test/m3-main-08c90aa8b/vmlinuz root=UUID=4f4d rw
    initrd /@/boot-test/m3-main-08c90aa8b/initramfs.img
}
`), 0o644)
	if got := entryInitrd(cfg, "/@/boot-test/m3-main-08c90aa8b/vmlinuz"); got != "/@/boot-test/m3-main-08c90aa8b/initramfs.img" {
		t.Fatalf("got %q", got)
	}
	if got := entryInitrd(cfg, "/@/boot/nope"); got != "" {
		t.Fatalf("unknown image gave %q", got)
	}
	// The kernel lives on btrfs while /boot is ext4: entries must search btrfs.
	g := &grubLayout{Boot: mount{UUID: "4f4d5801-424f", FSType: "ext4"}}
	e := g.entryText("j2", "t", "/@/boot-test/k/vmlinuz", "/@/boot-test/k/initramfs.img", "root=x", "4f4d5801-524f", "btrfs")
	for _, want := range []string{"insmod btrfs", "insmod zstd", "--set=root 4f4d5801-524f"} {
		if !strings.Contains(e, want) {
			t.Errorf("entry lacks %q:\n%s", want, e)
		}
	}
}
