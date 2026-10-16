# maclab

A test lab for Omarchy Macs. Hand it a kernel, and it boots that kernel exactly
once on a real Apple Silicon Mac. It then runs tests (including Wayland GUI
tests), collects logs, and puts the Mac back on its known-good kernel. When a
kernel crashes or hangs the machine, the lab gets the Mac back itself. When it
can't, it tells a person exactly what to press.

```
lab run m1air --kernel kernel-7.2.0-rc1-lab1.tar.zst --gui-test gui-smoke
```

AI agents get the same operations over MCP (`lab mcp`).

## Pieces

| Binary | Runs on | Job |
|---|---|---|
| `labd` | any Linux box, or a Mac | Controller: devices, leases, job queue, recovery ladder, notifications, artifact and log store |
| `lab-agent` | each test Mac (Omarchy/Asahi, aarch64) | Heartbeat. Stages kernels beside the known-good one, arms the one-shot boot, runs tests, uploads logs |
| `oobd` | the controller host wired to a test Mac's DFU port | Hard reset and serial console. Today: a macOS Mac running `macvdmtool`. Later: a Linux box with a Central Scrutinizer |
| `lab` | your machine | CLI, and `lab mcp` for agents |

## How a job runs

1. **Stage.** The agent downloads the artifact, installs its modules under
   `/usr/lib/modules/<release>` (refusing any release it didn't install
   itself), and writes the boot files for the Mac's bootloader. The
   known-good kernel is never touched.
   - **GRUB:** an initramfs and an entry in `/boot/grub/maclab.cfg`.
   - **Limine** (Omarchy on Apple Silicon: U-Boot, then Limine, then a UKI on
     the ESP): a unified kernel image in `<esp>/maclab/<job>/uki.efi`, listed in
     a marked block at the end of `limine.conf`. Limine reads only FAT, so the
     ESP needs about 120 MB free.
2. **Boot once.** The agent arms a one-shot and reboots. The bootloader
   **clears it before booting the entry**, so any reset afterwards, for any
   reason, lands on the known-good kernel.
   - **GRUB:** `maclab_next=<entry>` in `maclab.env` on the ESP. GRUB can't
     write `grubenv` on btrfs, so a plain `grub-reboot` would never clear;
     that's why the flag lives on the FAT ESP.
   - **Limine:** the Boot Loader Interface variable `LoaderEntryOneShot`, which
     Limine deletes as it reads it. Apple Silicon's U-Boot keeps EFI variables
     in RAM at runtime, so the agent writes U-Boot's store (`VarToFile`) to the
     file U-Boot loads them from (`ubootefi.var` on the ESP).
3. **Watch.** labd waits for a check-in from the new boot. The boot is tagged
   `maclab.job=<id>` on the kernel command line, so labd can tell "booted the
   test kernel" from "fell back". On Macs with an OOB controller, labd also
   reads the serial console and classifies panics, oopses, RCU stalls and
   lockups as they happen.
4. **Test.** `boot-health` always runs. It is followed by any builtin tests
   (`gui-smoke`, `gui-terminal`) or your own scripts. GUI tests run inside the
   GUI user's Hyprland session. Anything written to `$MACLAB_OUT` comes back
   with the job.
5. **Collect.** The journal, kernel log and serial console are saved.
   Warnings and errors that aren't in the Mac's baseline are listed as
   `new_error_lines`.
6. **Restore.** The agent reboots to the known-good kernel, checks that the
   one-shot really cleared, and removes the staged kernel.

A test boot's command line starts from the known-good kernel's and adds `panic=10`
and `maclab.job=<id>`. It keeps `quiet`, `splash` and `loglevel=`, so the Mac boots
the way its user's boots do; dmesg and the journal record every level anyway. On a Mac
with a serial console, or with `lab run --verbose-boot`, it drops them instead and adds
`loglevel=7` (and the serial console). `lab run --cmdline-base default` starts from the distro's stock
command line (`KERNEL_CMDLINE[default]` in `/etc/default/limine`) instead, to show a
kernel needs no bring-up parameters. `--cmdline-base '<cmdline>'` takes a literal
one. `--cmdline-strip 'asahi.* dcpext_*'` drops matching parameters, and `--cmdline`
appends. The job records the staged and the booted command line. Test boots also
keep `systemd-analyze` time, blame and critical-chain.

Outcomes: `pass`, `tests_failed`, `booted_unhealthy`, `panicked`, `hung`,
`crashed_or_hung`, `boot_failed`, `stage_failed`, `infra_error`, `canceled`.
`crashed_or_hung` means the Mac rebooted during a test with no kernel error
captured (`panicked` needs one); its summary gives the seconds from the last
check-in to the next boot's first, and back within about 90s reads as a crash
(`panic=10` reboots in seconds), later as a watchdog reset after a hang, which is
an inference, not a diagnosis.

## When things go wrong

labd notices a problem from any of these signals:

- The heartbeat stops.
- The boot ID doesn't change after a reboot.
- The Mac comes back on the known-good kernel.
- A panic appears on serial, and the Mac doesn't reboot within 60s.
- The serial console goes silent mid-boot for 2 minutes.

It then climbs a ladder:

1. Soft reboot through the agent, if the agent still answers.
2. Hard reset through the OOB controller, up to twice.
3. **Ask a human.** The Mac goes to `needs_hands`, and one urgent
   notification goes out (ntfy and/or a command such as `notify-send`):

   > **m1air needs a power cycle**
   > 1. Find m1air (MacBook Air M1, left desk). Open the lid if it's closed.
   > 2. Hold the power button (the Touch ID key, top right of the keyboard) for 10 seconds, until the screen stays black.
   > 3. Wait 5 seconds, then press it once to turn it back on.
   > 4. That's it. The lab notices when it checks in again and picks up from there.

When the Mac checks in again, the alert clears, leftover staged kernels are
removed, and queued jobs continue. `lab status` shows the same instruction
while it's outstanding.

Each Mac gets a recovery tier: 0 = panic reboot + one-shot fallback,
1 = + hardware watchdog (`apple_wdt`, armed through systemd),
2 = + out-of-band reset and serial.

What a crashed boot leaves behind is incomplete. These Macs have no pstore
backend: there is no ramoops region in the device tree, and the kernel's EFI
pstore backend is off by default (`CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE`); it
wouldn't help anyway, since U-Boot keeps EFI variables in RAM at runtime. So the
panic message itself reaches only a serial console. Writes made just before a
panic are lost too. On an M1 MacBook Air (two runs, each ending in a sysrq
panic), files whose `fsync` had returned 1 s or 0 s before the panic were gone
after the reset, although `panic=10` held the Mac up for 10 s after it. Files
fsync'd 2 s or more before survived on btrfs, and 5 s or more before on ext4
(where 2 s and 1 s weren't tried). A file written without `fsync` 35 s before
the panic came back empty. The cause wasn't investigated. So the previous boot's
journal that labd collects can end well before the crash: journald syncs to disk
every 5 minutes by default, and at once only after a critical message. labd's
job events, which name each test as labd starts it, show where a boot crashed.

## Setup

```sh
make                                 # binaries in bin/
labd                                 # prints the admin token on first start
lab login http://<labd-host>:7770 <admin-token>
lab enroll m1air --label "MacBook Air M1, left desk"
```

On the Mac:

```sh
sudo ./lab-agent setup --server http://<labd-host>:7770 --token enr_... --gui-user <you> --autologin
```

`setup` makes these changes. Each one is idempotent and backed up:

- GRUB: appends the one-shot hook to `/boot/grub/custom.cfg` (backup: `custom.cfg.pre-maclab`) and creates `maclab.env` on the ESP.
- Limine: creates `<esp>/maclab/`, adds the (empty) maclab block to `limine.conf`, and keeps a copy of U-Boot's `ubootefi.var` as `ubootefi.var.pre-maclab`.
- Records the running kernel as known-good.
- Sets `kernel.panic = 10`.
- Arms the hardware watchdog (`RuntimeWatchdogSec=30s`).
- Installs and starts `lab-agent.service`.

Then run the baseline:

```sh
lab baseline m1air    # two reboots: proves the one-shot selects AND clears
lab crashtest m1air   # optional: deliberate panic, checks it recovers by itself
```

No other job runs on a Mac until its baseline passes.

### Out-of-band control from a macOS host

On the controller Mac, build `macvdmtool` (Xcode command line tools).
Connect its DFU port to the test Mac's DFU port with a USB-C cable that isn't
USB 2.0-only.

**Step zero:** check that `sudo macvdmtool nop` reports a connection and that
`sudo macvdmtool reboot serial` resets the target. Only then install `oobd` using
`deploy/com.maclab.oobd.plist`, and point labd at it:

```sh
lab device m1air --oob-url http://<controller-host>:7780 --oob-token <token>
lab oob m1air
```

`macvdmtool` only drives one port, so it's one controller Mac per test Mac.

## Live data: stream, screen, logs, shell

Everything a UI needs is on the API. The web UI uses it now, and a TUI can use it later.

- `GET /api/stream`: server-sent events for `device`, `job`, `serial`, `kevent` and `screen` (`?device=` limits it to one Mac).
- `POST /api/devices/{n}/screenshot`, `GET .../screen`, `.../screens`: captures come from the display
  controller via `ffmpeg kmsgrab`. That works from the moment the display driver loads (boot splash,
  text console, emergency shell, login screen, desktop), with `grim` as a fallback. Jobs capture
  `screen/after-boot.jpg` and `screen/after-tests.jpg`.
- `GET /api/devices/{n}/logs?source=journal|kernel&lines=N`: live from the Mac.
- `lab shell <device>`: an interactive shell over the out-of-band USB-C serial link (`GET/POST
  /api/devices/{n}/console`). It works with the Mac's network down. `lab-agent setup` enables an
  115200 getty on `ttySAC0`.

Before the display driver loads, the screen can't be captured, but serial carries the text of every
stage: m1n1, U-Boot, the kernel from `[0.000000]` (lab boots add `console=ttySAC0,115200`), and
login. A Mac leaves serial mode on every reboot, so labd asks oobd to re-arm around each one.

## Build from a GitHub URL

```sh
lab run m1air --kernel https://github.com/iconidentify/aurora-linux/tree/custom/sep --gui-test gui-smoke
lab build https://github.com/AsahiLinux/linux/pull/123 --device m1air
lab build https://github.com/AsahiLinux/linux/pull/123 --config ./my.config   # one build for every Mac
```

Agents do the same with `lab_run(source=...)`, `lab_build` and `lab_build_status`, and use `lab_exec`
instead of ssh. labd resolves repo, branch (`/tree/...`), commit and PR URLs (or `git-url#ref`) to
a commit with `git ls-remote`. It keys the build on that commit, the target Mac's running
`/proc/config.gz` and the kbuild recipe, and reuses an identical earlier build.

`lab-builder` runs on the controller Mac as a root LaunchDaemon. Root is needed because macOS Local
Network privacy blocks user processes. It runs `builder/kbuild` in an Apple `container` micro-VM
(`builder/Containerfile`: Debian, gcc, Rust 1.93.1, bindgen), started in the user's session. All
state is one size-capped volume (`container volume create -s 40G maclab-cache`): one shared
depth-1 git store, one reused worktree, at most two build dirs, and an 8 GB ccache. The host scratch
dir is emptied after every build. labd's artifact store is garbage-collected to a budget
(`--artifact-budget-gb`, default 20).

Measured on a base M5 (10 cores, VM with 16 GB) with aurora's config: first build 9 minutes;
rebuild of a warm tree about 40 seconds. Progress (stage, object count, ETA) and the log stream
live on `/api/stream` (`build`, `buildlog`) and `/api/builds/{id}/log?follow=1`.

## omarchy-m-test: hardware checks in every job

On a Mac with a desktop user, every job also runs
[omarchy-m-test](https://github.com/maralcbr/omarchy-m-testing) in the desktop
session: about 70 checks of the boot chain, drivers, GPU, video decode, display,
audio, Wi-Fi, power and CPU, and short benchmarks. The agent installs or upgrades
the tool with its own installer, which checks the release signature. It answers
the disclaimer and then gives no more input, so every question meant for a person
(look at the screen, close the lid, reload Wi-Fi, upload) is skipped, never
answered yes. The run takes 1 to 3 minutes.

- **Known-good runs** (`lab baseline`, `lab run <mac>` with no kernel) become the
  Mac's reference report.
- **Lab kernels** are compared with that reference. A check that passes on the
  known-good kernel and fails on the test kernel is a regression and fails the job.
  `boot.files` and `boot.kernel-package` are listed apart: they fail for any
  kernel that isn't an installed package. A kernel that lacks a feature on
  purpose names what it's expected to fail: `--omt-allow system.failed-units`,
  or `--omt-allow hardware.drivers:<compatible>` for one device-tree node, which
  still fails the job if any other node stops binding. When `hardware.drivers`
  fails on both kernels, the unclaimed nodes are compared one by one: a node a
  driver claims on the known-good kernel and not on the test kernel regresses as
  `hardware.drivers:<compatible>`.
- **Publishing:** `lab run <mac> --publish`, `lab publish <job>`, or the job page's
  Publish button uploads the signed report to omarchy-m-testing.org. Only
  known-good runs qualify, because the site names a report's build from the
  installed packages, and those don't describe a lab kernel. The site's deletion
  link stays in the job's `omt-published.json`.

```sh
labd --omt-publish --omt-every 24h   # refresh each idle Mac's known-good report daily, and publish it
labd --omt=false                     # don't add it to jobs
```

## Release packages from a PKGBUILD

```sh
lab package ~/recipes/linux-aurora                        # the recipe exactly as written
lab package ~/recipes/linux-aurora --pkgrel 11.14 \
    --commit https://github.com/iconidentify/aurora-linux/commit/<sha> -o ./rel
lab run m1air --kernel <build-id>                         # boot the kernel package once
lab build-get <build-id> -o ./rel                         # packages + the PKGBUILD as built, sha256-checked,
                                                          # and the uploaded recipe (patches, data files) in ./rel/recipe/
```

A kernel build (above) makes a lab test artifact. A package build makes the release: it runs a
PKGBUILD recipe with `makepkg`, the way the release machine (m1) does, and returns every package it
makes (`linux-aurora`, `linux-aurora-headers`, ...) plus the PKGBUILD as built. The CLI uploads only
the recipe's own files: the PKGBUILD, its local sources, and install/changelog files. makepkg
downloads the rest. `--commit` repoints `_commit` (the PKGBUILD must download from that repository),
`--pkgrel` sets pkgrel, and either one refreshes the checksums with `updpkgsums`. Agents use
`lab_package`, then `lab_build_status`, then `lab_run(build_id=...)`.

The builder is `builder/pkg`. It is Arch Linux ARM, the release machine's `/etc/makepkg.conf`
verbatim, and `maclab.conf` with the one difference: packages are `.pkg.tar.zst`. ccache stays
off, as on the release machine: its base-dir path rewriting changes `__FILE__` strings inside
modules. When the image is built, gcc, glibc, binutils, rustup, bindgen and pahole come out at the
same versions as on an up-to-date Arch Linux ARM machine. Rebuild the image to follow the distribution:

```sh
# on the controller Mac, in a directory holding builder/pkg/* and the rootfs tarball
curl -LO http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz
container build -t maclab-pkgbuild:1 .
container volume create -s 120G maclab-pkgcache   # once; a kernel tree needs ~35 GB while building
```

Checked against a linux-aurora build of the same recipe on an Arch Linux ARM machine: the file
lists and package metadata are identical. Contents are byte-identical except where the build
directory's path leaks in: ELF build-ids, the source paths Rust drivers embed for panics
(`/cache/work/b/...` here), and the build timestamp in `vmlinuz`. A cold build takes 8 to 12
minutes on a base M5.

The 30+ GB work tree is deleted after every build. The volume keeps downloaded sources (the newest
six) and the Rust toolchains. `lab-builder` takes package builds only when it has
`--pkg-image` (the default, `maclab-pkgbuild:1`). An older builder only ever gets kernel builds.

## Kernel artifacts

A tarball in the Arch package layout: exactly one
`usr/lib/modules/<release>/` holding the modules and `vmlinuz` (or `Image`).
A `linux-*.pkg.tar.zst` works as-is. From an `O=` build tree:

```sh
lab pack --build ~/linux/build    # the O= dir -> kernel-<release>.tar.zst
```

The release string must be unique (set `LOCALVERSION`). The agent refuses to
install over a kernel it didn't install, including the running one.

The device tree comes from m1n1 on the ESP, not from the test kernel, and that includes a
release package booted with `lab run`. A kernel that needs new DT bindings needs a matching
m1n1 stage 2. A lab boot doesn't exercise device-tree changes.

## For AI agents

```sh
claude mcp add maclab -- lab mcp
```

Tools: `lab_devices`, `lab_device`, `lab_run`, `lab_wait`, `lab_job`, `lab_jobs`,
`lab_log`, `lab_screenshot`, `lab_baseline`, `lab_crashtest`, `lab_lease`,
`lab_release`, `lab_reset`, `lab_serial`, `lab_exec`, `lab_cancel`, `lab_build`,
`lab_build_status`, `lab_package` and `lab_publish`. A device in `needs_hands` is waiting for a
person. Tell the user; don't retry.

A lab is worth describing to its agents once: which Macs you have, which one has
serial, what they must not touch. Write that in a short Markdown file and hand it
to them with a prompt.

## Verified on hardware

On an M3 Max host (J516cAP, macOS 27.0.1) driving an M1 MacBook Air (J313) through its DFU port:

- `macvdmtool reboot` resets the target from an M3 host: back 37 s later. (It was already verified
  from an **M5 Pro** host, J704AP, on macOS 26.5.) With the watchdog stopped at runtime (systemd's
  `RuntimeWatchdogSec` set to 0) and `kernel.panic=0`, a crashed Air stayed down for 2 minutes until
  `macvdmtool reboot` brought it back in 36 s.
- Apple Silicon's U-Boot arms `apple_wdt` and leaves it running into Linux: booting with
  `watchdog.handle_boot_enabled=0` logs `watchdog0 running and kernel based pre-userspace handler
  disabled` within the first second. With `watchdog.open_timeout=N` (lab boots don't set it today),
  a boot that hangs or gets stuck before something opens `/dev/watchdog` is reset: a test boot stuck
  in the initramfs waiting for its root device came back on its known-good kernel by itself.

From the sources, not measured: m1n1 disables the watchdog, so m1n1 itself runs unwatched, and
U-Boot feeds it while U-Boot or Limine waits, so a boot sitting at a prompt or a menu stays up. Once
Linux runs, the kernel feeds it until something opens `/dev/watchdog` (forever without
`open_timeout`), and a healthy boot must open it in time too. `lab-agent setup`'s
`RuntimeWatchdogSec=30s` has systemd open it once the real root is up (the initramfs doesn't get
that setting), and systemd then keeps it fed for as long as it runs, even through a boot stuck in
emergency mode.

## Not yet verified on hardware

- The serial console from an M3 host. A USB 2.0 cable (no SBU wires) carried no serial data either
  way, so it is still open whether serial mode works from an M3 host with a SuperSpeed cable. Reset
  needs only CC.

## Development

`make test` runs the unit tests and eight end-to-end scenarios against a
simulated Mac (`internal/agent/sim.go`):

- A good kernel
- Panic at boot
- Hang, recovered by hard reset
- Silent hang, caught from serial
- No OOB, human power cycle, then queued jobs resume
- Crash during a test
- Deliberate crash test
- A failing test

`lab-agent sim --server .. --token ..` enrolls a simulated Mac against a real labd.

## Phones and the LAN

`labd --trust 192.168.1.0/24,127.0.0.1` (or `MACLAB_TRUST`) lets browsers on
those networks use the UI with no admin token, so a phone can just open
`http://<labd-host>:7770`. It judges the TCP peer address only, never a
forwarded header. Everyone on a trusted network can reboot Macs, open
their serial shell and run commands on them as root, so trust only a
network you'd hand a root shell to. A token still works from anywhere. On a
phone the UI switches to a bottom tab bar and can be added to the home
screen.

## License

MIT; see [LICENSE](LICENSE). The web UI bundles third-party files under their own
licenses: xterm.js (MIT), subsets of JetBrains Mono Nerd Font and IBM Plex Sans
(SIL OFL 1.1), and the Omarchy logo, icon and font (MIT). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). maclab isn't an official Omarchy
or Asahi Linux project, and it isn't affiliated with Apple.
