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

   A failed staging is tried again, up to 3 attempts, 30 s and then 2 min
   apart, with the failed attempt's leftovers removed first. Only an attempt
   that is over is tried again: one the agent reported failed, or one the Mac
   rebooted under. One that outlasts labd's 20-minute wait, or whose Mac goes
   quiet, may still be staging, so the job fails instead. The same error
   twice in a row looks permanent and ends it early.
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
   (`gui-smoke`, `gui-terminal`, `suspend-devices`) or your own scripts. GUI
   tests run inside the GUI user's Hyprland session. Anything written to
   `$MACLAB_OUT` comes back with the job. `suspend-devices` writes `devices` to
   `/sys/power/pm_test` and runs `systemctl suspend`: the kernel freezes tasks
   and runs the devices' prepare and suspend callbacks (not their late and
   noirq phases, nor the sleep itself), waits 5 s and resumes them by itself.
   The test passes if that cycle's kernel log shows the wait (which comes only
   once those callbacks succeeded) and no device failing to suspend or resume,
   and the default route comes back. On a kernel without `pm_test`'s `devices`
   mode (`CONFIG_PM_DEBUG`) it is skipped, which is not a pass: the job ends
   `tests_failed`. `pm_test` goes back to the mode it
   had, but to `none` only once nothing is left that could suspend the Mac; if
   a suspend that didn't finish in time never settles, it stays at `devices`
   until the next boot, so a later suspend is a test one too. Omarchy locks the
   desktop before every suspend, and only the user's password unlocks it, so
   the test stops the GUI user's `omarchy-sleep-lock.service` for the cycle and
   starts it again after. All of it, putting things back too, ends within the
   test's timeout (5 minutes by default). The Mac goes quiet for 10-15 s
   (NetworkManager takes Wi-Fi down for the suspend), so just before it
   suspends, the test tells labd how long the Mac may be off the network (3.5
   minutes: the waits for the cycle, for it to settle and for the route, or
   what is left of the timeout), and labd waits that out on that boot before
   counting the Mac as lost. A real suspend can't be
   tested unattended: Apple Silicon's RTC has no wake alarm, so only a key
   press wakes the Mac (a reset ends the boot). labd warns when a test named
   `suspend-*` needs someone there.
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

A job that couldn't stage its kernel ends `stage_failed`, with the reason and
`lab retry <job>` in its summary. `lab retry` (or Retry on a finished job's page)
runs any finished job again as a new job: the same Mac, kernel, tests and cmdline.
A source job boots the kernel its first run built. Once that has been collected,
the retry builds again from the exact commit the first build recorded, not from
wherever its branch or pull request points now; a job that recorded no commit
can't be retried, and the refusal says to run it afresh with `lab run`.
`lab retry` holds the new job as you, and the web UI's Retry as `web`.

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

On a tier 1 Mac a test boot recovers from hangs without a controller Mac, once Linux runs.
U-Boot leaves `apple_wdt` running into Linux (it feeds it itself while it or Limine waits,
so a Mac sitting at a U-Boot prompt or the Limine menu is not reset). A test boot's
command line adds `systemd.watchdog_sec=0 watchdog.open_timeout=N`: systemd, in the
initramfs too, leaves the watchdog alone, and the kernel pings it only for N seconds. N is
the job's boot timeout less 2 minutes for the reset and the fallback boot, and at least
60: 120 with labd's default 4-minute `--boot-timeout`. Any boot that hasn't opened the
watchdog by then is reset within 30 s, a healthy one too, so lab-agent opens it on every
test boot (about 5 s after the kernel starts, on an M1 Air). If it can't yet, it tries
again every second, while it checks in, until N seconds after the kernel started, and then
logs that the Mac will be reset: a boot that hung, or is alive but stuck before lab-agent
runs (say waiting for its root device), is reset. An installed-mode boot doesn't hand the
watchdog over (no `systemd.watchdog_sec=0`): systemd holds and feeds it as on any boot,
and lab-agent just notes that. On a test boot lab-agent then holds the watchdog (so the
Mac still shows tier 1) and feeds it only while:

- PID 1 answers. lab-agent asks it for its version every 10 s, and 30 s without an answer
  stops the feeding, test or not. This stands in for systemd's own watchdog, which is off
  on a test boot: a wedged PID 1 is reset within 90 s of its last answer, where
  `RuntimeWatchdogSec=30s` takes 30 s, and a PID 1 too busy to answer for 30 s counts as
  wedged, which lab-agent logs.
- A test runs within its timeout plus 20 s (2 minutes more for a GUI test, as waiting for
  the desktop session can outlast a short timeout), counted, like the timeout, from when
  its script has downloaded. Nothing else extends that: a test that hangs where its timeout
  can't reach it ends in a reset although lab-agent keeps checking in, while labd still
  waits for it.
- Outside tests, the last check-in that reached labd, or the last command starting or
  ending, was less than 10 minutes ago. A test boot stays up for as long as labd is in
  touch (a long log upload, or a Mac left on a lab entry whose one-shot didn't clear), and
  is reset after 10 minutes without labd.

Either way the one-shot is spent and the Mac comes back on its known-good kernel, except
on a Mac whose one-shot didn't clear: that one comes back on the lab entry, so while labd
is down it resets every 11 minutes or so. The watchdog stays running when lab-agent exits,
so a shutdown that stalls is reset 60 s after that, and so is a test boot whose lab-agent
is stopped (`systemctl stop lab-agent`).

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
- Keeps the journal on disk, if it isn't already, with
  `/etc/systemd/journald.conf.d/90-maclab.conf` (`Storage=persistent`), and
  moves this boot's journal there, so labd can read a failed lab boot's journal.
  `--volatile-journal` leaves journald alone.
- Installs and starts `lab-agent.service`.

`setup` refuses, before changing anything, a Mac that can't reboot unattended:
one whose disk needs a passphrase at boot, or, under Limine, one with Limine
config enrollment on. An encrypted volume is fine when a key file unlocks it: one
named in its `/etc/crypttab` or `/etc/crypttab.initramfs` line, a
`/etc/cryptsetup-keys.d/<name>.key`, or `rd.luks.key=` or `cryptkey=` on the
cmdline. What is refused is a volume that would wait for a passphrase and that
boot can't do without: the one under `/` or `/boot`, one the cmdline unlocks
(`rd.luks.uuid=`, `rd.luks.name=`, `luks.uuid=`, `luks.name=`, `cryptdevice=`),
or a crypttab entry without `nofail`. Under GRUB, a `/boot` on dm-crypt is
refused whatever unlocks it later: GRUB asks for its passphrase itself. Limine then
checks `limine.conf` against a checksum built into its EFI binary and stops
booting once the lab edits `limine.conf`. Enrollment is on when
`EFI/BOOT/BOOTAA64.EFI` or `EFI/limine/limine_aa64.efi` on the ESP holds a
checksum, or when `ENABLE_ENROLL_LIMINE_CONFIG=yes` in `/etc/default/limine` has
every Limine update enroll one; set it to `no` there, then run
`sudo limine enroll-config --reset <binary>` for each enrolled binary.
`lab-agent preflight` reports the same as problems, which hold jobs back, and
warns about a journal that isn't kept across reboots: that loses the logs of a
lab boot that fails, but doesn't hold jobs back.

Then run the baseline:

```sh
lab baseline m1air    # two reboots: proves the one-shot selects AND clears
lab crashtest m1air   # optional: deliberate panic, checks it recovers by itself
```

No other job runs on a Mac until its baseline passes.

To take a Mac out of the lab, `sudo lab-agent uninstall` undoes every change `setup` made. First it
tells labd the Mac is leaving: labd cancels the Mac's running and queued jobs, saying why, lists it as
`left`, and from then on neither resets it nor asks for hands, as it otherwise would once the agent
stops mid-job. If labd can't be reached, uninstall goes on, and says so and what to run on the
controller instead (`lab cancel <job>`, then `lab forget <device>`). Then it stops
and removes the agent and its config (with the device secret), clears a lab one-shot, removes the
maclab block from `limine.conf` (or restores `custom.cfg` from its backup), the staged kernels and
the modules the lab installed, and the panic, watchdog, serial-getty and autologin settings, and
maclab's journald drop-in, if a newer setup wrote one. U-Boot's `ubootefi.var.pre-maclab` is kept,
not restored: it would drop any EFI variable set since. It refuses on a lab kernel. While the maclab
block is in `limine.conf`, it also refuses while Limine config enrollment is on, and says how to turn
it off: a Limine binary on the ESP with the file's checksum enrolled would not boot once the block
came out, and with `ENABLE_ENROLL_LIMINE_CONFIG=yes` any Limine update could enroll one mid-uninstall.
Without `--force`, it refuses while a job is in flight or the bootloader can't be found; with it, a
bootloader it can't find is left alone, and so is `/var/lib/maclab`. `--dry-run` prints each action,
or the refusal, without taking it. labd still lists the Mac afterwards:
`lab forget <device>` on the controller drops it (its jobs stay), so it can enroll again under the
same name. It refuses a Mac with a job running or queued, and, unless given `--force`, one that
someone else holds a lease on (forgetting it would end their lease and cut their `lab shell`) or
whose agent still checks in and never said it was leaving. Forgetting a Mac labd doesn't know is done
already: `lab forget` says so and exits 0.

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

## Release gate

`lab gate` answers whether a kernel has passed on real hardware for every supported chip family,
from the jobs already run. It covers the kernel only: lab boots use each Mac's installed m1n1,
U-Boot and device trees (see "Kernel artifacts"), so it says nothing about a boot-chain change.

```sh
lab gate <build-id | kernel sha256 prefix>                    # all six families must pass
lab gate b1015-120000-ab12 --families m1,m2 --evidence gate.json
lab gate b1015-120000-ab12 --volunteers                       # count volunteers' Macs too
```

Families come from the SoC compatible in each Mac's device tree (or, from an agent older than that
fact, its device-tree model): `m1` (t8103), `m1-pro` (M1 Pro/Max/Ultra: t6000-t6002), `m2` (t8112),
`m2-pro` (M2 Pro/Max/Ultra: t6020-t6022), `m3` (t8122) and `m3-pro` (M3 Pro/Max: t6030, t6031,
t6034). M3 Ultra and M4 and later are not covered: those Macs are listed as not counted.

Only plain runs count: ones that boot the Mac's known-good cmdline (no `--cmdline`,
`--cmdline-strip` or `--cmdline-base` other than `known-good`; `--verbose-boot` is fine), run at
least the tests every job on that Mac runs (`boot-health`, and `omarchy-m-test` where labd runs it),
and have no `--omt-allow`. A run with a changed cmdline boots something a release doesn't, so it
counts neither way. A run that tested less counts when it failed, since it failed even so, but not
when it passed. Canceled, `infra_error` and `build_failed` jobs say nothing about the kernel and are
skipped, and so are crash tests, which crash it on purpose. So is a `tests_failed` job whose every
failed test couldn't start at all (its shell exited 126 or 127, as `omarchy-m-test` does when the
desktop user can't read the job's directory) and whose kernel logged nothing fatal; other trouble
running a test (a script that didn't download, no desktop session) looks like the kernel's in the
job's record, so it still counts as a failure. Every other outcome but `pass` is a failure.

Each Mac fails when it failed on the kernel and never passed, passes when it passed and never
failed, and is **flaky** when it did both, in either order: a `lab retry` that passes doesn't hide
the failure before it, and the report lists both jobs. `stage_failed` means the kernel never booted
(the Mac couldn't stage it, e.g. its boot partition was full): it counts only for a Mac with no pass
or failure on the kernel, so a run that couldn't stage never hides another result. A family's
result is decided in this order:

1. **fail** when any of its Macs failed;
2. **flaky** when any of its Macs both passed and failed;
3. **pass** when at least one passed;
4. **couldn't stage** (`stage_failed`) when its only results are Macs that couldn't stage the
   kernel: the gate stays shut, and the report gives the job's reason to fix before running it again;
5. **untested** when none of its Macs has a result, including when it has no Mac in the lab.

Volunteers' Macs (enrolled with `./volunteer`, see [Volunteer a Mac](#volunteer-a-mac)) run agents
the lab doesn't control, so they count only with `--volunteers`; otherwise the report lists them
and their runs apart. A staging problem on one Mac doesn't hide a pass or a failure on another.
The gate is open only when every required family passed. `lab gate` exits 3 when it is shut.

`--evidence` writes the report as one JSON evidence record:
the kernel (sha256, build, release), `result` (`pass` or `fail`), and per family its result and
runs (device, job, outcome, per-test results, the deciding run first; `reason` for a run that
couldn't stage, or a flaky Mac's other result), and `not_counted`, the runs that decide nothing,
each with its reason (`volunteer` marks a volunteer's Mac). Then `volunteers` names the volunteers'
Macs, `volunteers_counted` says whether they counted, and the labd host. The API is
`GET /api/gate/{kernel}?families=m1,m2&volunteers=1`; agents use `lab_gate`.

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
m1n1 stage 2. A lab boot doesn't exercise device-tree changes. [Two installs per Mac](docs/ab-installs.md)
proposes how it could.

## For AI agents

```sh
claude mcp add maclab -- lab mcp
```

Tools: `lab_devices`, `lab_device`, `lab_run`, `lab_wait`, `lab_job`, `lab_jobs`,
`lab_log`, `lab_screenshot`, `lab_baseline`, `lab_crashtest`, `lab_lease`,
`lab_release`, `lab_reset`, `lab_serial`, `lab_exec`, `lab_cancel`, `lab_retry`, `lab_build`,
`lab_build_status`, `lab_package`, `lab_publish` and `lab_gate`. A device in `needs_hands` is waiting for a
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

## Volunteer a Mac

On an Apple Silicon Mac running Omarchy, in a clone of this repo:

```sh
./volunteer          # join the lab
./volunteer leave    # leave it again (sudo lab-agent uninstall)
```

`./volunteer` installs Tailscale and signs in if needed, finds labd among the
tailnet's online machines (port 7770), asks it for an enrollment token, downloads
labd's lab-agent and runs `sudo lab-agent setup --server .. --token .. --gui-user <you>`
with them. Any machine on the tailnet could answer like a lab, and its lab-agent
runs as root, so before signing up it shows the machine that answered (its
tailnet DNS name and host name) and goes on only when you answer `y`. It stops
when more than one lab answers. `MACLAB_SERVER=http://<host>:7770 ./volunteer`
skips the search and the question.

The maintainer runs labd with `--tailscale` (see [Tailscale](#tailscale)) and
keeps `make`'s `bin/lab-agent-linux-arm64` next to labd, which hands it out.
Then they share the labd machine with each volunteer's Tailscale account (admin
console, Machines, Share), or invite them to the tailnet. Any person labd lets
look may enroll a Mac this way (`POST /api/volunteer`): the Mac gets a free
name made from `<user>-<hostname>` and the volunteer's login as its label, and
is marked a volunteer's: `lab gate` leaves its results out unless asked (see
[Release gate](#release-gate)). Tagged tailnet devices, lab Macs under `tag:maclab`
among them, are machines and get no token. Each person holds at most one unused
token: asking again replaces it, so running `./volunteer` again after a setup
that stopped half way just works. At most 20 people hold one at once; the next
gets a 429 until one is used or expires a day later. Admins aren't limited. Next
comes its baseline, `lab baseline <name>`; after `./volunteer leave`,
`lab forget <name>`.

## Phones and the LAN

`labd --trust 192.168.1.0/24,127.0.0.1` (or `MACLAB_TRUST`) lets browsers on
those networks use the UI with no admin token, so a phone can just open
`http://<labd-host>:7770`. It judges the TCP peer address only, never a
forwarded header. Everyone on a trusted network can reboot Macs, open
their serial shell and run commands on them as root, so trust only a
network you'd hand a root shell to. A token still works from anywhere. On a
phone the UI switches to a bottom tab bar and can be added to the home
screen.

## Tailscale

Lab Macs and labd can live on a tailnet: the maintainer's own tailnet while
developing, and a separate tailnet for the Omarchy project before anyone else
joins. Nothing in maclab holds a Tailscale API key; a maintainer does the
tailnet side by hand.

```sh
labd --listen <labd tailnet IP>:7770 --tailscale --admins alice@github,bob@github
```

With `--tailscale`, labd asks the local tailscaled who each tailnet peer is
(`tailscale whois`; answers are cached for a minute, failed lookups for 5
seconds). Logins in `--admins` get admin
access with no token. Every other peer, tagged devices included, may only
look: the dashboard, Macs, jobs, builds, logs and saved screens, including
the console output in the live view and in each job's logs. Anything that
changes the lab, the console itself (`lab shell`), the Mac's stored serial
log and new screenshots answer 403, and device views never carry the
controller's token. Peers off the tailnet still need the admin token, which
keeps working everywhere for `lab` and scripts.

`--trust` still gives admin by the connection's address, so tailnet traffic
that reaches labd from a trusted address gets admin too, whoever sent it.
With `--tailscale`, labd refuses that trust where it can tell: a tailnet
address is judged by its identity even inside a trusted network, and a
request proxied by `tailscale serve` or Funnel (it carries serve's
`Tailscale-User-*`, `Tailscale-Headers-Info` or `Tailscale-Funnel-Request`
headers, or an `X-Forwarded-For` naming a tailnet address) gets no trust and
needs the token. labd can't see the rest: a subnet router that brings tailnet
traffic into a trusted network, or someone who reaches a machine there over
Tailscale SSH and connects from it, looks like local traffic. labd logs a
warning at startup for each trusted network. With `--tailscale`, trust only
networks no tailnet route leads into, or leave `--trust` off and use
`--admins` and the token.

To add a Mac, make a one-off auth key in the admin console (Settings, Keys,
Generate auth key): not reusable, pre-approved, tagged `tag:maclab`, short
expiry. Put it in a file only you can read (`(umask 077; cat > tskey)`), then
on the Mac:

```sh
sudo ./lab-agent setup --server http://<labd tailnet IP>:7770 --token enr_... --tailscale-authkey-file tskey
```

`--tailscale-authkey -` reads the key from stdin instead, and asks for it when
stdin is a terminal. A key given straight to `--tailscale-authkey` still
works, with a warning: the process list and sudo's journal entry show it,
and tailnet viewers can read that journal through labd.

Before anything else, setup runs `tailscale up --auth-key=file:... --advertise-tags=tag:maclab
--ssh --hostname=maclab-<name>` (`--tailscale-hostname` to choose; a first setup
uses the machine's hostname, since the lab name only arrives with enrollment).
The key goes to tailscale in a root-only temporary file, removed as soon as
`tailscale up` returns. On a Mac that is logged in already, setup adds
`--force-reauth`, without which tailscale ignores the new key, so a rerun
with a key from another tailnet really moves the Mac. If tailscale won't
run without naming the Mac's other settings (an exit node, routes), setup
runs it again with `--reset` and lists what went back to its default. Then
it checks that the Mac has a new login, is tagged `tag:maclab`, and is on
the tailnet labd is on (when `--server` is a tailnet address or a `ts.net`
name), and that labd answers. It never prints or stores the key.
Re-joining can cut a Tailscale SSH session, and tailscale may refuse to do
it from one; run setup from the console or over plain SSH then.

A minimal policy: Macs reach only labd, admins reach labd and SSH into the
Macs as root, and the rest of the tailnet may view labd.

```hujson
{
  "groups": {"group:maclab-admins": ["alice@github", "bob@github"]},
  "tagOwners": {
    "tag:maclab":            ["group:maclab-admins"],
    "tag:maclab-controller": ["group:maclab-admins"], // the labd host
  },
  "grants": [
    {"src": ["tag:maclab"], "dst": ["tag:maclab-controller"], "ip": ["tcp:7770"]},
    {"src": ["autogroup:member"], "dst": ["tag:maclab-controller"], "ip": ["tcp:7770"]},
    {"src": ["group:maclab-admins"], "dst": ["tag:maclab"], "ip": ["tcp:22"]},
  ],
  "ssh": [
    {"action": "accept", "src": ["group:maclab-admins"], "dst": ["tag:maclab"], "users": ["root"]},
  ],
}
```

Use `"action": "check"` to make admins re-authenticate before SSH. Tailscale's
free Personal plan may limit Tailscale SSH (unconfirmed; check the plan before
counting on it).

## License

MIT; see [LICENSE](LICENSE). The web UI bundles third-party files under their own
licenses: xterm.js (MIT), subsets of JetBrains Mono Nerd Font and IBM Plex Sans
(SIL OFL 1.1), and the Omarchy logo, icon and font (MIT). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). maclab isn't an official Omarchy
or Asahi Linux project, and it isn't affiliated with Apple.
