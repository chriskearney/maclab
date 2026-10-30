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
     ESP needs room for one more UKI plus 121 MiB it keeps free (a 120 MiB
     reserve and 1 MiB for metadata): about 180 MiB with Omarchy's ~60 MiB UKIs.
     Preflight sizes the UKI by the largest one in `<esp>/EFI/Linux`.

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
   counting the Mac as lost. Once the network is back, the test tells labd
   so, and labd stops waiting: a hang in the next test shows after the usual
   60 s of silence. A real suspend can't be
   tested unattended: Apple Silicon's RTC has no wake alarm, so only a key
   press wakes the Mac (a reset ends the boot). labd warns when a test named
   `suspend-*` needs someone there.
5. **Collect.** The journal, kernel log and serial console are saved.
   Warnings and errors that aren't in the Mac's baseline are listed as
   `new_error_lines`.
6. **Restore.** The agent reboots to the known-good kernel, checks that the
   one-shot really cleared, and removes the staged kernel.

A test boot's command line starts from the known-good kernel's and adds the Lab
boot parameters (`panic=10`, `watchdog.open_timeout=N` and the Lab boot marker
`maclab.lab_boot=1`) and `maclab.job=<id>`. It keeps `quiet`, `splash` and `loglevel=`, so the Mac boots
the way its user's boots do; dmesg and the journal record every level anyway. On a Mac
with a serial console, or with `lab run --verbose-boot`, it drops them instead and adds
`loglevel=7` (and the serial console). `lab run --cmdline-base default` starts from the distro's stock
command line (`KERNEL_CMDLINE[default]` in `/etc/default/limine`) instead, to show a
kernel needs no bring-up parameters. `--cmdline-base '<cmdline>'` takes a literal
one. `--cmdline-strip 'asahi.* dcpext_*'` drops matching parameters, and `--cmdline`
appends. The job records the staged and the booted command line. Test boots also
keep `systemd-analyze` time, blame and critical-chain.

Outcomes: `pass`, `tests_failed`, `booted_unhealthy`, `panicked`, `hung`,
`crashed_or_hung`, `boot_failed`, `lost_contact`, `stage_failed`, `infra_error`, `canceled`.
`crashed_or_hung` means the Mac rebooted during a test with no kernel error
captured (`panicked` needs one); its summary gives the seconds from the last
check-in to the next boot's first, and back within about 90s reads as a crash
(`panic=10` reboots in seconds), later as a watchdog reset after a hang, which is
an inference, not a diagnosis.

## Lab boots come back by themselves

Every Lab boot gets the Mac back to its known-good kernel without help, on
every Mac. The one-shot is spent by the time anything below fires, so each
reboot lands on the Mac's own entry.

- `panic=10` reboots a panic, even one before the sysctl applies.
- `watchdog.open_timeout=N` (labd `--watchdog-open-timeout`; by default half the job's boot timeout, at least 120s)
  resets an early hang: U-Boot leaves the hardware watchdog running into the
  kernel, `apple_wdt` takes it over, and the kernel stops feeding it unless
  systemd opens it within N seconds (worst case N + 30s). A test kernel must
  be built with `apple_wdt`, or the watchdog resets it about 60s into every
  boot; the job flags one without it.
- Before every Lab boot, lab-agent writes a deadline record to
  `/var/lib/maclab/lab-boot/`: **no contact** (twice the job's boot timeout,
  unless lab-agent reaches labd first) and a **hard ceiling** (the job's end).
  `maclab-lab-boot-deadlines.service`, an early unit with no network
  dependency, reboots a Lab boot when either passes, and on a Volunteer's Mac
  as soon as its Availability window closes. labd waits for that
  before its recovery ladder, so a Lab-owned Mac's OOB hard resets are a later rung.
- After any recovery, lab-agent uploads the lost boot's journal (by boot ID)
  and any pstore/ramoops records, as `prevboot/` in the job.
- A boot that came back only through its deadline fails as `lost_contact`:
  the kernel or Release broke networking.

[docs/lab-boot-hardware-check.md](docs/lab-boot-hardware-check.md) is the
check that the early unit and the watchdog work on a real Mac.

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

On a Volunteer's Mac the ladder differs: nothing reaches the Volunteer until
the Lab boot's Hard ceiling plus one boot timeout have passed with no check-in
(by then its own deadlines have had every chance to bring it back), and the
notice goes only to the Mac's own ntfy topic, never the lab-wide topic or
`--notify-cmd`, which are the Maintainers'. `sudo lab-agent notify --topic
https://ntfy.sh/my-topic` switches the Mac to the Volunteer's own topic; it
reaches labd at the next check-in, and `status` shows the `subscribe to:` URL.

When the Mac checks in again, the alert clears, leftover staged kernels are
removed, and queued jobs continue. `lab status` shows the same instruction
while it's outstanding.

A job that couldn't stage its kernel ends `stage_failed`, with the reason and
`lab retry <job>` in its summary. `lab retry` (or Retry on a finished job's page)
runs any finished job again as a new job: the same Mac, kernel, tests and cmdline,
and the new job records which one it retries (`retry_of`). A source job boots the
kernel its first run built. Once that has been collected, the retry builds again
from the exact commit and the config the first build recorded, not from wherever
its branch or pull request points now or the Mac's config as it is now; a job
that recorded no commit, or whose config has been collected too, can't be
retried (a build from another config would be another kernel), and the refusal
says to run it afresh with `lab run`.
`lab retry` holds the new job as you, and the web UI's Retry as `web`.

Each Mac gets a recovery tier: 0 = panic reboot + one-shot fallback and the
Lab boot deadlines,
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
half the job's boot timeout, and at least 120 (what an older labd, which doesn't send its
timeout, gets too): 120 with labd's default 4-minute `--boot-timeout`, 300 with
`lab run --boot-timeout 600`. The other half is left for the reset and the fallback boot, so labd
sees the Mac back on its known-good kernel before it gives up and resets it mid-fallback,
with a margin that grows with the timeout. A per-job `--boot-timeout` under 4 minutes still gets
N = 120, which leaves the reset and the fallback boot less than half of it: they may not be done
before labd stops waiting, and labd then resets the Mac mid-fallback. Any boot that hasn't opened the
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
  its script has downloaded (a builtin test downloads nothing, even one that names a script
  too). Nothing else extends that: a test that hangs where its timeout can't reach it ends
  in a reset although lab-agent keeps checking in, while labd still waits for it. A test
  already running when lab-agent opens the watchdog late (on a retry) gets the same budget,
  counted from when it started, so one already past it is reset at once.
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
labd --maintainer <you>              # first start: you become the first Maintainer (default $USER)
lab login http://<labd-host>:7770 "$(cat ~/.local/share/maclab/admin.token)"
lab enroll m1air --label "MacBook Air M1, left desk"
```

Each Maintainer has their own labd token. `lab maintainer add <name>` prints
a new one once (labd keeps only its hash); `lab maintainer list` and
`lab maintainer remove <name>` do the rest, and removing someone revokes their
token at once. Jobs and Promotions record the Maintainer whose token asked.
Upgrading from a labd with a single admin token keeps that token, in the same
`admin.token` file, as the first Maintainer's (`--maintainer`, default `$USER`).

labd listens on `127.0.0.1:7770` unless told otherwise. For Macs over Tailscale,
start it with `--listen <tailnet-ip>:7770` (or `MACLAB_LISTEN`) so it is not
reachable off the tailnet. Remote links are slow, so the timeouts that assume a
LAN are flags: `--boot-timeout`, `--offline-after`, `--alive-window`,
`--quiet-grace` and `--stage-timeout` (defaults are sized for remote Macs).
Artifact downloads resume with HTTP range requests after a dropped transfer. An
enrollment token is spent by the Mac's first check-in, so a failed `setup` can
be run again with the same token until it expires. lab-agent's own request
timeouts are `http_timeout_sec` and `transfer_timeout_sec` in its config file.

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
- Installs and enables `maclab-lab-boot-deadlines.service`, which reboots a Lab boot that misses its deadline.
- With `--autologin`, logs the GUI user into the desktop on boot; with `--autologin` or `--stay-awake`, turns their idle lock and screensaver off (Lab-owned Macs only).
- Installs and starts `lab-agent.service`.

`setup` refuses, before changing anything, a Mac that can't reboot unattended:
one whose disk needs a passphrase at boot, or, under Limine, one with Limine
config enrollment on. An encrypted volume is fine when a key file unlocks it. For the
volume under `/` (or an encrypted `/boot`), that must be a key file the initramfs can read
before `/` is unlocked: one its `/etc/crypttab.initramfs` line names, or `rd.luks.key=` or
`cryptkey=` on the cmdline, and not on that volume itself (as in
`rd.luks.key=<file>:<device>` or `cryptkey=<device>:...` naming it, or `root=`). Keys in
`/etc/crypttab` and `/etc/cryptsetup-keys.d/<name>.key` live on `/` and the initramfs
reads neither, so they count only for other volumes; the `encrypt` hook (`cryptdevice=`)
reads no crypttab at all, only `cryptkey=`. What is refused is a volume that would wait
for a passphrase and that boot can't do without: the one under `/` or `/boot`, one the
cmdline unlocks (`rd.luks.uuid=`, `rd.luks.name=`, `luks.uuid=`, `luks.name=`,
`cryptdevice=`), or a crypttab entry without `nofail`. Under GRUB, a `/boot` on dm-crypt is
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
controller instead (`lab cancel <job>`, then `lab forget <device>`). Then it stops the agent. If
that fails, or uninstall is interrupted (Ctrl-C) before it, nothing else is changed, and while the
agent runs on, uninstall tells labd the Mac stays after all: labd puts it back in the pool (its
canceled jobs stay canceled). But `systemctl disable --now` can fail, or die of a Ctrl-C, while
systemd goes on to stop the agent, so uninstall first asks systemd whether `lab-agent.service` is
still active or enabled. If it is neither, there is no agent to keep the Mac in the lab: uninstall
leaves it `left`, says so, and finishes when run again. If labd doesn't hear that the Mac stays,
uninstall says so: `lab reset <device>` on the controller puts a Mac that left back in the lab, and
runs the recovery ladder on it, out-of-band reset included, as for any Mac (a Mac that wedged
mid-uninstall, say). Only labd's own recovery leaves a Mac that left alone. Don't `lab reset` a Mac
whose uninstall finished: it brings back a Mac with no agent, which then goes through recovery,
out-of-band resets and all, and ends in a call for hands. Use `lab forget` for it instead. Once the
agent is stopped, uninstall disables and removes it and the lab's other units
(`maclab-lab-boot-deadlines`, `-session` and `-lock`, as `leave` does), then its config (with the device secret), clears a lab one-shot, removes the
maclab block from `limine.conf` (or restores `custom.cfg` from its backup), the staged kernels and
the modules the lab installed, and the panic, watchdog, serial-getty, autologin and stay-awake settings, and
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

### A Volunteer's Mac

A Mac is Lab-owned or a Volunteer's for as long as it stays enrolled; the
enrollment token decides which, and changing it means enrolling again.

```sh
lab enroll ada-mbp --volunteer "Ada Lovelace" --contact ada@example.org
```

Either flag without the other is refused. labd gives the Mac its own
unguessable ntfy topic when it enrolls (on the server `--ntfy` posts to), and
`setup` prints it with a QR code to subscribe from a phone. On a Volunteer's
Mac `setup` refuses `--autologin` and `--stay-awake`. Setup and every
check-in report whether `@` can be snapshotted (`/` is the btrfs subvolume
`@` and snapper has a root config for it); a Mac whose `@` can't is shown as
not eligible for Installed runs. On the Mac, `sudo lab-agent status` shows
what it is enrolled as, its topic, its Availability window and its
eligibility.

Nothing from the lab starts on a Volunteer's Mac outside its Availability
window, the baseline included, and a Mac with no window is closed. Only the
Volunteer sets it, on the Mac, in the Mac's local time:

```sh
sudo lab-agent window add mon-fri 19:00-07:00   # a window crossing midnight belongs to the day it starts
sudo lab-agent window remove mon-fri 19:00-07:00
sudo lab-agent window show
sudo lab-agent pause                     # end the current window now
sudo lab-agent pause --until 2026-11-03  # closed until that date begins
sudo lab-agent open --until 22:00        # open now until 22:00, whatever the schedule says
```

These take effect at once and work with labd or the tailnet down; check-ins
carry them to labd, which has no API to change them. lab-agent refuses any lab
command outside the window, and the job records the refusal. labd starts a job
on a Volunteer's Mac only inside its window, on AC power, and when the job's
expected length fits in what is left of the window; until then the job stays
`queued`. `--omt-every` refreshes wait for a window the same way. A Lab boot's
hard ceiling is the window's end if that comes before the job's end.

At the window's end, or on `pause`, lab-agent stops the job itself, on its own
clock and with labd or the tailnet down too: staging stops where it is, and a
Lab boot (one that hasn't reached labd yet included) reboots to the Known-good
kernel within a second or two. The job ends `incomplete`, not failed, and labd
queues it again as a new job for a later window. A lease on a Volunteer's Mac
ends with the window at the latest, and `pause` ends it. While a job holds the
Mac, lab-agent blocks suspend (`systemd-inhibit --what=sleep --mode=block`)
and releases it after; the idle lock and screensaver are never touched.
Nothing wakes a sleeping Mac: a window it sleeps through is missed.

About 5 minutes before a job's first reboot (labd's `--reboot-warning`, 0 for
none), a desktop notice in the Volunteer's session names the job and the
reboot's time, with a Pause button that does what `pause` does; the job waits
those minutes, and one warning is shown per job. With no desktop session to
show it, the job goes ahead within the window. The Audit log records, per job,
whether the warning was shown. Lab-owned Macs get no warning and no wait.

A Volunteer can also ask to be told about jobs on the Mac's own ntfy topic:
`sudo lab-agent notify --jobs on` (off by default; `off` turns it off again,
and `status` shows it). As a job starts, the notice names the job and who
asked, says the job takes at most about so many minutes, and asks the
Volunteer to leave the Mac alone until the done notice. When the job ends, a
second notice says how it ended and that the Mac is free. A Mac that still
needs hands gets that notice once it is back, and one whose job labd lost by
restarting gets it at once. Nothing else about jobs goes to the Mac's topic,
and Lab-owned Macs get none of this.

The Volunteer also chooses what Maintainers may do on the Mac, its Access
level, and can read everything done to it, its Audit log:

```sh
sudo lab-agent access qualification   # the default: no lab exec, --script or --gui-script
sudo lab-agent access full            # everything a Lab-owned Mac allows
sudo lab-agent log                    # every Maintainer action on this Mac (works offline)
sudo lab-agent jobs                   # the lab's jobs on this Mac
sudo lab-agent publish on|off         # omarchy-m-test publishing; on lists the deletion links
```

At Qualification labd rejects `lab exec`, `--script` and `--gui-script` at
submit (`403`, naming the Access level), and lab-agent refuses them at run
whatever labd sends: Qualification still takes baselines, crash tests,
built-in tests, omarchy-m-test and lab-kernel runs. Like the window commands,
`access` takes effect on the Mac at once, with labd down too. Lowering it ends
a lease at once, and a job running a Maintainer's script ends `incomplete`:
its Lab boot reboots to the Known-good kernel within a second or two. A job it
still allows keeps running. At either level the Mac's screen and live journal
are shown only while a job or lease holds it inside its window; a job's own
screenshots are still taken.

Every command labd sends carries the Maintainer it acts for (the one who
asked, or whose job it is) and its job. Before acting, lab-agent appends who,
what (with the command or script text), the job and the time to the Mac's
append-only Audit log, `/var/lib/maclab/audit.log`, and records each refusal
too. Leaving the lab leaves the log in place: it is the Volunteer's record.
Reports carry new entries to labd, whose copy Maintainers read with `lab audit
<mac>` (`GET /api/devices/{n}/audit`). `status` shows the Access level and the
latest entries.

An Installed run (`lab run <mac> --installed <manifest>`) is Qualification
work: on a Volunteer's Mac only the Release's expected manifest is frozen
beforehand (`lab installed freeze-manifest`), and its package files are
uploaded (`lab upload`) so lab-agent can fetch them by sha256. The run takes
the preinstall references from the Volunteer's own system (an omarchy-m-test
run and the boot's kernel error lines, frozen and pinned in
`PINS.preinstall`), then installs the Release through one named install
operation: lab-agent fetches exactly the manifest's packages and installs
them with `pacman -U`, as the Omarchy installer does. The Audit log records
the install, with the Maintainer, the Release and the job, before it runs. A
failed install ends the run before any Lab boot. The identity checks before,
booted and after are lab-agent's own read-only collector, not a script, and
identity-before freezes the installer's entry the Mac shows. A Mac at
Qualification still refuses any script, even one named `identity-*`, and
`lab exec`. Lab-owned Macs keep the hand-run flow: a Maintainer installs the
Release, freezes the preinstall references and runs `lab installed
freeze-entry`.

### Leaving

A Volunteer can leave at any time, and the Maintainers can end an enrollment.
Either way nothing of the lab is left on the Mac.

```sh
sudo lab-agent leave          # asks first; --yes answers for you (scripts)
lab remove ada-mbp            # a Maintainer ends the enrollment in labd
```

`leave` is immediate and works with labd down. It stops any job (the job ends
`incomplete`), reboots a Lab boot to the Known-good kernel, removes the lab's
boot entries (its block in `limine.conf`, or its hook in GRUB's `custom.cfg`,
leaving every other line as it was, and the staged kernels), its systemd
units, the Lab-boot autologin drop-in, sysctl and watchdog files and the device
secret, and tells labd. If labd can't be reached, lab-agent keeps trying
and finishes leaving once it has told labd. Then it prints what is left to
remove by hand: the lab-agent package and the Tailscale node. The Audit log
(`/var/lib/maclab/audit.log`) and Access level stay, and `log` still reads
them. Only a Volunteer's Mac has `leave`; a Lab-owned Mac's enrollment is
ended by the Maintainers.

`lab remove` (`POST /api/devices/{name}/end-enrollment`) takes the Mac out of labd at once:
its device secret is refused from that moment, whether or not the Mac checks in
again, and a job on it ends `incomplete` and is not retried. The Volunteer
is told on the Mac's own ntfy topic and, at its next check-in, on the desktop,
which Maintainer ended it. At that check-in lab-agent does what `leave` does
and appends the Maintainer to the Audit log. To enroll the Mac again, a
Maintainer makes a new token (`lab enroll`); the Mac's Kind follows that token.

These are not `lab-agent uninstall` and `lab forget` (see [Setup](#setup)
above), which stay as they were. `uninstall` is the full
teardown of a Mac set up for the lab: labd lists the Mac as `left` until `lab
forget` drops its record, and `lab reset` (or an uninstall that stops early)
can bring it back. `leave` is the Volunteer's one-step exit: labd forgets the
Mac and refuses its secret at once (`POST /api/agent/left`), and there is
nothing to undo. Likewise `lab forget` drops the record of a Mac that has
already gone, refusing one whose agent still checks in, while `lab remove`
ends the enrollment of a live Volunteer's Mac, which then removes the lab
itself.

Publishing omarchy-m-test reports is off on a Volunteer's Mac until its
Volunteer runs `publish on`, whatever `--omt-publish` or a job's `--publish`
asks; `lab publish` is refused too. Each `publish on` lists the deletion link
of every report published so far.

A Mac enrolled with `./volunteer` (see [Volunteer a Mac](#volunteer-a-mac)) is a
Volunteer's too, named and reached by the tailnet login that ran it.

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
  fails on both kernels, the unclaimed nodes are compared compatible by
  compatible, counting nodes: more nodes of a compatible left unclaimed on the
  test kernel than on the known-good one (none then, or 3 against 1) regress as
  `hardware.drivers:<compatible>`, and fewer count as fixed. A reference
  recorded before the lab counted nodes compares compatibles only.
- **Publishing:** `lab run <mac> --publish`, `lab publish <job>`, or the job page's
  Publish button uploads the signed report to omarchy-m-testing.org. Only
  known-good runs qualify, because the site names a report's build from the
  installed packages, and those don't describe a lab kernel. The site's deletion
  link stays in the job's `omt-published.json`. A Volunteer's Mac is published
  only once its Volunteer opts in (see above).

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
lab gate b1015-120000-ab12 --exclude j1015-093012-ab12        # set a lab-caused failure aside, this once
lab exclude j1015-093012-ab12 --reason "the access point went down mid-test"   # ... in every report
lab exclude j1015-093012-ab12 --clear                         # count it again
```

Families come from the SoC compatible in each Mac's device tree (or, from an agent older than that
fact, its device-tree model): `m1` (t8103), `m1-pro` (M1 Pro/Max/Ultra: t6000-t6002), `m2` (t8112),
`m2-pro` (M2 Pro/Max/Ultra: t6020-t6022), `m3` (t8122) and `m3-pro` (M3 Pro/Max: t6030, t6031,
t6034). M3 Ultra and M4 and later are not covered: those Macs are listed as not counted.

Only plain runs count: ones that boot the Mac's known-good cmdline (no `--cmdline`,
`--cmdline-strip` or `--cmdline-base` other than `known-good`; `--verbose-boot` is fine), run at
least the tests every job on that Mac runs (`boot-health`, and `omarchy-m-test` where labd runs it,
each known by its builtin whatever the job named it), and have no `--omt-allow`. Where labd runs
`omarchy-m-test`, a pass counts only if its report was compared with the Mac's known-good run of
it: with nothing to compare with, nothing could regress, so such a pass is listed as not counted
("no OMT reference"; `lab baseline` makes the reference). A run with a changed cmdline boots
something a release doesn't, so it counts neither way. A run that tested less counts when it
failed, since it failed even so, but not when it passed. Canceled, `infra_error` and `build_failed`
jobs say nothing about the kernel and are skipped, and so are crash tests, which crash it on
purpose. So is a `tests_failed` job whose every failed test never started, because bash couldn't
open the test's script, and whose kernel logged nothing fatal: the last thing the test printed is
bash's own error for its `test-<name>.sh`, exiting 126 for `Permission denied` (as for
`omarchy-m-test` when the desktop user can't read the job's directory) or 127 for `No such file or
directory`. A test that ran and exited 126 or 127 itself, say for a binary it couldn't execute
(`Exec format error`) or a command it couldn't find, failed like any other, and other trouble
running a test (a script that didn't download, no desktop session) looks like the kernel's in the
job's record, so it still counts as a failure. A job canceled after its kernel had already failed
(a panic, a reboot or hang during a test, a test that failed by itself) keeps that failure as its
outcome, with the cancel in its summary; tests the cancel cut short are the cancel's. Every other
outcome but `pass` is a failure.

Each job records its Mac as it was when the job was submitted: its chip family, whether it was a
volunteer's, and whether labd ran `omarchy-m-test` in its jobs. The gate judges the job by that,
so what the Mac became since (or another Mac enrolled under its name after `lab forget`) doesn't
change the verdict; a job from before labd recorded it is judged by the Mac as it is now. A Mac
labd no longer has (`lab forget`) doesn't count: its runs are listed as not counted, "device gone",
under their family, or under the report when the job didn't record its family.

Each Mac fails when it failed on the kernel and never passed, passes when it passed and never
failed, and is **flaky** when it did both, in either order: a `lab retry` that passes doesn't hide
the failure before it, and the report lists both jobs, a retry naming the job it retries
(`retry_of`). `stage_failed` means the kernel never booted (the Mac couldn't stage it, e.g. its
boot partition was full): it counts only for a Mac with no pass or failure on the kernel, so a run
that couldn't stage never hides another result. A family's result is decided in this order:

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

A failure the lab caused can read as the kernel's: an access point that goes down during a test
makes the Mac look lost, `crashed_or_hung`, and that failure would keep its family flaky for good.
`--exclude j1,j2` sets those jobs aside for that one report. They are listed as excluded, in
`excluded` and, marked `excluded`, in their family's `not_counted`, and the summary names them, so
the decision is on the record; nothing is kept, so a `lab gate` without it counts them again. Only
finished jobs of the kernel can be excluded.

`lab exclude <job> --reason "..."` keeps a job aside instead: labd marks the job (`gate_exclusion`:
who set it aside, why and when), and every `lab gate` after that, release scripts' included, sets it
aside as `--exclude` would, without being asked. The report lists each such job of the kernel in
`exclusions`, with who, why and when, and the summary names them; a run it sets aside that would
have counted is in its family's `not_counted`, marked `excluded`, with the mark as `exclusion`.
`lab job` shows the mark too. It takes a Maintainer's token and a reason, and only a finished job; the
person is the Maintainer whose token asked. `lab exclude <job> --clear` takes it off, and
the job counts again. It is for a failure the lab caused, never for one of the kernel's that would
keep a release back. Jobs from before labd kept the mark have none, and count as before. The API is
`POST /api/jobs/{id}/exclude` with `{"reason": "...", "by": "..."}`, and `DELETE` to clear; agents
use `lab_exclude`.

Results are strings: a family's is `pass`, `fail`, `flaky`, `stage_failed` or `untested`, and a
run's `pass`, `fail`, `flaky` or `stage_failed`. A script that looks for `"fail"` must treat
`"flaky"` as not passing too. The report's own `result` is only ever `pass` (the gate is open) or
`fail`.

`--evidence` writes the report as one JSON evidence record:
the kernel (sha256, build, release), `result` (`pass` or `fail`), and per family its result and
runs (device, job, outcome, per-test results, the deciding run first; `reason` for a run that
couldn't stage, or a flaky Mac's other result; `retry_of` for a retry), and `not_counted`, the runs
that decide nothing, each with its reason (`volunteer` marks a volunteer's Mac, `excluded` a job
`--exclude` or `lab exclude` set aside, and `exclusion` the latter's mark). Then `volunteers` names
the volunteers' Macs, `volunteers_counted` says whether they counted, `excluded` lists the jobs
`--exclude` set aside, `exclusions` those `lab exclude` did (job, device, outcome, by, reason,
time), `not_counted` holds the runs of forgotten Macs whose jobs didn't record their family, and the
labd host. The API is
`GET /api/gate/{kernel}?families=m1,m2&volunteers=1&exclude=j1,j2`; agents use `lab_gate`.

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
`lab_build_status`, `lab_package`, `lab_publish`, `lab_gate` and `lab_exclude`. A device in `needs_hands` is waiting for a
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
- The named install operation (`pacman -U` of the Release's packages) and
  omarchy-m-test's preinstall run on a Volunteer's own, possibly locked,
  session.
- Whether `apple_wdt` can be armed before the kernel starts (m1n1/U-Boot).
  If it can, tier 1 would also cover early-boot hangs.

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
tailnet DNS name and host name, printable ASCII only, since the machine picks
its own host name) and goes on only when you answer `y`. It stops
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
gets a 429 until one is used or expires a day later. Each person may have at
most 3 Macs in the lab, counted by tailnet login; a fourth gets a 409 until
`lab forget` drops one of them. Maintainers, asking with their token, aren't
limited. Next
comes its baseline, `lab baseline <name>`; after `./volunteer leave`,
`lab forget <name>`.

## Phones

Open `http://<labd-host>:7770` and enter your Maintainer token; the UI keeps
it. Every change needs a Maintainer's token, whatever network it comes from;
with `--tailscale`, tailnet peers may look without one (see
[Tailscale](#tailscale)). On a phone the UI
switches to a bottom tab bar and can be added to the home screen.

A browser on the tailnet carries its access to every page it opens, so labd
refuses (403) any request but GET, HEAD and OPTIONS whose `Origin`
names another host or port than the `Host` it was sent to, or that comes with
`Sec-Fetch-Site: cross-site` or `same-site` and no matching `Origin`. Another
site's page can't run commands on the Macs, and labd's own UI, served from
the address it calls, works as before. The lab CLI, agents, builders and
curl send neither header and aren't affected. A proxy in front of labd must
pass on the `Host` the browser asked for.

A page can get past that check by DNS rebinding: its site points the page's
own name at labd's address once the page is open, and then the page and labd
are one origin to the browser. So access that comes with no token, from a
tailnet login, counts only on a request that asked for labd by
one of its own names: an IP address, `localhost`, this machine's host name
(short, fully qualified and under `.local`) and, with `--tailscale`, its
MagicDNS name. Any other name gets a 403 that names it, for GETs too, since a
page could read the lab as well; the UI shows why and asks for the token. If
browsers reach labd by another name, a DNS alias say, run labd with
`--allow-host labd.lan` (repeatable, or a comma-separated list). The token,
device secrets and the builder token work by any name, so the lab CLI, agents,
builders and scripts with a token don't care.

## Tailscale

Lab Macs and labd can live on a tailnet: the maintainer's own tailnet while
developing, and a separate tailnet for the Omarchy project before anyone else
joins. Nothing in maclab holds a Tailscale API key; a maintainer does the
tailnet side by hand.

```sh
labd --listen <labd tailnet IP>:7770 --tailscale
```

With `--tailscale`, labd asks the local tailscaled who each tailnet peer is
(`tailscale whois`; answers are cached for a minute, failed lookups for 5
seconds). Every peer, tagged devices included, may look with no token: the
dashboard, Macs, jobs, builds, logs and saved screens, including the console
output in the live view and in each job's logs. Anything that changes the
lab, the console itself (`lab shell`), the Mac's stored serial log and new
screenshots need a Maintainer's token and answer 403 without one, and device
views never carry the controller's token. A Maintainer's token works from
anywhere, on the tailnet or off it, for the UI, `lab` and scripts.

To add a Mac, make a one-off auth key in the admin console (Settings, Keys,
Generate auth key): not reusable, pre-approved, tagged `tag:maclab`, short
expiry. On the Mac, put it in a file only you can read, run setup with it,
and remove the file:

```sh
(umask 077; cat > tskey)    # paste the key, Enter, then Ctrl-D
sudo ./lab-agent setup --server http://<labd tailnet IP>:7770 --token enr_... --tailscale-authkey-file tskey
shred -u tskey
```

Setup refuses a key file that group or others may read: make a new key
then, since anyone could have read that one. `--tailscale-authkey -` reads
the key from stdin instead, and asks for it when stdin is a terminal. A key
given straight to `--tailscale-authkey` is refused: by the time setup sees
it, the process list and sudo's journal entry show it, and tailnet viewers
can read that journal through labd. Revoke such a key and make a new one.

Before anything else, setup runs `tailscale up --auth-key=file:... --advertise-tags=tag:maclab
--ssh --hostname=maclab-<name>` (`--tailscale-hostname` to choose; a first setup
uses the machine's hostname, since the lab name only arrives with enrollment).
The key goes to tailscale in a root-only temporary file, removed as soon as
`tailscale up` returns. On a Mac that is logged in already, setup adds
`--force-reauth`, without which tailscale ignores the new key, so a rerun
with a key from another tailnet really moves the Mac. If tailscale won't
run without naming the Mac's other settings (an exit node, routes), setup
lists the settings that go back to their defaults, then runs it again with
`--reset`. It keeps `--shields-up` if the Mac had it, and says so: that
blocks every connection into the Mac, Tailscale SSH included. Then
it checks that the Mac has a new login, is tagged `tag:maclab`, and is on
the tailnet labd is on (when `--server` is a tailnet address or a `ts.net`
name). If it isn't, setup logs the Mac out (`tailscale logout`)
rather than leave it on the wrong tailnet, or untagged, with Tailscale SSH
on, and says so; make a new key and run setup again. Last, it checks that
labd answers. It never prints or stores the key, and removes the key file
when stopped by Ctrl-C, SIGTERM or a dropped SSH session (SIGHUP).
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

## Artifact package boot-test workflow

`lab boot-test` accepts an exact reviewed device profile/catalog and kernel, Mesa and boot-setup artifacts, compiles the finite workflow, then invokes the real local runner with plan-bound authorization. Recovery mode is explicit (`network-only` or `serial-assisted`); pending device adapters are refused. See [the command, source-review contract and limits](docs/artifact-boot-test.md). `make boot-test-dist BOOT_TEST_OUT=/owned/new-prefix` builds a relocatable local command/resource prefix without installing services or contacting a Mac. Device owner/compiler closures and per-run artifact/authorization data remain explicit reviewed inputs; this does not claim every historical prototype is packaged or portable.
