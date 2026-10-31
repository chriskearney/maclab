# Hardware check: the lock screen stays on a Volunteer's Mac

The lab harness proves the autologin decision and the skipped on-screen checks
on a simulated Mac. This is the check on a real one: that a Lab boot logs the
Volunteer's GUI user in behind the lock screen, and that nothing else does. Run
it once per Mac model, and again after an Omarchy or SDDM update. Record the
results at the end.

You need: a Volunteer's Mac (unencrypted, enrolled with `--gui-user`) whose
baseline passed, `lab` logged in to labd, a way to see the Mac's screen, and
about 30 minutes. Start from the Volunteer's own boot.

## 1. The units are in place

```sh
systemctl is-enabled maclab-lab-boot-session.service maclab-lab-boot-lock.service   # enabled, enabled
systemctl show -p Before maclab-lab-boot-session.service   # lists sddm.service
ls -l /etc/sddm.conf.d /run/sddm.conf.d                    # no maclab file in /run; in /etc at most a dangling zz-maclab-lab-boot-autologin.conf link
```

## 2. The Volunteer's own boot cannot autologin

Reboot into the Mac's default entry. Expect the SDDM password greeter.
`/run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf` does not exist, so the
`/etc/sddm.conf.d` link to it (left by an earlier Lab boot) dangles, and SDDM
skips it.

## 3. A Lab boot logs in, locked

```sh
lab run <mac>   # any job that boots a test entry
```

Expect, on the screen:

- No password greeter: the GUI user's session starts, and the lock screen
  (Omarchy's `omarchy-system-lock`, else hyprlock) is up within seconds, before
  the desktop is usable.
- `/etc/sddm.conf.d/zz-maclab-lab-boot-autologin.conf` is a link to
  `/run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf`, which exists, with
  `User=<gui-user>`.
- The job passes, and its omarchy-m-test report shows the `video` section's
  checks skipped (`--unattended` and `--skip video` both ran), in the baseline
  and the test run alike.
- The tests start only once the lock is up: `/run/maclab-lab-boot-lock`
  says `locked` before the job's first test begins.
- The lock screen is still up when the job ends; the Volunteer's password
  unlocks it.

SDDM 0.21 reads `/etc/sddm.conf.d` and `/usr/lib/sddm/sddm.conf.d`, never
`/run/sddm.conf.d`, which is why the drop-in is reached through the link. If
the password greeter still shows, check the link resolves (`cat` it) and that
no `/etc/sddm.conf` overrides `[Autologin]`: SDDM reads that file last.

Then make the lock fail (`sudo chmod -x $(command -v omarchy-system-lock hyprlock)`)
and run a job again. Expect the session to be terminated, the job to fail
saying the Volunteer's session could not be locked, and no test to have run
on an unlocked session. Restore the execute bits.

## 4. Back on the Volunteer's own boot

After the job, the Mac reboots to its known-good kernel. Expect the password
greeter again, and no drop-in under `/run`.

## 5. An encrypted Mac keeps Omarchy's autologin

On an encrypted Volunteer Mac, a Lab boot writes no drop-in
(`journalctl -u maclab-lab-boot-session` says so). Omarchy's own autologin,
if the installer set one, is unchanged.

## 6. A Lab-owned Mac is unchanged

On a Lab-owned Mac, `--autologin` and `--stay-awake` still apply, the desktop
is unlocked after every boot. Its omarchy-m-test run is unattended too, so its
report skips the on-screen checks as well, unless the tool is older than 0.1.15.

## Results

Record per Mac model: Omarchy and SDDM versions, which lock command was used,
and each step's outcome.
