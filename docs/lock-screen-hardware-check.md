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
ls /etc/sddm.conf.d /run/sddm.conf.d                       # no maclab autologin file in either
```

## 2. The Volunteer's own boot cannot autologin

Reboot into the Mac's default entry. Expect the SDDM password greeter.
`/run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf` does not exist.

## 3. A Lab boot logs in, locked

```sh
lab run <mac>   # any job that boots a test entry
```

Expect, on the screen:

- No password greeter: the GUI user's session starts, and the lock screen
  (Omarchy's `omarchy-system-lock`, else hyprlock) is up within seconds, before
  the desktop is usable.
- `/run/sddm.conf.d/zz-maclab-lab-boot-autologin.conf` exists, with
  `User=<gui-user>`.
- The job passes, and its omarchy-m-test report has no `video` section checks
  (`omarchy-m-test --skip video` ran), neither in the baseline nor the test run.
- The tests start only once the lock is up: `/run/maclab-lab-boot-lock`
  says `locked` before the job's first test begins.
- The lock screen is still up when the job ends; the Volunteer's password
  unlocks it.

If SDDM ignores the drop-in under `/run`, the unit's path is wrong for this
SDDM: note the config directories `sddm --example-config` lists.

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
is unlocked after every boot, and its omarchy-m-test report keeps the
on-screen checks.

## Results

Record per Mac model: Omarchy and SDDM versions, which lock command was used,
and each step's outcome.
