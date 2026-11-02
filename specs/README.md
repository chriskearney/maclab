# Specs

TLA+ specifications of the parts of maclab where the bugs have been in how several actors interleave, not in any one function. TLC, the TLA+ model checker, tries every interleaving of a small model and either proves the properties hold for it or prints the shortest run that breaks one. See `docs/adr/0004-model-the-lab-boot-in-tla.md` for why.

```sh
make spec                                           # fetches the pinned tla2tools.jar, then checks every model
specs/labboot/check.sh models/current.cfg           # one model (set TLA2TOOLS to the jar)
```

`make spec` needs `java` (17 or later). CI runs it in the `spec` job of `.github/workflows/test.yml`.

## labboot: one Lab boot

`labboot/LabBoot.tla` follows one Lab boot of a Lab-owned Mac in whole minutes. labd sends `boot_once`. lab-agent writes the deadline record, arms the Limine one-shot, re-arms before its report and again before the reboot, and holds the watchdog on the Lab boot. The firmware boots whatever the one-shot and `limine.conf` select. The early unit enforces the No-contact deadline and the Hard ceiling. labd waits, walks the recovery ladder, classifies, and restores the Mac to its Known-good kernel. Faults (snapshot syncs, failed arms and cancels, lost reports, no network, a broken or crashing kernel, a cancel) strike whenever they like.

The properties, named as in the module:

| Property | What must hold | Guards |
|---|---|---|
| `BlameSound` | labd blames the test kernel (`boot_failed`, `hung`, `crashed_or_hung`, `tests_failed`) only for what the kernel did; an infra fault reads as `infra_error` or `lost_contact` | 18b9311, 2f2e337 |
| `PassSound` | a pass is the test kernel's: it booted, and the test ran on it | 6b6eae6 |
| `NetLossNotBlamed` | a Lab boot that only lost its network is not the kernel's failure | open (#44, part 1) |
| `LabBootOnlyDuringJob` | once labd is done, the Mac runs its Known-good kernel, or labd has taken it out of the pool | 1995466 |
| `ArmFailedMeansDisarmed` | lab-agent never tells labd an arm failed while the one-shot is still set | b804c41 |
| `NoContactBeforeWatchdog` | the No-contact deadline, not the agent's watchdog, ends a Lab boot that never reached labd | 2f2e337 |
| `WatchdogIdleFromLabd` | outside a test, a Lab boot that lost labd is reset `watchdogIdle` after the last sign of labd, no later | 953652a |
| `BoundedFirmwareWrites`, `OneFirmwareWrite` | NVRAM and U-Boot's file see one one-shot write per Lab boot, however long labd is out of reach | b804c41 |
| `HandsOnlyWhenStuck` | labd asks for hands only when the Mac can't come back by itself (CONTEXT.md, Needs hands) | open |
| `Terminates` | labd finishes the job before the model's clock runs out | |

Each model in `labboot/models/` says on its `\* expect:` line how TLC must end, and `check.sh` fails the build otherwise:

- **`current*.cfg`**: today's design, with and without an out-of-band hard reset (and with failing arms), under every fault it is meant to survive. They must pass. Their `\* witnesses:` line names outcomes TLC must show are reachable (a pass, a lost_contact, a needs_hands, a snapshot sync repaired by the re-arm...), so a change to the spec can't make the properties hold by cutting off the runs they are about.
- **`bug-*.cfg`**: a fixed bug, replayed by undoing its fix (a name in `Bugs`). TLC must find the property the fix protects violated. The same model with `Bugs = {}` must pass, which shows the fix, and not something else, is what makes it hold.
- **`open-*.cfg`**: what today's code still gets wrong, as far as the model knows. Each must fail. When one is fixed, its fix goes into the spec, the model is expected to pass, and it moves into `current*.cfg`'s faults or properties.

The open models today, each a counterexample TLC finds in today's design. Each was read against the code: the rearm, arm-after-write, snapshot, hands and short-timeout ones by reviewers trying to refute them, the rest raised by reviewers of the spec's fidelity and confirmed in the code. All are real; some are narrower than the model makes them. A ninth, a test kernel that panicked just after reaching labd passing on the Known-good kernel, was fixed in 6b6eae6 and is now `bug-6b6eae6-tests-on-any-boot`.

| Model | What happens | How likely |
|---|---|---|
| `open-rearm-fails-after-ack` | The re-arm before the reboot fails (lock held by a snapshot sync), so the Mac never reboots; the ladder soft-reboots it and classify says `hung`. | Needs a lock held past a minute in a few seconds' window. |
| `open-cancel-fails` | A re-arm fails on the lock, the cancel behind it fails on the same lock and is only logged: labd hears the arm failed with the one-shot still set. | Rare: two lock timeouts in a row. |
| `open-arm-fails-after-write` | The first arm, in `exec`, does not cancel when it fails after writing the one-shot, as the re-arm does. | Narrow on U-Boot Macs: only a failure after the variable file is renamed in place. |
| `open-snapper-at-shutdown` | A snapshot sync during shutdown, after the last re-arm, drops the block; labd says `boot_failed`. | snapper-cleanup's `ExecStopPost` runs limine-snapper-sync when shutdown stops it. |
| `open-hands-before-watchdog` | A tier 1 Mac's Lab boot loses its network in a test: labd asks for hands about 6 minutes after it last heard from it, before the agent's watchdog (11 minutes) would bring it back. | Any network loss mid-test on the fork's M1. |
| `open-back-in-pool-on-test-kernel` | ... and if the network comes back, the check-in returns the Mac to the pool on its test kernel, restore skipped, until the next job's pre-job restore. | Follows the one above. |
| `open-net-loss-blamed` | A network loss mid-test is classified `hung` or `crashed_or_hung`, against the kernel. | Known: malik-na/maclab#44, part 1. |
| `open-short-boot-timeout` | With a 3-minute boot timeout, labd stops waiting before the no-contact reboot and the Known-good boot after it are back, and on a tier 1 Mac says `hung`. | Only for short per-job boot timeouts; nothing rejects them. |

To read a counterexample, run TLC on the model by hand. It prints the run state by state, each headed by the action taken:

```sh
cd specs/labboot
java -cp ../.tools/tla2tools.jar tlc2.TLC -deadlock -config models/open-rearm-fails-after-ack.cfg LabBoot
```

### What the model leaves out

labd restarting mid-job, lab-agent crashing or restarting, a lost check-in response, a check-in from a dead boot arriving late, Volunteer Macs (Availability windows, Pause, Access level), the release gate, and the Known-good kernel drifting between labd, the agent and the default entry. Each is a candidate for its own spec, or for a fault here.

Some timing is finer than a minute, and the model has none of it:

- **watchdog.open_timeout against lab-agent's start.** lab-agent starts after `network-online.target`, and the kernel stops feeding apple_wdt at `max(boot timeout / 2, 120 s)`. On a Lab boot with no network, if wait-online takes long enough, apple_wdt resets the Mac before the no-contact deadline and leaves no reason: the 2f2e337 symptom again. It looks possible for boot timeouts of 4.5 minutes or less, labd's own fallback default being 4. It needs measured times to settle.
- A boot-partition lock can take a minute, so arms and cancels can outlast labd's 2-minute arm timeout without any lost report.
- A `reboot` command waits for its own result to be acked; the model reboots on delivery.
- NVRAM and U-Boot's variable file are one copy of the one-shot here, two on a real Mac.

The model's margins rest on `Skew <= 1` (how far a Lab boot's clock may run behind) and `BootLen = 2` (minutes from a reboot to lab-agent checking in). `NoContactBeforeWatchdog` fails at `Skew = 2`.

### Changing the spec

When the code changes how a Lab boot works, change the spec the same way, in the same PR. Keep the action's comment pointing at the code it models. If a fix closes an `open-*` model, flip its `expect:` to `pass` or fold it into `current*.cfg`. If you add a fault or a property, add a witness that shows the new behaviour is reachable.
