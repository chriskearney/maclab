---
status: accepted
---

# The Lab boot is modelled in TLA+ and model-checked in CI

The Lab boot's bugs have been in how labd, lab-agent, the firmware and Omarchy's own tools interleave, not in any one function. limine-snapper-sync dropped the lab's block between the arm and the reboot (18b9311). A failed re-arm left the one-shot set while labd heard the arm had failed (b804c41). The agent's watchdog beat the No-contact deadline (2f2e337). A test ending fed the watchdog past the point labd had asked for hands (953652a). A canceled job left the Mac on its test kernel (1995466). Each was found on a real Mac, or by lab-loop, after it had shipped. Unit tests check the interleavings someone thought of, so we decided to state what a Lab boot must guarantee as a TLA+ specification (`specs/labboot/LabBoot.tla`) and have TLC check every interleaving of a small model. `make spec` runs it, and so does CI.

The spec's terms are CONTEXT.md's. Each fix in the list above can be undone in the model with a name in `Bugs`, and CI requires TLC to find the bug again, so the spec is shown to catch the bugs we have already had. What the model says today's code still gets wrong lives in `open-*` models that must fail until it is fixed.

## Considered options

- **More unit and integration tests.** We keep writing them, but each covers one interleaving. The bugs above were all in interleavings no test had.
- **lab-loop alone.** lab-loop finds bugs on real hardware, but a night of fault-injected boots explores a few hundred runs and takes a Mac. TLC explores every run of the model in seconds. They complement each other: lab-loop's labelled event logs are the natural input for checking a real run against the spec, a later step.
- **PlusCal.** PlusCal reads like code, but the Lab boot's timing (deadlines that must fire before the clock moves, faults that may strike at any moment) is easier to state directly in TLA+.
- **Apalache instead of TLC.** Apalache handles larger or unbounded models symbolically. The model is small enough for TLC, which needs only Java and one jar.

## Consequences

- A change to how a Lab boot works changes the spec in the same PR. CI fails if a `current` model breaks, if a replayed bug is no longer caught, or if an `open` model starts passing without being moved.
- The spec checks the design, not the Go. It can drift from the code without anyone noticing. Each action's comment names the code it models, and reviewers check the two together.
- The model is coarse: whole minutes, one job, one Lab-owned Mac, one test. Some results depend on that coarseness: `open-short-boot-timeout` turns on a margin of about a minute, and the margins rest on assumed clock skew and boot times (`specs/README.md`). Read each counterexample against the code before acting on it.
- The first model found nine things today's code gets wrong, two of them already known (malik-na/maclab#44's network loss, and 953652a's hands before the watchdog), each confirmed in the code. The worst, a test kernel that panicked just after reaching labd passing with its test run on the Known-good kernel, was fixed in 6b6eae6 and became a replayed bug. The rest are `open-*` models until fixed.
- labd restarts, agent crashes, Volunteer windows and the Known-good kernel's agreement between labd and the Mac are not modelled yet (`specs/README.md`).
- CI and `make spec` need Java and download tla2tools.jar 1.7.4, pinned by SHA-256.
