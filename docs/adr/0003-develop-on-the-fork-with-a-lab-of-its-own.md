---
status: accepted
---

# Maclab is developed on Naeem's fork, against a lab of its own on a Linux controller

Maclab's home is `chriskearney/maclab`, and only Chris merges there. Chris and Naeem work in very different time zones, so a PR could wait a day for a merge, and work that needs the last PR merged and tested on a real Mac waited with it. To develop and test at the speed the lab needs, we decided that day-to-day development happens on `malik-na/maclab`. PRs there are reviewed and merged by Naeem once the fork's CI passes. The fork's `main` is upstream's `main` plus merged work: `upstream/main` is merged into it often, and finished work goes upstream in batches as PRs, as `integrate/malik-local-20261028` did. The fork tests against a lab of its own, separate from Chris's labd. Naeem's M3 Max (MacBook Pro 16-inch, Omarchy, aarch64 Linux) is the controller and runs labd and lab-builder. lab-builder builds with Docker, since Apple `container` needs macOS (malik-na/maclab#45, PR malik-na/maclab#49). Naeem's M1 is enrolled as a Lab-owned Mac.

## Considered options

- **Keep every PR on upstream.** Rejected: waiting a time zone for each merge is what this decision exists to stop.
- **Test the fork against Chris's labd.** Rejected for development: work on labd itself needs a labd we can redeploy at will, and an experiment that wedges a Mac shouldn't touch the lab Chris runs.
- **Boot the M3 Max into macOS as the controller.** Kept as a fallback, not the default. macOS gets the whole design (Apple `container`, and `macvdmtool` for oobd's hard reset and serial console), but the M3 Max is Naeem's daily Linux machine. When an experiment needs a hard reset, the M3 Max can boot macOS for it.
- **Enroll the M1 as a Volunteer's Mac.** Rejected: Availability windows, the locked desktop and skipped On-screen checks don't fit a development Mac. Kind is fixed at enrollment, so testing the volunteer flow means enrolling the M1 again.
- **A Linux box with a Central Scrutinizer for out-of-band control.** Later. It is the README's own plan for oobd without macOS, and it would give the M1 a hard reset.

## Consequences

- Upstream and the fork change the same files, so merges conflict. `lab-builder` did in #49 after Chris's named-builder and package-job work. Merge `upstream/main` into the fork before starting work on an area, not only before a batch goes upstream.
- Issues and PRs live on the fork, and the two repos number them separately: `malik-na/maclab#45` is not `chriskearney/maclab#45`. Always write `owner/repo#N`.
- The M1 has no out-of-band controller, so it is a tier 1 Mac: panic reboot, the hardware watchdog and the no-contact deadline, but no hard reset and no serial console. A Lab boot those can't bring back is Needs hands, and someone presses the power button. malik-na/maclab#44's tier-1 watchdog fix (PR malik-na/maclab#48) matters more here than on a lab with oobd.
- Until #49 is merged and has built a real kernel, `lab build` and `lab run --source` don't work on this lab. Kernels are built by hand and given as `lab run --kernel <file>`. Package builds under Docker are untried.
- The controller is a laptop. If it suspends, labd stops, and a Lab boot in progress loses its controller. On lab nights the M3 Max stays on AC power with the lid switch ignored.
- The M3 Max can't be a test Mac while it is the controller. Work on M3 hardware (the agent loop's later targets, see `docs/research/agent-loop-week1.md`) needs a second controller, or the M3 Max enrolled in a lab run elsewhere.
