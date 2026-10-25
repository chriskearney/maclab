# maclab

A test lab that boots kernels once on real Apple Silicon Macs running Omarchy, tests them, and puts each Mac back on its known-good kernel.

## People

**Volunteer**:
A person other than a Maintainer who lends their own Omarchy Mac to the lab from wherever it lives. They are the human who answers when their Mac needs hands.
_Avoid_: Contributor, donor, tester

**Maintainer**:
A named person with their own access to labd who runs jobs and decides whether a Release is qualified.
_Avoid_: Admin, operator

## Machines

**Known-good kernel**:
The kernel a Mac returns to after every lab boot, recorded on both labd and the Mac. On a Volunteer's Mac, it is the kernel the Volunteer's own system boots by default.

**Lab boot**:
A boot of a Mac from an entry the lab put there (a test kernel or an installed Release), as opposed to a boot of the Mac's own default entry.

**Availability window**:
A time when a Volunteer's Mac may be used for lab jobs, set only by its Volunteer: a weekly schedule in the Mac's local time, plus a Pause or an "open now until" they add by hand. Outside it, the Mac is the Volunteer's own and nothing from the lab runs on it.
_Avoid_: Slot, schedule (for the window itself)

**Pause**:
A Volunteer closing their Mac's Availability window early: by default only the current window, or until a date they choose. Work in progress stops as it would at the window's end.

**Access level**:
What Maintainers may do on a Volunteer's Mac, chosen by its Volunteer: Qualification (only what Qualification needs) or Full (everything a lab-owned Mac allows).
_Avoid_: Permissions, trust level

**Audit log**:
The record, per Volunteer Mac, of every Maintainer action on it, which its Volunteer can read.

## Releases

**Release**:
A kernel package together with what the Omarchy installer puts on a Mac, versioned as one unit.
_Avoid_: Build, version

**Omarchy setup**:
What the Omarchy installer puts on a Mac: the system a Release is installed into.

**Qualification**:
The fleet-wide verdict on one Release: qualified or not qualified, reached by running the Release as installed on every eligible Volunteer Mac.
_Avoid_: Certification, sign-off

**Installed run**:
A run of a Release as the Omarchy installer installs it on a Mac. On a Volunteer's Mac it fits inside one Availability window and ends in a Rollback; it can end incomplete (the window closed first) or aborted by the Volunteer, neither of which is a failure.

**Rollback**:
Returning a Volunteer's Mac to its system exactly as it was just before an Installed run.
_Avoid_: Restore, revert

**Promotion**:
Making an accepted installed run a Mac's new references and Known-good kernel. Volunteer Macs are never promoted.
