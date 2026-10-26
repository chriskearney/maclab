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

**Lab-owned Mac**:
A Mac the Maintainers keep for the lab, with no Volunteer. A Mac is lab-owned or a Volunteer's for as long as it stays enrolled.

**Kind**:
Whether a Mac is a Volunteer's or Lab-owned, fixed by its enrollment for as long as it stays enrolled; changing it means enrolling the Mac again.
_Avoid_: Type, class

**GUI user**:
The user on a Mac whose Wayland session GUI tests run in; on a Volunteer's Mac it is the Volunteer's own account, logged in and locked on a Lab boot.

**On-screen check**:
A check of omarchy-m-test that needs the screen visible (the `video` section's test card). It runs on Lab-owned Macs and is left out on a Volunteer's Mac, which is locked while a test runs.

**Known-good kernel**:
The kernel a Mac returns to after every lab boot, recorded on both labd and the Mac. On a Volunteer's Mac, it is the kernel the Volunteer's own system boots by default.

**Lab boot**:
A boot of a Mac from an entry the lab put there (a test kernel or an installed Release), as opposed to a boot of the Mac's own default entry.

**No-contact deadline**:
The time by which a Lab boot must reach labd, about twice the job's boot timeout; a Lab boot that hasn't reached labd by then reboots to the Known-good kernel.
_Avoid_: Boot timeout (labd's own wait, a different thing)

**Hard ceiling**:
The time a Lab boot ends whatever happens, even in contact with labd: the job's end, or the Availability window's end if that comes first.
_Avoid_: Job timeout

**Needs hands**:
The state of a Mac that has to be power cycled by a person because it can't come back by itself. A Lab-owned Mac reaches it after the boot timeout and its recovery ladder; a Volunteer's Mac only after the Hard ceiling plus one boot timeout with no check-in, and its Volunteer is asked on the Mac's own topic.
_Avoid_: Stuck, bricked

**Lost boot**:
A Lab boot the Mac came back from without labd ending it (a panic, a watchdog reset, a deadline or a hard reset); its logs are collected afterwards.
_Avoid_: Crashed boot, failed boot

**Availability window**:
A time when a Volunteer's Mac may be used for lab jobs, set only by its Volunteer: a weekly schedule in the Mac's local time, plus a Pause or an "open now until" they add by hand. Outside it, the Mac is the Volunteer's own and nothing from the lab runs on it.
_Avoid_: Slot, schedule (for the window itself)

**Attended window**:
A time the Volunteer opens by hand to say they are at their Mac, so Lab boots that need someone to type the disk password may run in it.
_Avoid_: Supervised window

**Pause**:
A Volunteer closing their Mac's Availability window early: by default only the current window, or until a date they choose. Work in progress stops as it would at the window's end.

**Incomplete**:
How a job ends when its Availability window's end or a Pause cuts it short: lab-agent stops it and puts the Mac back on its own system by itself. It is not a failure, and labd tries it again as a new job in a later window.
_Avoid_: Interrupted, aborted (aborted by the Volunteer is a different ending)

**Open now**:
A Volunteer opening their Mac's Availability window by hand, from now until a time they choose, whatever its weekly schedule or a Pause says. It merges with a scheduled window it runs into.

**Access level**:
What Maintainers may do on a Volunteer's Mac, chosen by its Volunteer: Qualification (only what Qualification needs: no exec and no Maintainer's script) or Full (everything a lab-owned Mac allows). Lowering it stops at once whatever it no longer allows.
_Avoid_: Permissions, trust level

**Audit log**:
The record, per Volunteer Mac, of every Maintainer action on it (who, what, when, which job), kept on the Mac itself and written before each action, which its Volunteer can read. labd keeps a copy.

**Leaving**:
A Mac ending its enrollment, from either side: its Volunteer runs `leave`, or a Maintainer ends the enrollment in labd. Any job stops incomplete, the Mac returns to its Known-good kernel, and the lab's boot entries, units, autologin drop-in and device secret are removed. The Audit log stays with the Volunteer.
_Avoid_: Unenrolling, removing (for the Mac side)

## Releases

**Release**:
A kernel package together with what the Omarchy installer puts on a Mac, versioned as one unit.
_Avoid_: Build, version

**Omarchy setup**:
What the Omarchy installer puts on a Mac: the system a Release is installed into.

**Qualification**:
The fleet-wide verdict on one Release: qualified or not qualified, reached by running the Release as installed on the Macs a Maintainer picks for it, and recorded by a named Maintainer. A qualified verdict can later be revoked; a fix is always a new Release.
_Avoid_: Certification, sign-off

**Installed run**:
A run of a Release as the Omarchy installer installs it on a Mac. On a Volunteer's Mac it fits inside one Availability window and ends in a Rollback; it can end incomplete (the window closed first) or aborted by the Volunteer, neither of which is a failure.

**Eligible**:
A Mac is eligible for Installed runs when its own system (`@`) can be snapshotted, so that a Rollback can return it exactly as it was.

**Boot method**:
How a run's kernel was started: a cold boot through the Mac's firmware, or kexec from the running system. Every run records it.

**Rollback**:
Returning a Volunteer's Mac to its system exactly as it was just before an Installed run.
_Avoid_: Restore, revert

**Promotion**:
Making an accepted installed run a Mac's new references and Known-good kernel. Volunteer Macs are never promoted.
