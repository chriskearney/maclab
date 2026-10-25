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
The kernel a Mac returns to after every lab boot, recorded on both labd and the Mac.

**Availability window**:
A time when a Volunteer's Mac may be used for lab jobs. Outside it, the Mac is the Volunteer's own.

## Releases

**Release**:
A kernel package together with what the Omarchy installer puts on a Mac, versioned as one unit.
_Avoid_: Build, version

**Omarchy setup**:
What the Omarchy installer puts on a Mac: the system a Release is installed into.

**Qualification**:
The fleet-wide verdict on one Release: qualified or not qualified, reached by running the Release as installed on every eligible Volunteer Mac.
_Avoid_: Certification, sign-off

**Promotion**:
Making an accepted installed run a Mac's new references and Known-good kernel.
