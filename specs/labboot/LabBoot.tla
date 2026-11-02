------------------------------ MODULE LabBoot ------------------------------
(***************************************************************************)
(* One Lab boot of a Lab-owned Mac, from labd sending boot_once to labd    *)
(* putting the Mac back on its Known-good kernel (CONTEXT.md's terms).     *)
(*                                                                         *)
(* The actors are labd (internal/server/runner.go, recover.go, device.go), *)
(* lab-agent on the arming boot and on the Lab boot (internal/agent/       *)
(* agent.go, labboot.go, watchdog.go), the ESP and NVRAM as Limine and     *)
(* U-Boot read them (limine.go), and limine-snapper-sync, which rewrites   *)
(* limine.conf behind the lab's back.                                      *)
(*                                                                         *)
(* Time is whole minutes. An action that the code takes as soon as it can  *)
(* (a check-in, a report, a deadline firing) is urgent: the clock does not *)
(* move while one is enabled. Faults are not urgent: they may strike at    *)
(* any moment or never. Each fix the history records can be undone with a  *)
(* name in Bugs, so TLC replays the bug it fixed.                          *)
(*                                                                         *)
(* Left out, for later specs or finer time: labd restarting mid-job,       *)
(* lab-agent crashing, a lost check-in response, a check-in from a dead    *)
(* boot arriving late, Volunteer windows, the release gate, the Known-good *)
(* kernel diverging between labd and the Mac; and, below a minute, the     *)
(* kernel's watchdog.open_timeout against lab-agent starting after         *)
(* network-online.target, the minute a contended boot-partition lock can   *)
(* take, a reboot command waiting for its own report's ack, a test's       *)
(* budget starting after its script downloads, and NVRAM and U-Boot's      *)
(* variable file as two copies of the one-shot (here, one).                *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    BootTimeout,  \* labd's boot timeout for the job (--boot-timeout, 6 by default)
    BootLen,      \* the most a boot takes from the reboot to lab-agent checking in
    TestLen,      \* how long the one test takes on a good kernel: its timeout
    MaxTime,      \* the clock stops here; labd must be done well before
    Skew,         \* how far a Lab boot's clock may run behind (no network to set it)
    OOB,          \* whether the Mac has an out-of-band hard reset (tier 1 Macs don't)
    Faults,       \* the faults that may strike, a subset of FaultNames
    Bugs          \* the fixes undone, a subset of BugNames

FaultNames == {
    "SnapperSync",        \* limine-snapper-sync drops the maclab block from limine.conf
    "SnapperAtShutdown",  \* ... also between the last re-arm and the firmware reading it
    "ArmFails",           \* an arm fails before it writes the one-shot (lock timeout)
    "ArmFailsAfterWrite", \* an arm fails after it wrote the one-shot (persist, readback)
    "CancelFails",        \* cancelling the one-shot fails too (the same lock)
    "ReportLost",         \* the agent's report doesn't reach labd (labd down, network)
    "NetDown",            \* the Lab boot comes up with no network (driver refused)
    "NetDropInTest",      \* the Lab boot loses its network during the test
    "NetBack",            \* ... and gets it back later
    "DeadKernel",         \* the test kernel never reaches userspace
    "CrashInTest",        \* the test kernel panics during the test
    "CrashBeforeTest",    \* the test kernel panics after reaching labd, before the test
    "Cancel"}             \* a Maintainer cancels the job while labd waits on the Mac

BugNames == {
    "NoRearm",            \* 18b9311: no re-arm before the report or the reboot
    "RearmEveryRetry",    \* b804c41: the pre-report re-arm writes NVRAM on every retry
    "RearmNoCancel",      \* b804c41: a failed re-arm leaves the one-shot set
    "NoContactUncapped",  \* 2f2e337: no-contact deadline is 2x the boot timeout, uncapped
    "WdIdleFromAnyEvent", \* 953652a: a test ending feeds the watchdog from now
    "RestoreNoWait"}      \* 1995466: restore decides on the boot it sees at once

ASSUME /\ BootTimeout \in Nat \ {0}
       /\ BootLen \in Nat \ {0}
       /\ TestLen \in Nat \ {0}
       /\ MaxTime \in Nat
       /\ Skew \in Nat
       /\ OOB \in BOOLEAN
       /\ Faults \subseteq FaultNames
       /\ Bugs \subseteq BugNames

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

(* Times from the code, in minutes. *)
WatchdogIdle    == 10  \* watchdog.go watchdogIdle
WatchdogHW      == 1   \* watchdog.go watchdogTimeout
NoContactMargin == 1   \* labboot.go noContactMargin
ArmTimeout      == 2   \* runner.go armTimeout
QuietGrace      == 3   \* labd --quiet-grace
AliveWindow     == 1   \* labd --alive-window
TestGrace       == 2   \* labd waits this long past a test's timeout
CleanupTimeout  == 2   \* runner.go restore's cleanup call
Budget          == TestLen + 1                 \* watchdog.go testBudget: timeout + 20 s
SelfRecovery    == 2 * BootTimeout             \* runner.go selfRecovery, Lab-owned Mac
JobLen          == 3 * BootTimeout + 5 + TestLen + TestGrace  \* runner.go labBootJob
RestoreBudget   == 3 * BootTimeout + 5         \* runner.go runJob: restore's context
NoContactWait   ==                             \* labboot.go newLabBootDeadlines
    IF "NoContactUncapped" \in Bugs THEN 2 * BootTimeout
    ELSE Min(2 * BootTimeout, WatchdogIdle - NoContactMargin)

Deadlines    == {"no_contact", "ceiling"}
KernelBlame  == {"boot_failed", "hung", "crashed_or_hung", "tests_failed"}
RestoreRets  == {"restore", "restore_reboot"}
RestorePhases == {"restore_wait", "restore_check", "restore_reboot", "cleanup"}
NoCmd        == [kind |-> "none", target |-> 0]

VARIABLES
    now,
    \* labd: the job's phase and what it knows of the Mac
    lphase,      \* where execute/restore is
    outcome,     \* the job's outcome, "none" until decided
    wdl,         \* the deadline of what labd waits for now
    rdl,         \* when restore's context runs out
    waitFrom,    \* the boot labd waits to see the Mac leave, or calls on
    ladderStep,  \* the recovery ladder's rung: "soft", "oob", "oob2"
    ladderRet,   \* which wait the ladder serves
    ladderUsed,  \* the ladder ran for this wait: a "detected:" step
    devState,    \* "pool", or out of it: "needs_hands", "new"
    cmd,         \* the command labd has queued for the Mac
    cmdLost,     \* labd failed that command with errDeviceLost
    labdBoot,    \* the BootID of the last check-in
    labdTag,     \* that boot's kernel: "Test" if its JobTag is the job
    labdSeenAt,  \* when labd last heard a check-in
    armVerdict,  \* "none", "ok", "agent_failed", "timeout", "lost"
    restoreErr,  \* restore failed
    \* the Mac
    boot,        \* boot counter; 0 is the boot labd arms
    kernel,      \* "KG" (the default entry) or "Test"
    mac,         \* "running" or "shutdown" (between a reboot and the firmware)
    graceful,    \* the shutdown is a reboot, not a reset
    userspace,   \* sysinit reached: the early unit and lab-agent run
    bootAt,      \* when this boot started
    skew,        \* how far this boot's clock runs behind
    net,         \* this boot can reach labd
    \* the ESP and NVRAM
    block,       \* limine.conf has the maclab block with the job's entry
    oneShot,     \* LoaderEntryOneShot names the job's entry (NVRAM and U-Boot's file)
    staged,      \* the job's UKI is staged
    nvWrites,    \* one-shot writes to NVRAM and U-Boot's file for this Lab boot
    \* lab-agent's Lab boot files (labboot.go)
    hasDl,       \* deadlines.json exists
    dlNC,        \* its no-contact deadline
    dlCeil,      \* its ceiling
    seen,        \* boot.json's deadline: "none" (no file), "" or a deadline
    contact,     \* the contact file names this boot
    \* lab-agent on the arming boot (agent.go)
    ares,        \* boot_once's result waiting to be reported: "none", "ok", "failed"
    checked,     \* the pre-report re-arm has run (afterAck.checked)
    after,       \* the result carries the re-arm-and-reboot afterAck
    runAfter,    \* labd acked it: run the afterAck
    lastTry,     \* when the last report failed
    \* lab-agent on the Lab boot (watchdog.go)
    wdHeld, wdUntil, heard, testing, testStart, testDone,
    \* history, for the properties
    deadKernel,     \* the test kernel is broken: it never reaches userspace
    testBooted,     \* the firmware has booted the test kernel
    netDropped,     \* the Lab boot lost its network during the test
    kernelCrashed,  \* the test kernel panicked after reaching labd
    ranOnKG,        \* a test labd sent ran on the Known-good kernel
    wdBeatDeadline, \* the agent's watchdog reset a Lab boot that never reached labd
    blockDropped    \* a snapshot sync dropped the block after the arm, before the boot

labdVars  == <<lphase, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet, ladderUsed,
               devState, cmd, cmdLost, labdBoot, labdTag, labdSeenAt, armVerdict,
               restoreErr>>
macVars   == <<boot, kernel, mac, graceful, userspace, bootAt, skew, net>>
espVars   == <<block, oneShot, staged, nvWrites>>
recVars   == <<hasDl, dlNC, dlCeil, seen, contact>>
agentVars == <<ares, checked, after, runAfter, lastTry>>
wdVars    == <<wdHeld, wdUntil, heard, testing, testStart, testDone>>
histVars  == <<deadKernel, testBooted, netDropped, kernelCrashed, ranOnKG,
               wdBeatDeadline, blockDropped>>
vars == <<now, labdVars, macVars, espVars, recVars, agentVars, wdVars, histVars>>

-----------------------------------------------------------------------------
(* Helpers *)

\* lab-agent is up and can reach labd.
Reach == mac = "running" /\ userspace /\ net

\* labd heard from the Mac within its alive window (device.go aliveLocked).
Alive == now - labdSeenAt <= AliveWindow

\* The early unit's 1 s loop finds a deadline passed (labboot.go
\* enforceLabBootDeadlines). It reads this boot's clock, which may run behind.
EarlyDue ==
    /\ kernel = "Test" /\ mac = "running" /\ userspace /\ hasDl
    /\ \/ now >= dlCeil + skew
       \/ ~contact /\ now >= dlNC + skew

ArmResults ==
    {"ok"} \cup (IF "ArmFails" \in Faults THEN {"fail"} ELSE {})
           \cup (IF "ArmFailsAfterWrite" \in Faults THEN {"failAfterWrite"} ELSE {})
CancelResults == {"ok"} \cup (IF "CancelFails" \in Faults THEN {"fail"} ELSE {})

\* limineLayout.arm with result r: the block, then the one-shot unless it is
\* already set (the shortcut b804c41 added, after which arm can't fail), then
\* the readbacks.
ArmState(r) ==
    LET shortcut == oneShot /\ "RearmEveryRetry" \notin Bugs
    IN  IF ~staged \/ r = "fail"
          THEN [ok |-> FALSE, os |-> oneShot, bl |-> block, nv |-> nvWrites]
        ELSE IF r = "ok" \/ shortcut
          THEN [ok |-> TRUE, os |-> TRUE, bl |-> TRUE,
                nv |-> IF shortcut THEN nvWrites ELSE nvWrites + 1]
        ELSE [ok |-> FALSE, os |-> TRUE, bl |-> TRUE, nv |-> nvWrites + 1]

\* labBootAfterAck's rearm: an arm that, failing, cancels the one-shot. The
\* cancel can fail as well, and is then only logged.
RearmState(r, c) ==
    LET a == ArmState(r)
    IN  IF a.ok \/ "RearmNoCancel" \in Bugs \/ c = "fail" THEN a
        ELSE [a EXCEPT !.os = FALSE]

-----------------------------------------------------------------------------
(* labd's steps that end one wait and start the next *)

\* runJob goes on to restore, under a context of its own: first, if the Mac
\* may still be rebooting into the Lab boot this job armed, wait for that
\* boot (runner.go restore). Assigns outcome, lphase, wdl, rdl, waitFrom.
EnterRestore(o) ==
    LET pending == "RestoreNoWait" \notin Bugs /\ (labdBoot = 0 \/ ~Alive)
    IN  /\ outcome' = o
        /\ rdl' = now + RestoreBudget
        /\ IF pending
             THEN /\ lphase' = "restore_wait"
                  /\ wdl' = now + BootTimeout + SelfRecovery
                  /\ waitFrom' = 0
             ELSE /\ lphase' = "restore_check"
                  /\ UNCHANGED <<wdl, waitFrom>>

\* Send the test (runner.go execute). callNote binds a command to the boot
\* labd knows when it sends it, not to the boot it judged.
\* Assigns cmd, cmdLost, lphase, wdl, waitFrom.
StartTests ==
    /\ cmd' = [kind |-> "run_test", target |-> labdBoot]
    /\ cmdLost' = FALSE
    /\ lphase' = "testing"
    /\ wdl' = now + TestLen + TestGrace
    /\ waitFrom' = labdBoot

\* The Mac is back after the arm (runner.go execute): on the test entry,
\* take the after-boot screenshot, then run the test; fell back, ask
\* collect_lost how the Lab boot ended.
\* Assigns cmd, cmdLost, lphase, wdl, rdl, waitFrom, outcome, ladderUsed.
JudgeBoot ==
    IF labdTag = "Test"
      THEN /\ cmd' = [kind |-> "capture", target |-> labdBoot]
           /\ cmdLost' = FALSE
           /\ lphase' = "capture"
           /\ waitFrom' = labdBoot
           /\ ladderUsed' = FALSE
           /\ UNCHANGED <<wdl, rdl, outcome>>
      ELSE /\ EnterRestore(IF seen \in Deadlines THEN "lost_contact"
                           ELSE IF ladderUsed THEN "hung"
                           ELSE "boot_failed")
           /\ UNCHANGED <<cmd, cmdLost, ladderUsed>>

\* The Mac is back after it went away during the test (lostDuringTest).
\* Assigns the same as JudgeBoot.
JudgeTest ==
    /\ EnterRestore(IF seen \in Deadlines THEN "lost_contact"
                    ELSE IF ladderUsed THEN "hung"
                    ELSE "crashed_or_hung")
    /\ UNCHANGED <<cmd, cmdLost, ladderUsed>>

\* The ladder's last rung (recover.go ladder): a person must power cycle it.
\* execute's classify then finds the "detected:" step: hung. Inside restore,
\* restore fails, and a pass with it.
\* Assigns devState, lphase, outcome, restoreErr.
NeedsHands(ret) ==
    /\ devState' = "needs_hands"
    /\ lphase' = "done"
    /\ outcome' = IF ret \in {"boot", "test"} THEN "hung"
                  ELSE IF outcome = "pass" THEN "infra_error" ELSE outcome
    /\ restoreErr' = (restoreErr \/ ret \in RestoreRets)

HardReset == mac' = "shutdown" /\ graceful' = FALSE

\* waitBack timed out: walk the recovery ladder. Soft reboot only a Mac still
\* checking in on the boot labd waited on; else hard reset; else a person.
\* Assigns ladderUsed, ladderRet, cmd, cmdLost, ladderStep, lphase, wdl, mac,
\* graceful, devState, outcome, restoreErr.
StartLadder(ret) ==
    /\ ladderUsed' = TRUE
    /\ ladderRet' = ret
    /\ IF labdBoot = waitFrom /\ Alive
         THEN /\ cmd' = [kind |-> "reboot", target |-> labdBoot]
              /\ cmdLost' = FALSE
              /\ ladderStep' = "soft"
              /\ lphase' = "ladder"
              /\ wdl' = now + BootTimeout
              /\ UNCHANGED <<mac, graceful, devState, outcome, restoreErr>>
         ELSE IF OOB
         THEN /\ HardReset
              /\ ladderStep' = "oob"
              /\ lphase' = "ladder"
              /\ wdl' = now + BootTimeout
              /\ UNCHANGED <<cmd, cmdLost, devState, outcome, restoreErr>>
         ELSE /\ NeedsHands(ret)
              /\ UNCHANGED <<cmd, cmdLost, ladderStep, wdl, mac, graceful>>

-----------------------------------------------------------------------------
(* labd *)

LArmTimeout ==
    /\ lphase = "arming" /\ now >= wdl
    /\ armVerdict' = "timeout"
    /\ cmd' = NoCmd
    /\ EnterRestore("infra_error")
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmdLost, labdBoot,
                   labdTag, labdSeenAt, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* The Mac rebooted before boot_once's result reached labd: errDeviceLost.
LArmLost ==
    /\ lphase = "arming" /\ labdBoot /= 0
    /\ armVerdict' = "lost"
    /\ EnterRestore("infra_error")
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmd, cmdLost,
                   labdBoot, labdTag, labdSeenAt, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

LBackWaitback ==
    /\ lphase = "waitback" /\ labdBoot /= waitFrom
    /\ JudgeBoot
    /\ UNCHANGED <<ladderStep, ladderRet, devState, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* Every *Expire step: waitBack looks again whether the Mac is back before it
\* walks the ladder.
LWaitbackExpire ==
    /\ lphase = "waitback" /\ now >= wdl /\ labdBoot = waitFrom
    /\ StartLadder("boot")
    /\ UNCHANGED <<rdl, waitFrom, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<espVars, recVars, agentVars, wdVars, histVars>>

\* The after-boot screenshot ends without an answer: the Mac is on another
\* boot, or silent past quietGrace. execute logs it and runs the test anyway,
\* on whatever boot labd knows now.
LCaptureLost ==
    /\ lphase = "capture"
    /\ labdBoot /= waitFrom \/ now - labdSeenAt >= QuietGrace
    /\ StartTests
    /\ UNCHANGED <<outcome, rdl, ladderStep, ladderRet, ladderUsed, devState,
                   labdBoot, labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* run_test fails with errDeviceLost: the Mac is on another boot.
LTestLostReboot ==
    /\ lphase = "testing" /\ labdBoot /= waitFrom
    /\ JudgeTest
    /\ UNCHANGED <<ladderStep, ladderRet, devState, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* run_test fails: the Mac has been silent past quietGrace on the same boot.
LTestSilent ==
    /\ lphase = "testing" /\ now - labdSeenAt >= QuietGrace
    /\ lphase' = "lostwait"
    /\ wdl' = now + Max(BootTimeout - QuietGrace, 1)
    /\ UNCHANGED <<outcome, rdl, waitFrom, ladderStep, ladderRet, ladderUsed, devState,
                   cmd, cmdLost, labdBoot, labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* The test ran past its timeout and grace with the Mac still checking in
\* (callNote's clock runs only while the Mac is alive).
LTestTimeout ==
    /\ lphase = "testing" /\ now >= wdl /\ Alive
    /\ EnterRestore("tests_failed")
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmd, cmdLost,
                   labdBoot, labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

LBackLost ==
    /\ lphase = "lostwait" /\ labdBoot /= waitFrom
    /\ JudgeTest
    /\ UNCHANGED <<ladderStep, ladderRet, devState, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

LLostExpire ==
    /\ lphase = "lostwait" /\ now >= wdl /\ labdBoot = waitFrom
    /\ StartLadder("test")
    /\ UNCHANGED <<rdl, waitFrom, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<espVars, recVars, agentVars, wdVars, histVars>>

\* Back from restore's reboot: still on the lab entry means the one-shot did
\* not clear, and the Mac leaves the pool (State new); else clean up.
\* Assigns lphase, restoreErr, devState, cmd, cmdLost, wdl.
RebootedBack ==
    IF labdTag = "Test"
      THEN /\ lphase' = "done"
           /\ restoreErr' = TRUE
           /\ devState' = "new"
           /\ UNCHANGED <<cmd, cmdLost, wdl>>
      ELSE /\ cmd' = [kind |-> "cleanup", target |-> labdBoot]
           /\ cmdLost' = FALSE
           /\ lphase' = "cleanup"
           /\ wdl' = now + CleanupTimeout
           /\ UNCHANGED <<restoreErr, devState>>

LBackLadder ==
    /\ lphase = "ladder" /\ labdBoot /= waitFrom
    /\ CASE ladderRet = "boot" ->
              JudgeBoot /\ UNCHANGED <<restoreErr, devState>>
         [] ladderRet = "test" ->
              JudgeTest /\ UNCHANGED <<restoreErr, devState>>
         [] ladderRet = "restore" ->
              /\ lphase' = "restore_check"
              /\ UNCHANGED <<cmd, cmdLost, wdl, rdl, waitFrom, outcome, ladderUsed,
                             restoreErr, devState>>
         [] ladderRet = "restore_reboot" ->
              RebootedBack /\ UNCHANGED <<rdl, waitFrom, outcome, ladderUsed>>
    /\ UNCHANGED <<ladderStep, ladderRet, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* A rung's wait ran out: the next rung, two hard resets, then a person.
LLadderExpire ==
    /\ lphase = "ladder" /\ now >= wdl /\ labdBoot = waitFrom
    /\ IF OOB /\ ladderStep /= "oob2"
         THEN /\ HardReset
              /\ ladderStep' = IF ladderStep = "soft" THEN "oob" ELSE "oob2"
              /\ wdl' = now + BootTimeout
              /\ UNCHANGED <<lphase, devState, outcome, restoreErr>>
         ELSE /\ NeedsHands(ladderRet)
              /\ UNCHANGED <<mac, graceful, ladderStep, wdl>>
    /\ UNCHANGED <<rdl, waitFrom, ladderRet, ladderUsed, cmd, cmdLost, labdBoot, labdTag,
                   labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<espVars, recVars, agentVars, wdVars, histVars>>

LRestoreWaitBack ==
    /\ lphase = "restore_wait" /\ labdBoot /= waitFrom
    /\ lphase' = "restore_check"
    /\ UNCHANGED <<outcome, wdl, rdl, waitFrom, ladderStep, ladderRet, ladderUsed,
                   devState, cmd, cmdLost, labdBoot, labdTag, labdSeenAt, armVerdict,
                   restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

LRestoreWaitExpire ==
    /\ lphase = "restore_wait" /\ now >= wdl /\ labdBoot = waitFrom
    /\ StartLadder("restore")
    /\ UNCHANGED <<rdl, waitFrom, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<espVars, recVars, agentVars, wdVars, histVars>>

\* On a Lab boot, reboot to the Known-good kernel; then clean up.
LRestoreCheck ==
    /\ lphase = "restore_check"
    /\ IF labdTag = "Test"
         THEN /\ cmd' = [kind |-> "reboot", target |-> labdBoot]
              /\ lphase' = "restore_reboot"
              /\ wdl' = now + BootTimeout
              /\ waitFrom' = labdBoot
         ELSE /\ cmd' = [kind |-> "cleanup", target |-> labdBoot]
              /\ lphase' = "cleanup"
              /\ wdl' = now + CleanupTimeout
              /\ UNCHANGED waitFrom
    /\ cmdLost' = FALSE
    /\ UNCHANGED <<outcome, rdl, ladderStep, ladderRet, ladderUsed, devState, labdBoot,
                   labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

LRestoreRebootBack ==
    /\ lphase = "restore_reboot" /\ labdBoot /= waitFrom
    /\ RebootedBack
    /\ UNCHANGED <<outcome, rdl, waitFrom, ladderStep, ladderRet, ladderUsed, labdBoot,
                   labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* waitBack walks the ladder before it gives up, here as anywhere.
LRestoreRebootExpire ==
    /\ lphase = "restore_reboot" /\ now >= wdl /\ labdBoot = waitFrom
    /\ StartLadder("restore_reboot")
    /\ UNCHANGED <<rdl, waitFrom, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<espVars, recVars, agentVars, wdVars, histVars>>

\* cleanup's call fails: its timeout, or the Mac is on another boot.
LCleanupFail ==
    /\ lphase = "cleanup" /\ (now >= wdl \/ cmdLost)
    /\ lphase' = "done"
    /\ restoreErr' = TRUE
    /\ cmd' = NoCmd
    /\ UNCHANGED <<outcome, wdl, rdl, waitFrom, ladderStep, ladderRet, ladderUsed,
                   devState, cmdLost, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* restore's context runs out: what it was waiting for, a ladder rung
\* included, returns the context's error, and the job ends with the Mac where
\* it is, in the pool unless labd already took it out.
LRestoreBudget ==
    /\ \/ lphase \in RestorePhases
       \/ lphase = "ladder" /\ ladderRet \in RestoreRets
    /\ now >= rdl
    /\ lphase' = "done"
    /\ restoreErr' = TRUE
    /\ UNCHANGED <<outcome, wdl, rdl, waitFrom, ladderStep, ladderRet, ladderUsed,
                   devState, cmd, cmdLost, labdBoot, labdTag, labdSeenAt, armVerdict>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

Labd ==
    \/ LArmTimeout \/ LArmLost
    \/ LBackWaitback \/ LWaitbackExpire \/ LCaptureLost
    \/ LTestLostReboot \/ LTestSilent \/ LTestTimeout
    \/ LBackLost \/ LLostExpire
    \/ LBackLadder \/ LLadderExpire
    \/ LRestoreWaitBack \/ LRestoreWaitExpire \/ LRestoreCheck
    \/ LRestoreRebootBack \/ LRestoreRebootExpire \/ LCleanupFail \/ LRestoreBudget

-----------------------------------------------------------------------------
(* lab-agent *)

\* exec boot_once (agent.go): write the deadline record (armLabBoot), then
\* arm. A failed arm here returns its error as it is: no cancel.
DoBootOnce ==
    /\ cmd' = NoCmd
    /\ hasDl' = TRUE
    /\ dlNC' = now + NoContactWait
    /\ dlCeil' = now + JobLen
    /\ seen' = "none"
    /\ contact' = FALSE
    /\ \E r \in ArmResults :
         LET a == ArmState(r)
         IN  /\ oneShot' = a.os /\ block' = a.bl /\ nvWrites' = a.nv
             /\ ares' = IF a.ok THEN "ok" ELSE "failed"
             /\ after' = a.ok
    /\ checked' = FALSE /\ runAfter' = FALSE /\ lastTry' = -1
    /\ UNCHANGED <<staged, lphase, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet,
                   ladderUsed, devState, cmdLost, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr, macVars, wdVars, histVars>>

\* screen: the after-boot screenshot answers, and labd sends the test.
DoCapture ==
    /\ IF lphase = "capture"
         THEN StartTests
         ELSE /\ cmd' = NoCmd
              /\ UNCHANGED <<cmdLost, lphase, wdl, waitFrom>>
    /\ UNCHANGED <<outcome, rdl, ladderStep, ladderRet, ladderUsed, devState, labdBoot,
                   labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<macVars, espVars, recVars, agentVars, wdVars, histVars>>

\* run_test: a command labd sent starting is a sign of labd, and the test's
\* budget then holds the watchdog (watchdog.go test). lab-agent runs it on
\* whatever boot it is on.
DoRunTest ==
    /\ cmd' = NoCmd
    /\ testing' = TRUE /\ testStart' = now /\ testDone' = FALSE
    /\ heard' = now /\ wdUntil' = now + Budget
    /\ ranOnKG' = (ranOnKG \/ kernel = "KG")
    /\ UNCHANGED <<wdHeld, lphase, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet,
                   ladderUsed, devState, cmdLost, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr, macVars, espVars, recVars, agentVars>>
    /\ UNCHANGED <<deadKernel, testBooted, netDropped, kernelCrashed, wdBeatDeadline,
                   blockDropped>>

\* reboot: the plain rebootLater, with no re-arm.
DoReboot ==
    /\ cmd' = NoCmd
    /\ mac' = "shutdown" /\ graceful' = TRUE
    /\ UNCHANGED <<boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<lphase, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet,
                   ladderUsed, devState, cmdLost, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr, espVars, recVars, agentVars, wdVars, histVars>>

\* cleanup: disarm, remove the stage and the block (stage.go Cleanup).
DoCleanup ==
    /\ cmd' = NoCmd
    /\ oneShot' = FALSE /\ block' = FALSE /\ staged' = FALSE
    /\ IF lphase = "cleanup" THEN lphase' = "done" ELSE UNCHANGED lphase
    /\ UNCHANGED <<nvWrites, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet,
                   ladderUsed, devState, cmdLost, labdBoot, labdTag, labdSeenAt,
                   armVerdict, restoreErr, macVars, recVars, agentVars, wdVars, histVars>>

Deliver ==
    /\ cmd /= NoCmd /\ cmd.target = boot /\ Reach /\ ~EarlyDue
    /\ CASE cmd.kind = "boot_once" -> DoBootOnce
         [] cmd.kind = "capture"   -> DoCapture
         [] cmd.kind = "run_test"  -> DoRunTest
         [] cmd.kind = "reboot"    -> DoReboot
         [] cmd.kind = "cleanup"   -> DoCleanup
    /\ UNCHANGED now

\* A check-in reaches labd (device.go heartbeat). A new BootID fails the
\* command queued for the old boot, and a Mac labd had asked hands for goes
\* back to its idle state. On a Lab boot the reply is a sign of labd: it
\* writes the contact file and feeds the watchdog (agent.go poll). The early
\* unit fires within a second of sysinit, before the network.
CheckIn ==
    /\ Reach /\ ~EarlyDue
    /\ labdSeenAt < now \/ labdBoot /= boot
    /\ labdBoot' = boot /\ labdTag' = kernel /\ labdSeenAt' = now
    /\ IF labdBoot /= boot /\ cmd /= NoCmd /\ cmd.target /= boot
         THEN cmd' = NoCmd /\ cmdLost' = TRUE
         ELSE UNCHANGED <<cmd, cmdLost>>
    /\ devState' = IF devState = "needs_hands" THEN "pool" ELSE devState
    /\ IF kernel = "Test"
         THEN /\ contact' = TRUE
              /\ heard' = now
              /\ wdUntil' = IF testing THEN wdUntil ELSE now + WatchdogIdle
         ELSE UNCHANGED <<contact, heard, wdUntil>>
    /\ UNCHANGED <<lphase, outcome, wdl, rdl, waitFrom, ladderStep, ladderRet,
                   ladderUsed, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, hasDl, dlNC, dlCeil, seen, agentVars,
                   wdHeld, testing, testStart, testDone, histVars>>

\* report (agent.go): checkBeforeReport re-arms once per result, then the
\* POST. On a 200 the afterAck runs; on a failure the agent retries.
AgentReport ==
    /\ ares /= "none" /\ lastTry < now /\ mac = "running" /\ userspace
    /\ \E r \in ArmResults, c \in CancelResults,
          delivered \in (IF "ReportLost" \in Faults THEN BOOLEAN ELSE {TRUE}) :
         LET doCheck == after /\ "NoRearm" \notin Bugs
                        /\ (~checked \/ "RearmEveryRetry" \in Bugs)
             a == IF doCheck THEN RearmState(r, c)
                  ELSE [ok |-> TRUE, os |-> oneShot, bl |-> block, nv |-> nvWrites]
             okNow == ares = "ok" /\ a.ok
             after2 == after /\ a.ok
         IN  /\ oneShot' = a.os /\ block' = a.bl /\ nvWrites' = a.nv
             /\ checked' = (checked \/ (doCheck /\ a.ok))
             /\ IF delivered /\ net
                  THEN /\ ares' = "none" /\ after' = FALSE /\ runAfter' = after2
                       /\ UNCHANGED lastTry
                       /\ IF lphase = "arming"
                            THEN IF okNow
                                   THEN /\ armVerdict' = "ok"
                                        /\ lphase' = "waitback"
                                        /\ wdl' = now + BootTimeout + SelfRecovery
                                        /\ waitFrom' = 0
                                        /\ UNCHANGED <<outcome, rdl>>
                                   ELSE /\ armVerdict' = "agent_failed"
                                        /\ EnterRestore("infra_error")
                            ELSE UNCHANGED <<armVerdict, lphase, wdl, rdl, waitFrom,
                                             outcome>>
                  ELSE /\ ares' = IF okNow THEN "ok" ELSE "failed"
                       /\ after' = after2 /\ runAfter' = FALSE /\ lastTry' = now
                       /\ UNCHANGED <<armVerdict, lphase, wdl, rdl, waitFrom, outcome>>
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmd, cmdLost, labdBoot,
                   labdTag, labdSeenAt, restoreErr>>
    /\ UNCHANGED <<now, staged, macVars, recVars, wdVars, histVars>>

\* labBootAfterAck's run: re-arm, and reboot only if that worked.
AfterRun ==
    /\ runAfter /\ mac = "running" /\ userspace
    /\ runAfter' = FALSE
    /\ IF "NoRearm" \in Bugs
         THEN /\ mac' = "shutdown" /\ graceful' = TRUE
              /\ UNCHANGED <<oneShot, block, nvWrites>>
         ELSE \E r \in ArmResults, c \in CancelResults :
                LET a == RearmState(r, c)
                IN  /\ oneShot' = a.os /\ block' = a.bl /\ nvWrites' = a.nv
                    /\ IF a.ok THEN mac' = "shutdown" /\ graceful' = TRUE
                       ELSE UNCHANGED <<mac, graceful>>
    /\ UNCHANGED <<ares, checked, after, lastTry>>
    /\ UNCHANGED <<now, staged, boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<labdVars, recVars, wdVars, histVars>>

\* The test ends: what is left of the idle budget from the last sign of labd.
TestEnd ==
    /\ testing /\ mac = "running" /\ now >= testStart
    /\ testing' = FALSE /\ testDone' = TRUE
    /\ wdUntil' = IF "WdIdleFromAnyEvent" \in Bugs THEN now + WatchdogIdle
                  ELSE heard + WatchdogIdle
    /\ UNCHANGED <<wdHeld, heard, testStart>>
    /\ UNCHANGED <<now, labdVars, macVars, espVars, recVars, agentVars, histVars>>

AgentTestReport ==
    /\ testDone /\ Reach /\ ~EarlyDue
    /\ testDone' = FALSE
    /\ IF lphase = "testing" /\ labdBoot = boot
         THEN EnterRestore("pass")
         ELSE UNCHANGED <<outcome, lphase, wdl, rdl, waitFrom>>
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmd, cmdLost, labdBoot,
                   labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<wdHeld, wdUntil, heard, testing, testStart>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, histVars>>

-----------------------------------------------------------------------------
(* The Mac *)

\* Limine boots the one-shot's entry if limine.conf has it; otherwise the
\* default entry, the Known-good kernel. Either way it consumes the one-shot.
FirmwareBoot ==
    /\ mac = "shutdown"
    /\ LET toTest == oneShot /\ block
       IN  /\ kernel' = IF toTest THEN "Test" ELSE "KG"
           /\ testBooted' = (testBooted \/ toTest)
           /\ net' \in IF toTest /\ "NetDown" \in Faults THEN BOOLEAN ELSE {TRUE}
           /\ skew' \in IF toTest THEN 0..Skew ELSE {0}
    /\ oneShot' = FALSE
    /\ boot' = boot + 1
    /\ mac' = "running" /\ graceful' = TRUE /\ userspace' = FALSE /\ bootAt' = now
    /\ contact' = FALSE
    /\ wdHeld' = FALSE /\ testing' = FALSE /\ testDone' = FALSE
    /\ ares' = "none" /\ checked' = FALSE /\ after' = FALSE /\ runAfter' = FALSE
    /\ lastTry' = -1
    /\ UNCHANGED <<now, labdVars, block, staged, nvWrites, hasDl, dlNC, dlCeil, seen,
                   wdUntil, heard, testStart, deadKernel, netDropped, kernelCrashed,
                   ranOnKG, wdBeatDeadline, blockDropped>>

\* sysinit, within BootLen of the reboot. On a Lab boot the early unit writes
\* boot.json and lab-agent opens the watchdog (newLabWatchdog: idle from now).
Userspace ==
    /\ mac = "running" /\ ~userspace /\ ~(kernel = "Test" /\ deadKernel)
    /\ userspace' = TRUE
    /\ IF kernel = "Test"
         THEN /\ seen' = IF hasDl THEN "" ELSE seen
              /\ wdHeld' = TRUE /\ heard' = now /\ wdUntil' = now + WatchdogIdle
         ELSE UNCHANGED <<seen, wdHeld, heard, wdUntil>>
    /\ UNCHANGED <<testing, testStart, testDone>>
    /\ UNCHANGED <<now, boot, kernel, mac, graceful, bootAt, skew, net>>
    /\ UNCHANGED <<labdVars, espVars, hasDl, dlNC, dlCeil, contact, agentVars, histVars>>

\* The early unit passes a deadline: it records which in boot.json and reboots.
EarlyUnit ==
    /\ EarlyDue
    /\ seen' = IF now >= dlCeil + skew THEN "ceiling" ELSE "no_contact"
    /\ mac' = "shutdown" /\ graceful' = TRUE
    /\ UNCHANGED <<boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<now, labdVars, espVars, hasDl, dlNC, dlCeil, contact, agentVars,
                   wdVars, histVars>>

\* lab-agent stopped feeding at wdUntil; the hardware resets a minute later,
\* leaving no reason behind.
WatchdogReset ==
    /\ wdHeld /\ mac = "running" /\ now >= wdUntil + WatchdogHW
    /\ HardReset
    /\ wdBeatDeadline' = (wdBeatDeadline \/ ~contact)
    /\ UNCHANGED <<boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<now, labdVars, espVars, recVars, agentVars, wdVars,
                   deadKernel, testBooted, netDropped, kernelCrashed, ranOnKG,
                   blockDropped>>

\* A broken test kernel panics (panic=10) or hangs until apple_wdt resets it.
DeadReset ==
    /\ kernel = "Test" /\ deadKernel /\ mac = "running" /\ now >= bootAt + 1
    /\ HardReset
    /\ UNCHANGED <<boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<now, labdVars, espVars, recVars, agentVars, wdVars, histVars>>

-----------------------------------------------------------------------------
(* Faults *)

SnapperSync ==
    /\ "SnapperSync" \in Faults
    /\ block
    /\ \/ mac = "running"
       \/ "SnapperAtShutdown" \in Faults /\ mac = "shutdown" /\ graceful
    /\ block' = FALSE
    /\ blockDropped' = (blockDropped \/ (oneShot /\ ~testBooted))
    /\ UNCHANGED <<now, labdVars, macVars, oneShot, staged, nvWrites, recVars,
                   agentVars, wdVars, deadKernel, testBooted, netDropped, kernelCrashed,
                   ranOnKG, wdBeatDeadline>>

NetDropInTest ==
    /\ "NetDropInTest" \in Faults
    /\ kernel = "Test" /\ testing /\ net
    /\ net' = FALSE /\ netDropped' = TRUE
    /\ UNCHANGED <<boot, kernel, mac, graceful, userspace, bootAt, skew>>
    /\ UNCHANGED <<now, labdVars, espVars, recVars, agentVars, wdVars,
                   deadKernel, testBooted, kernelCrashed, ranOnKG, wdBeatDeadline,
                   blockDropped>>

NetBack ==
    /\ "NetBack" \in Faults
    /\ kernel = "Test" /\ mac = "running" /\ netDropped /\ ~net
    /\ net' = TRUE
    /\ UNCHANGED <<boot, kernel, mac, graceful, userspace, bootAt, skew>>
    /\ UNCHANGED <<now, labdVars, espVars, recVars, agentVars, wdVars, histVars>>

\* The test kernel panics once it has reached labd: during the test, or
\* before it; panic=10 reboots it in seconds.
KernelCrash ==
    /\ kernel = "Test" /\ mac = "running" /\ userspace /\ contact
    /\ \/ "CrashInTest" \in Faults /\ testing
       \/ "CrashBeforeTest" \in Faults /\ ~testing /\ ~testDone
          /\ lphase \in {"capture", "testing"}
    /\ HardReset
    /\ kernelCrashed' = TRUE
    /\ UNCHANGED <<boot, kernel, userspace, bootAt, skew, net>>
    /\ UNCHANGED <<now, labdVars, espVars, recVars, agentVars, wdVars,
                   deadKernel, testBooted, netDropped, ranOnKG, wdBeatDeadline,
                   blockDropped>>

\* A Maintainer cancels while execute waits on the Mac. waitBack returns the
\* canceled context: before the ladder, "canceled while booting"; during it,
\* the ladder stops and classify finds its "detected:" step. canceledAfter
\* keeps a kernel failure as the outcome (runner.go runJob).
Cancel ==
    /\ "Cancel" \in Faults
    /\ \/ lphase = "waitback"
       \/ lphase = "lostwait"
       \/ lphase = "ladder" /\ ladderRet \in {"boot", "test"}
    /\ EnterRestore(CASE lphase = "waitback" -> "canceled"
                      [] lphase = "lostwait" -> "crashed_or_hung"
                      [] OTHER -> "hung")
    /\ UNCHANGED <<ladderStep, ladderRet, ladderUsed, devState, cmd, cmdLost,
                   labdBoot, labdTag, labdSeenAt, armVerdict, restoreErr>>
    /\ UNCHANGED <<now, macVars, espVars, recVars, agentVars, wdVars, histVars>>

-----------------------------------------------------------------------------
(* Time *)

Urgent ==
    \/ Labd
    \/ Deliver \/ CheckIn \/ AgentReport \/ AfterRun \/ AgentTestReport
    \/ FirmwareBoot \/ EarlyUnit \/ WatchdogReset \/ DeadReset

\* Steps that may wait, but not past a deadline of their own.
Due ==
    \/ mac = "running" /\ ~userspace /\ ~(kernel = "Test" /\ deadKernel)
       /\ now >= bootAt + BootLen
    \/ testing /\ mac = "running" /\ now >= testStart + TestLen

Tick ==
    /\ now < MaxTime
    /\ ~Due
    /\ ~ENABLED Urgent
    /\ now' = now + 1
    /\ UNCHANGED <<labdVars, macVars, espVars, recVars, agentVars, wdVars, histVars>>

-----------------------------------------------------------------------------

Init ==
    /\ now = 0
    /\ lphase = "arming" /\ outcome = "none" /\ wdl = ArmTimeout /\ rdl = 0
    /\ waitFrom = 0
    /\ ladderStep = "none" /\ ladderRet = "none" /\ ladderUsed = FALSE
    /\ devState = "pool"
    /\ cmd = [kind |-> "boot_once", target |-> 0] /\ cmdLost = FALSE
    /\ labdBoot = 0 /\ labdTag = "KG" /\ labdSeenAt = 0
    /\ armVerdict = "none" /\ restoreErr = FALSE
    /\ boot = 0 /\ kernel = "KG" /\ mac = "running" /\ graceful = TRUE
    /\ userspace = TRUE /\ bootAt = 0 /\ skew = 0 /\ net = TRUE
    /\ block = TRUE /\ oneShot = FALSE /\ staged = TRUE /\ nvWrites = 0
    /\ hasDl = FALSE /\ dlNC = 0 /\ dlCeil = 0 /\ seen = "none" /\ contact = FALSE
    /\ ares = "none" /\ checked = FALSE /\ after = FALSE /\ runAfter = FALSE
    /\ lastTry = -1
    /\ wdHeld = FALSE /\ wdUntil = 0 /\ heard = 0
    /\ testing = FALSE /\ testStart = 0 /\ testDone = FALSE
    /\ deadKernel \in IF "DeadKernel" \in Faults THEN BOOLEAN ELSE {FALSE}
    /\ testBooted = FALSE /\ netDropped = FALSE /\ kernelCrashed = FALSE
    /\ ranOnKG = FALSE /\ wdBeatDeadline = FALSE /\ blockDropped = FALSE

Next ==
    \/ Urgent
    \/ Userspace \/ TestEnd
    \/ SnapperSync \/ NetDropInTest \/ NetBack \/ KernelCrash \/ Cancel
    \/ Tick

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ lphase \in {"arming", "waitback", "capture", "testing", "lostwait", "ladder",
                   "done"} \cup RestorePhases
    /\ outcome \in {"none", "pass", "infra_error", "canceled", "lost_contact"} \cup KernelBlame
    /\ ladderStep \in {"none", "soft", "oob", "oob2"}
    /\ ladderRet \in {"none", "boot", "test"} \cup RestoreRets
    /\ devState \in {"pool", "needs_hands", "new"}
    /\ cmd.kind \in {"none", "boot_once", "capture", "run_test", "reboot", "cleanup"}
    /\ armVerdict \in {"none", "ok", "agent_failed", "timeout", "lost"}
    /\ kernel \in {"KG", "Test"} /\ labdTag \in {"KG", "Test"}
    /\ mac \in {"running", "shutdown"}
    /\ seen \in {"none", ""} \cup Deadlines
    /\ ares \in {"none", "ok", "failed"}
    /\ {ladderUsed, cmdLost, restoreErr, graceful, userspace, net, block, oneShot,
        staged, hasDl, contact, checked, after, runAfter, wdHeld, testing, testDone,
        deadKernel, testBooted, netDropped, kernelCrashed, ranOnKG, wdBeatDeadline,
        blockDropped} \subseteq BOOLEAN

\* labd blames the test kernel only for what the test kernel did: a boot that
\* never came up, or a test boot that crashed or went off the network (which
\* labd can't tell from a crash). An infra fault (a dropped limine.conf
\* block, a failed re-arm, a deadline the agent's watchdog beat) must read as
\* infra_error or lost_contact (18b9311, 2f2e337).
BlameSound ==
    /\ outcome = "boot_failed" => testBooted /\ deadKernel
    /\ outcome \in KernelBlame \ {"boot_failed"} =>
         testBooted /\ (deadKernel \/ netDropped \/ kernelCrashed)
    /\ outcome = "lost_contact" => testBooted

\* A pass is the test kernel's: it booted, and the test ran on it.
PassSound ==
    outcome = "pass" => testBooted /\ ~deadKernel /\ ~ranOnKG

\* A Lab boot that only lost its network is not the kernel's failure. Open:
\* labd can't tell a network loss from a hang (malik-na/maclab#44, part 1).
NetLossNotBlamed ==
    (netDropped /\ ~kernelCrashed /\ ~deadKernel) => outcome \notin KernelBlame

\* Once labd is done with the job, the Mac runs its Known-good kernel, unless
\* labd took it out of the pool and said so (1995466).
LabBootOnlyDuringJob ==
    (kernel = "Test" /\ mac = "running") => (lphase /= "done" \/ devState /= "pool")

\* lab-agent never tells labd an arm failed while the one-shot is still set,
\* so no later plain reboot boots the test kernel unwatched (b804c41).
ArmFailedMeansDisarmed ==
    armVerdict = "agent_failed" => ~oneShot

\* The no-contact deadline, not the agent's watchdog, ends a Lab boot that
\* never reached labd, so labd hears why (2f2e337). It needs Skew below
\* NoContactMargin plus the time from the arm to lab-agent opening the
\* watchdog, which the model allows to be zero: Skew <= 1 here.
NoContactBeforeWatchdog == ~wdBeatDeadline

\* Outside a test, a Lab boot that has lost labd is reset watchdogIdle after
\* the last sign of labd and no later (953652a).
WatchdogIdleFromLabd ==
    (wdHeld /\ ~testing /\ ~net) => wdUntil <= heard + WatchdogIdle

\* NVRAM and U-Boot's file on the ESP see a handful of writes per Lab boot,
\* however long labd is out of reach (b804c41); today, one.
BoundedFirmwareWrites == nvWrites <= 3
OneFirmwareWrite == nvWrites <= 1

\* labd asks a person to power cycle the Mac only when it can't come back by
\* itself (CONTEXT.md, Needs hands). A running Lab boot always can: its
\* ceiling, and the agent's watchdog, reboot it to the Known-good kernel.
HandsOnlyWhenStuck ==
    devState = "needs_hands" => ~(kernel = "Test" /\ mac = "running")

\* labd finishes the job before the clock runs out.
Terminates == now = MaxTime => lphase = "done"

(* Witnesses: each is false in some state the model reaches, which check.sh
   requires of every witness a model names. They keep the properties above
   from holding only because a change to the spec cut off the behaviours
   they are about. *)
NoPass        == outcome /= "pass"
NoLostContact == outcome /= "lost_contact"
NoBootFailed  == outcome /= "boot_failed"
NoHung        == outcome /= "hung"
NoCrash       == outcome /= "crashed_or_hung"
NoCancel      == outcome /= "canceled"
NoInfra       == outcome /= "infra_error"
NoNeedsHands  == devState /= "needs_hands"
NoAgentFailed == armVerdict /= "agent_failed"
NoRepair      == ~(blockDropped /\ outcome = "pass")

=============================================================================
