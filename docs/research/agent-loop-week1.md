# Week 1 of an agent loop: 20 Lab boots overnight, nobody touches the Mac

Design sketch. Written 2026-11-01. Nothing here is built yet.

**Goal:** an agent drives maclab through 20 Lab boots overnight on one
Lab-owned Mac, including deliberately broken kernels, and no person touches the
Mac. That is the first step toward agents that bring up hardware by
experiment: guess, boot once, read the evidence, guess again. Week 1 doesn't try
to fix any driver. It proves the loop can run unattended and finds every place
where it can't.

**Done when:**

- 20 Lab boots finish in one night, at least 8 of them with a broken kernel.
- No boot ends with the Mac in Needs hands, and nobody power-cycles it.
- Every boot has a ledger entry, and the agent's reading of each one has been
  scored against what was actually injected.
- Every surprise (an outcome other than the one predicted, or a human step) is
  filed as an issue.

## The split: the harness acts, the agent reads

In week 1 the agent doesn't submit jobs. A small harness (`cmd/lab-loop`, Go,
using `internal/client`) owns everything that must not go wrong: which Mac,
which kernel, which cmdline, the order, the budget, when to stop, and the
ledger. After each job the harness asks the agent what happened, giving it the
job ID and read-only lab tools and nothing else. It doesn't tell the agent what
was injected.

This gives a judge with a known answer key for free. The harness knows it
booted `maclab_chaos.mode=hang_late`, the agent has to work that out from
`lab_job`, `lab_log` and `lab_serial`, and the harness scores the answer. A
judge that can't tell a hang from lost Wi-Fi on a known fault won't be able
to tell a bad driver patch from a good one later.

Week 3 hands the agent `lab_run`. Week 1 keeps it read-only, so a confused
agent can't cancel, exclude or `lab_exec` its way into a wedged Mac.

```
            ┌──────────── harness (cmd/lab-loop) ─────────────┐
 schedule ─▶│ pick mode ─▶ lab run ─▶ wait ─▶ ask agent ─▶ score ─▶ ledger
            │                                   │                     │
            │                     read-only MCP │                     │
            │       lab_job lab_log lab_serial lab_device             │
            └──────────── stop rules: needs_hands, infra ×2, budget ──┘
```

## One kernel, many faults: `maclab_chaos`

Rebuilding for every boot would make the night about the builder. Instead,
build one kernel once, from the Mac's known-good source plus one small
built-in file, and choose the fault on the command line. Built-in module
parameters take the file's name as a prefix, so the switch is
`maclab_chaos.mode=<mode>`.

```c
// drivers/misc/maclab_chaos.c: lab-only fault injection. Never ship this.
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/workqueue.h>

static char *mode = "none";
module_param(mode, charp, 0444);
static char *marker = "";
module_param(marker, charp, 0444);
static int delay_sec = 90;
module_param(delay_sec, int, 0444);

static bool is(const char *m) { return !strcmp(mode, m); }

static void chaos_late(struct work_struct *w)
{
	if (is("oops_late"))
		BUG();                       /* kills this kworker, the system lives on */
	if (is("panic_late"))
		panic("maclab-chaos: panic_late");
}
static DECLARE_DELAYED_WORK(chaos_work, chaos_late);

static int __init chaos_early(void)
{
	if (is("hang_early")) {              /* before SMP and apple_wdt: only U-Boot's watchdog can save it */
		local_irq_disable();
		for (;;)
			cpu_relax();
	}
	return 0;
}
early_initcall(chaos_early);

static int __init chaos_init(void)
{
	pr_info("maclab-chaos: mode=%s marker=%s\n", mode, marker);
	if (is("panic_early"))
		panic("maclab-chaos: panic_early");
	if (is("hang_late"))                 /* kernel alive, userspace never starts */
		for (;;)
			msleep(1000);
	if (is("oops_late") || is("panic_late"))
		schedule_delayed_work(&chaos_work, delay_sec * HZ);
	return 0;
}
late_initcall(chaos_init);
```

It needs one line in `drivers/misc/Makefile` (`obj-y += maclab_chaos.o`) on a
branch of the kernel fork that the lab builds with `lab build`. Whether the
Mac's kernel has `panic_on_oops` set decides whether `oops_late` stays an oops,
so check `/proc/sys/kernel/panic_on_oops` before the first night.

`netdown` needs no code: `modprobe.blacklist=brcmfmac` boots a healthy kernel
with no Wi-Fi.

## The night's schedule

20 boots in a fixed order, shuffled with a recorded seed. Each fault appears
twice. `marker` boots carry a fresh random string that a script test must find
in `dmesg`, which proves the result belongs to this boot and not a stale one.

| Mode | Boots | What breaks | Predicted outcome | What it proves |
| --- | --- | --- | --- | --- |
| `none` | 4 | nothing | `pass` | the loop itself is stable |
| `marker` | 4 | nothing | `pass`, marker found | evidence comes from this boot |
| `oops_late` | 2 | a kworker dies about 90 s after boot | `panicked` | oops capture while the system lives |
| `panic_late` | 2 | panic about 90 s after boot, mid-test | `panicked` or `crashed_or_hung` | `panic=10` and log collection after a Lost boot |
| `panic_early` | 2 | panic before userspace | `boot_failed` without a serial console | the one-shot is spent, so the Mac falls back |
| `hang_early` | 2 | IRQs off before SMP | `boot_failed` after U-Boot's 60 s watchdog | the watchdog left running by U-Boot ([apple-watchdog-before-kernel.md](apple-watchdog-before-kernel.md)) |
| `hang_late` | 2 | userspace never starts | `boot_failed` after `watchdog.open_timeout` | the open-timeout gap that research doc found |
| `netdown` | 2 | no Wi-Fi | `lost_contact` | the deadline unit reboots a boot that never reached labd |

The predictions are guesses from reading `labboot.go` and `types.go`. A wrong
prediction is a finding: either the lab misreads a fault or I misread the lab.
Both are worth an issue.

At about 5–8 minutes for a healthy boot plus tests, and a few minutes more for
each recovery, 20 boots should fit in 3–4 hours. That leaves room in a night for
the slow cases.

## The agent's job after each boot

The harness runs Claude Code headless against `lab mcp`, with only read-only
tools allowed:

```
claude -p "$(cat loop/judge-prompt.md) Job: $JOB" \
  --mcp-config loop/mcp.json \
  --allowedTools "mcp__maclab__lab_job,mcp__maclab__lab_log,mcp__maclab__lab_serial,mcp__maclab__lab_device" \
  --output-format json
```

The prompt asks for one JSON object and nothing else:

```json
{
  "fault": "none | marker | oops_late | panic_late | panic_early | hang_early | hang_late | netdown | unsure",
  "lab_outcome_agrees": true,
  "human_needed": false,
  "evidence": ["log file and line the call rests on", "..."],
  "surprise": "anything the lab reported that doesn't fit, or empty"
}
```

`human_needed` is the question that matters most. If the agent says no and the
Mac is in Needs hands, the judge is dangerous, and that must show in the score.

## The ledger

One JSON line per boot in `loop/ledger.jsonl`, written by the harness, never by
the agent:

```json
{
  "iter": 7, "seed": 41, "started": "2026-11-03T01:12:09Z", "seconds": 412,
  "device": "m1", "job": "j1103-011209-ab12", "build": "b…", "kernel_sha256": "…",
  "injected": {"mode": "hang_late", "cmdline": "maclab_chaos.mode=hang_late"},
  "outcome": "boot_failed", "predicted": "boot_failed", "recovery": ["watchdog"],
  "needs_hands": false, "human_minutes": 0,
  "agent": {"fault": "hang_late", "human_needed": false, "tool_calls": 6, "tokens": 18400},
  "agent_inputs": [{"tool": "lab_job", "taint": "lab-evidence"}, {"tool": "lab_log", "file": "boot0/kernel.txt", "taint": "lab-evidence"}],
  "score": {"fault": true, "human_needed": true}
}
```

`agent_inputs` is the seed of the taint ledger. In week 1 everything an agent
reads is lab evidence, which is clean. The day an agent reads a vendor binary,
that input is tagged `vendor`, and the code it writes afterwards can't go
upstream. Recording it from the first boot is cheap. Reconstructing it later
won't hold up.

`human_minutes` is filled in by hand the next morning. Any non-zero value is a
failed night, however good the rest looks.

## Stop rules

The harness stops the night, and sends a notification on the Mac's topic, when:

- the Mac reaches `needs_hands`, because the lab's own instructions say not to
  retry and to tell a person;
- two jobs in a row end `infra_error`, which means the lab is broken and the
  kernel didn't cause it;
- a `none` boot doesn't pass, because the baseline is gone and every later
  result is noise;
- the budget runs out: 30 boots or a token cap, whichever comes first.

## Before the first night

- **A Lab-owned Mac with an out-of-band controller.** Never a Volunteer's Mac
  in week 1. A serial console also makes `panic_early` readable.
- **Lease it** (`lab lease`) so nothing else lands on it, and freeze its
  packages for the week. A normal kernel upgrade strands the Mac today
  (malik-na/maclab#43).
- **Baseline it** (`lab baseline`), then run `lab crashtest` once by hand to see
  recovery work before trusting it overnight.
- **Expect `netdown` to find malik-na/maclab#44.** A script test that loses the
  network is read as `hung`, and on a tier-1 Mac a pending upload kept the
  watchdog fed until a person power-cycled it. If week 1 reproduces that, it's
  the first real fix the loop earns.

## What week 1 produces

A ledger, a score, and a list of issues. The numbers that matter for later
weeks:

| Number | Why |
| --- | --- |
| Human minutes per night | The whole point. It has to be zero. |
| Judge accuracy on `fault` and on `human_needed` | Whether an agent can read the lab's evidence well enough to be trusted with a real patch |
| Minutes per Lab boot, healthy and broken | How many experiments a night one Mac can run |
| Tokens per boot | What the judging costs before the agent writes any code |

Week 3 replaces the chaos module with real hypotheses: the agent gets
`lab_run`, the target is `display.backlight` on the M3 Max, and the judge is
`omarchy-m-test`'s own check.
