// SPDX-License-Identifier: GPL-2.0
/*
 * maclab_chaos: lab-only fault injection for lab-loop's nights. Never ship
 * this. Built in, so its parameters are maclab_chaos.<name>= on the kernel
 * command line:
 *
 *   mode=none|marker   no fault (marker just prints maclab_chaos.marker=)
 *   mode=oops_late     BUG() in a kworker delay_sec after boot; the system lives on
 *   mode=panic_late    panic() delay_sec after boot, mid-test
 *   mode=panic_early   panic() before userspace
 *   mode=hang_early    IRQs off and spin before SMP: only U-Boot's watchdog resets it
 *   mode=hang_late     userspace never starts, the kernel stays alive:
 *                      watchdog.open_timeout resets it
 *
 * See docs/research/agent-loop-week1.md.
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/panic.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#ifdef MODULE
/* A module can't hang before SMP, and has only one init function. */
#error "maclab_chaos must be built in (obj-y), not as a module"
#endif

static char *mode = "none";
module_param(mode, charp, 0444);
static char *marker = "";
module_param(marker, charp, 0444);
static int delay_sec = 90;
module_param(delay_sec, int, 0444);

static bool is(const char *m)
{
	return !strcmp(mode, m);
}

static void chaos_late(struct work_struct *w)
{
	if (is("oops_late"))
		BUG();
	if (is("panic_late"))
		panic("maclab-chaos: panic_late");
}
static DECLARE_DELAYED_WORK(chaos_work, chaos_late);

static int __init chaos_early(void)
{
	if (is("hang_early")) {
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
	if (is("hang_late"))
		for (;;)
			msleep(1000);
	if (is("oops_late") || is("panic_late"))
		schedule_delayed_work(&chaos_work, delay_sec * HZ);
	return 0;
}
late_initcall(chaos_init);
