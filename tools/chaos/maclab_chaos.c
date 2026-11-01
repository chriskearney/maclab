// SPDX-License-Identifier: GPL-2.0
/*
 * maclab_chaos: lab-only fault injection for lab-loop's nights. Never ship
 * this. Built in, so its parameters are maclab_chaos.<name>= on the kernel
 * command line:
 *
 *   code=<hex>     which fault, as an opaque code from maclab_chaos_codes.h
 *   marker=<hex>   printed back, so a result can be tied to its boot
 *   delay_sec=N    how long after boot the late faults fire (default 90)
 *
 * The codes keep the fault's name off the cmdline and out of the kernel log,
 * so a judge reading the evidence can't read the answer. apply.sh draws a
 * fresh code per fault and writes the table lab-loop reads. The faults:
 *
 *   none, marker   no fault
 *   oops_late      BUG() in a kworker delay_sec after boot; the system lives on
 *   panic_late     panic() delay_sec after boot, mid-test
 *   panic_early    panic() before userspace
 *   hang_early     IRQs off and spin before SMP: only U-Boot's watchdog resets it
 *   hang_late      userspace never starts, the kernel stays alive:
 *                  watchdog.open_timeout resets it
 *   netdown        brcmfmac (the Wi-Fi driver) refuses to load
 *
 * See docs/research/agent-loop-week1.md.
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/panic.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "maclab_chaos_codes.h"

#ifdef MODULE
/* A module can't hang before SMP, and has only one init function. */
#error "maclab_chaos must be built in (obj-y), not as a module"
#endif

static char *code = "";
module_param(code, charp, 0444);
static char *marker = "";
module_param(marker, charp, 0444);
static int delay_sec = 90;
module_param(delay_sec, int, 0444);

static const struct {
	const char *code, *mode;
} codes[] = MACLAB_CHAOS_CODES;

/* is says whether the cmdline's code is the one for fault m. */
static bool is(const char *m)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(codes); i++)
		if (!strcmp(codes[i].mode, m))
			return code[0] && !strcmp(codes[i].code, code);
	return false;
}

static void chaos_late(struct work_struct *w)
{
	if (is("oops_late"))
		BUG();
	if (is("panic_late"))
		panic("maclab-chaos: fault");
}
static DECLARE_DELAYED_WORK(chaos_work, chaos_late);

/* netdown: fail brcmfmac's load the way a broken driver would, silently. */
static int chaos_module(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;

	if (action == MODULE_STATE_COMING && !strcmp(mod->name, "brcmfmac"))
		return notifier_from_errno(-EIO);
	return NOTIFY_DONE;
}
static struct notifier_block chaos_module_nb = { .notifier_call = chaos_module };

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
	pr_info("maclab-chaos: code=%s marker=%s\n", code, marker);
	if (is("panic_early"))
		panic("maclab-chaos: fault");
	if (is("hang_late"))
		for (;;)
			msleep(1000);
	if (is("oops_late") || is("panic_late"))
		schedule_delayed_work(&chaos_work, delay_sec * HZ);
	if (is("netdown"))
		register_module_notifier(&chaos_module_nb);
	return 0;
}
late_initcall(chaos_init);
