# Can the Apple watchdog be armed before the kernel loads?

Research for [malik-na/maclab#13](https://github.com/malik-na/maclab/issues/13). Researched 2026-10-26.

**Short answer: partly, and it already happens.** Asahi's U-Boot starts the
hardware watchdog with a 60 s timeout, keeps petting it while it (and EFI apps
such as Limine) run, and leaves it running when the OS calls
ExitBootServices. The Linux `apple_wdt` driver sees that the watchdog is
running when it probes, and the watchdog core then pets it **indefinitely**
until userspace opens `/dev/watchdog0`. So:

| Where the test kernel hangs | Reset today? |
| --- | --- |
| Between Limine's ExitBootServices and `apple_wdt` probe (early boot, early panic) | Yes, ~60 s after U-Boot last petted it (derived from source, not observed) |
| Kernel dead (hard lockup, panic with no reboot) after `apple_wdt` probe | Yes, within the 30 s the driver programs at probe (nobody pets it any more) |
| Kernel alive but userspace never opens the watchdog (stuck in initrd, waiting for root, systemd never starts) | **No.** The watchdog core pets it forever because `open_timeout` defaults to 0 |
| After systemd opens `/dev/watchdog0` (`RuntimeWatchdogSec=30s`) | Yes, already covered |

The remaining gap closes with a **kernel command-line change, not a rebuild**:
add `watchdog.open_timeout=<N>` (and `panic=10`) to the test boot entry that
maclab already writes into `limine.conf`.

Sources pinned to: m1n1 `51b747dced07a58eacf5dabc31ed6f00bcfa20fd`
(AsahiLinux/m1n1 main, 2026-10-24); U-Boot AsahiLinux/u-boot branch `asahi`
at `b33034a515a068381c4aa28831fb709e91300cd1` (2026-08-10); Linux
torvalds/linux master at `21a7f44fd0765fcc5194130b28767786eba1d1e7`;
AsahiLinux/PKGBUILDs at `39699ec74ed71b1a2bf60a67b066d5c2775442e8`;
AsahiLinux/docs at `3411b7e29a9db05079b82a9da3cacd5c17020334`.

## The boot chain and who touches the watchdog

```
iBoot ──(WDT armed, 120 s)──▶ m1n1 stage 1 ──(disables)──▶ m1n1 stage 2 ──(disables)──▶
U-Boot ──(arms 60 s, pets it)──▶ Limine (EFI app; U-Boot still pets) ──ExitBootServices (last pet)──▶
Linux: apple_wdt probe ──(sees it running, reprograms 30 s, core pets it until userspace opens)──▶
systemd (RuntimeWatchdogSec=30s)
```

## 1. m1n1 and U-Boot

### m1n1: always disables, has no option to arm

- `src/main.c` calls `wdt_disable()` unconditionally during init, before
  `run_actions()` loads the next stage
  ([main.c](https://github.com/AsahiLinux/m1n1/blob/51b747dced07a58eacf5dabc31ed6f00bcfa20fd/src/main.c)).
  This code runs in every m1n1 instance, so both stage 1 and stage 2 disable it.
- `src/wdt.c` `wdt_disable()` writes 0 to the control register (`+0x1c`) of
  `/arm-io/wdt`, and on `wdt-version` 2 or 3 SoCs also zeroes a secondary
  watchdog at `reg[2]`
  ([wdt.c](https://github.com/AsahiLinux/m1n1/blob/51b747dced07a58eacf5dabc31ed6f00bcfa20fd/src/wdt.c)).
  The only other function, `wdt_reboot()`, arms it with a tiny alarm to
  reboot immediately (used from `start.S` on fatal exceptions).
- No config, build option or `m1n1.conf` variable controls this. The parsed
  variables are `chosen.*`, `chainload=`, `display=`, `mitigations=`, `tso=`
  (`src/payload.c`, `IS_VAR(...)`), and `m1n1.conf.example` documents nothing
  watchdog-related. `chosen.*` only adds properties under `/chosen`, so it
  cannot add `timeout-sec` to the watchdog node.
- `src/hv/hv_wdt.c` is a software watchdog for m1n1's hypervisor mode only;
  it is not relevant to a normal boot.

So m1n1 cannot be made to leave the watchdog armed without patching and
rebuilding it, and it doesn't need to be: U-Boot arms it next.

### Asahi U-Boot: autostarts it at 60 s and never stops it

- `arch/arm/Kconfig`, `config ARCH_APPLE` does `select SYSRESET_WATCHDOG` and
  `select SYSRESET_WATCHDOG_AUTO` (U-Boot reboots Apple Macs through the
  watchdog). `drivers/sysreset/Kconfig`: `SYSRESET_WATCHDOG` does `select WDT`.
- `drivers/watchdog/Kconfig`: `WATCHDOG_AUTOSTART` is `default y` (the only
  exceptions are sunxi, STM32MP and Snapdragon), and `WATCHDOG_TIMEOUT_MSECS`
  is `default 60000`. `WDT_APPLE` is `default y if ARCH_APPLE`. `WDT` does
  `imply WATCHDOG`, which services the watchdog through U-Boot's cyclic
  framework.
- `configs/apple_m1_defconfig` sets none of these, so the defaults apply.
  Arch Linux ARM's Asahi package builds exactly that:
  `make apple_m1_defconfig` plus only the `OF_UPSTREAM` vendor options, then
  `make olddefconfig`
  ([PKGBUILDs/uboot-asahi/PKGBUILD](https://github.com/AsahiLinux/PKGBUILDs/blob/39699ec74ed71b1a2bf60a67b066d5c2775442e8/uboot-asahi/PKGBUILD),
  tag `asahi-v2026.07-2`).
- `drivers/watchdog/wdt-uclass.c`: `initr_watchdog()` (called from
  `common/board_r.c`) probes every `UCLASS_WDT` device and, if `autostart`,
  calls `wdt_start(dev, timeout*1000, 0)`. `wdt_pre_probe()` takes the
  timeout from the DT property `timeout-sec` (default
  `CONFIG_WATCHDOG_TIMEOUT_MSECS/1000` = 60) and honours the DT booleans
  `u-boot,noautostart` / `u-boot,autostart`.
- `drivers/watchdog/apple_wdt.c` `apple_wdt_start()`: resets the counter,
  writes `timeout_ms * clk_rate / 1000` to the bite register, sets
  `CTRL_RESET_EN`. It matches `apple,t8103-wdt` / `apple,wdt`, which the
  upstream DT watchdog node uses (`arch/arm64/boot/dts/apple/t8103.dtsi`,
  `wdt: watchdog@23d2b0000`, `clocks = <&clkref>`, no `timeout-sec`, no
  `u-boot,noautostart`).
- While an EFI app runs, U-Boot keeps petting it: `efi_timer_check()` ends
  with `schedule()` (`lib/efi_loader/efi_boottime.c`), and it runs whenever
  the app calls boot services such as `WaitForEvent`/`CheckEvent`.
- At **ExitBootServices**, U-Boot does `efi_set_watchdog(0)` (stops the
  *UEFI software* watchdog) then `schedule()` under the comment "Give the
  payload some time to boot", which is one last pet of the *hardware*
  watchdog. Nothing outside `drivers/watchdog/` calls `wdt_stop()` or
  `wdt_stop_all()`; the wdt uclass has no `pre_remove`, and `apple_wdt` has
  no `DM_FLAG_OS_PREPARE`, so `dm_remove_devices_active()` doesn't stop it.
  **The hardware watchdog is still running, about 60 s from expiry, when
  Limine jumps to the kernel.**
- Knobs: rebuild-time only (`CONFIG_WATCHDOG_TIMEOUT_MSECS`,
  `CONFIG_WATCHDOG_AUTOSTART`), or a `timeout-sec` / `u-boot,noautostart`
  property in the DT U-Boot uses (which comes from m1n1). There is no U-Boot
  environment variable for it. A `wdt` command exists only with `CMD_WDT`,
  which the Apple defconfig doesn't enable (unconfirmed whether the distro
  build turns it on).

**Unconfirmed on hardware:** I did not find an Asahi boot log showing
`WDT:   Started watchdog@23d2b0000 with servicing (60s timeout)`. The
behaviour above is read from source and build config. See "How to confirm"
below.

## 2. Linux `apple_wdt`: takes it over, then pets it forever by default

`drivers/watchdog/apple_wdt.c`
([source](https://github.com/torvalds/linux/blob/21a7f44fd0765fcc5194130b28767786eba1d1e7/drivers/watchdog/apple_wdt.c)),
`apple_wdt_probe()`:

```c
wdt->wdd.max_hw_heartbeat_ms = U32_MAX / wdt->clk_rate * 1000;
wdt->wdd.timeout = APPLE_WDT_TIMEOUT_DEFAULT;          /* 30 */

wdt_ctrl = readl_relaxed(wdt->regs + APPLE_WDT_WD1_CTRL);
if (wdt_ctrl & APPLE_WDT_CTRL_RESET_EN)
        set_bit(WDOG_HW_RUNNING, &wdt->wdd.status);

watchdog_init_timeout(&wdt->wdd, 0, dev);               /* DT timeout-sec, if any */
apple_wdt_set_timeout(&wdt->wdd, wdt->wdd.timeout);     /* reprograms bite to 30 s */
```

This detection has been there since the driver was added
([4ed224aeaf66](https://github.com/torvalds/linux/commit/4ed224aeaf661b63c2229df24a4d11a07e2653df),
Sven Peter, 2022). So when U-Boot left it running, the kernel marks it
`WDOG_HW_RUNNING` and resets the timeout to 30 s (max ~178 s at 24 MHz).

`drivers/watchdog/watchdog_dev.c`
([source](https://github.com/torvalds/linux/blob/21a7f44fd0765fcc5194130b28767786eba1d1e7/drivers/watchdog/watchdog_dev.c)):

- `watchdog.handle_boot_enabled` (bool, default `CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED`, Kconfig `default y`):
  if the hardware is running at registration, the core schedules an immediate
  ping and keeps pinging until userspace opens the device. With `=0` the
  kernel never pings it, so the machine resets one timeout (30 s) after
  probe unless userspace opens it first.
- `watchdog.open_timeout` (uint seconds, default `CONFIG_WATCHDOG_OPEN_TIMEOUT`,
  Kconfig `default 0` = infinite): the deadline, counted from registration,
  after which the core stops pinging a running watchdog that userspace has
  not opened. `watchdog_worker_should_ping()` returns
  `watchdog_hw_running(wdd) && !watchdog_past_open_deadline(wd_data)` for
  an unopened device. The first userspace open sets the deadline to infinity.
- Asahi kernels build the driver in and keep the defaults:
  `CONFIG_APPLE_WATCHDOG=y`, `CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y`,
  `CONFIG_WATCHDOG_OPEN_TIMEOUT=0`, `# CONFIG_WATCHDOG_NOWAYOUT is not set`
  ([PKGBUILDs/linux-asahi/config](https://github.com/AsahiLinux/PKGBUILDs/blob/39699ec74ed71b1a2bf60a67b066d5c2775442e8/linux-asahi/config)).
  The Asahi docs list `CONFIG_APPLE_WATCHDOG=y` and
  `CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y` as required options
  ([docs/sw/kernel-config.md](https://github.com/AsahiLinux/docs/blob/3411b7e29a9db05079b82a9da3cacd5c17020334/docs/sw/kernel-config.md)).

So with stock settings a kernel that is alive but never reaches userspace
gets **no** reset: the kernel pets the hardware watchdog itself.

Corollary for test kernels: one built **without** `apple_wdt` (or with it as
a module that never loads) would be reset about 60 s after ExitBootServices
even if it is healthy, because nobody takes over U-Boot's watchdog. This
follows from the source; not observed.

## 3. What closing the gap takes on an Omarchy Mac

**A kernel command-line change in the one-shot Limine entry. No rebuild.**

- Add `watchdog.open_timeout=N` to the test entry's cmdline (maclab already
  composes it; see README "--cmdline"). If systemd hasn't opened
  `/dev/watchdog0` within N s of `apple_wdt` registering, the core stops
  pinging and the hardware resets within the 30 s timeout after that. Worst
  case is about N + 30 s.
  - N must cover the time from probe until systemd opens the watchdog. If the
    initramfs runs its own systemd without `RuntimeWatchdogSec`, the device
    stays unopened until after switch-root, so N must cover the whole initrd
    phase (and any fsck or LUKS prompt). A value like 120 to 180 s is a
    reasonable start. Unconfirmed: whether Omarchy's initramfs systemd opens
    it; check with `journalctl -b -o short-monotonic | grep -i watchdog`.
  - `open_timeout` is mode 0644, so it can also be set later via
    `/sys/module/watchdog/parameters/open_timeout`, but that is too late for
    this gap. The cmdline is the useful place.
- Add `panic=10` to the cmdline. maclab's `kernel.panic=10` sysctl applies
  only once `systemd-sysctl` runs, so a panic before that just halts. The
  hardware watchdog would still catch it (≤60 s before probe, ≤30 s after),
  but `panic=` reboots sooner and more deterministically.
- Alternative: `watchdog.handle_boot_enabled=0` makes the kernel never pet
  it, so the reset comes 30 s after probe unless userspace opens it. That is
  too tight for a normal boot with an initrd; `open_timeout` is the better knob.
- Optional, not needed: a DT `timeout-sec` on the watchdog node would change
  both U-Boot's and Linux's timeout, but needs a modified DT, and m1n1's
  `chosen.*` can't do it. Changing U-Boot's 60 s means rebuilding U-Boot
  (`CONFIG_WATCHDOG_TIMEOUT_MSECS`). Making m1n1 leave iBoot's watchdog armed
  would mean patching m1n1. None of these is needed.
- maclab's `lab-agent setup` arming `RuntimeWatchdogSec=30s` only when
  `/dev/watchdog0` exists (`internal/agent/setup.go:98`) stays as it is. The
  cmdline change covers the window before systemd.
- Unconfirmed: whether Limine itself touches the UEFI watchdog. It doesn't
  matter, because the UEFI watchdog is U-Boot's software timer (`efi_watchdog.c`,
  300 s on image start, stopped at ExitBootServices), separate from the
  hardware one.

## 4. iBoot / firmware watchdog

- Asahi docs: "The initial macho (usually m1n1) is booted with the watchdog
  timer enabled, so if it does nothing to it, the system will automatically
  reboot after a while", with the compare value "initially set to 120
  seconds" (24 MHz counter at `0x23d2b0000+0x10`, compare `+0x14`, control
  `+0x1c`, bit 2 = reset enable; max timeout just under 3 min)
  ([docs/hw/soc/wdt.md](https://github.com/AsahiLinux/docs/blob/3411b7e29a9db05079b82a9da3cacd5c17020334/docs/hw/soc/wdt.md)).
- On newer SoCs (M4, A18 Pro, M4 Pro, M5 Max) iBoot from macOS 26.x also
  arms a **secondary** watchdog of about 120 s. m1n1 commits
  [0e88df7b](https://github.com/AsahiLinux/m1n1/commit/0e88df7bc989a71bda2b8acccc0bd6f5657c3ecb)
  ("Disarm secondary watchdog on t814x": "M4 and A18 Pro … reset with iboot
  from macOS 26.x after 120 seconds") and
  [ffe667db](https://github.com/AsahiLinux/m1n1/commit/ffe667db24b50b6fefd362d6fe84868617120237)
  (apply it to every `wdt-version` 2/3 SoC) added disarming it.
- m1n1 disables both, so iBoot's watchdog **does not** carry through to the
  kernel. Coverage before the kernel comes from U-Boot (section 1), not from
  firmware.
- Unconfirmed: whether Linux knows about the secondary watchdog. `apple_wdt`
  only drives the primary (`WD1_*`) registers, which is fine because m1n1
  has already disarmed the secondary.

## How to confirm on a lab Mac

1. U-Boot side: on the serial console or framebuffer during U-Boot, look for
   `WDT:   Started watchdog@... with servicing (60s timeout)`.
2. Kernel side: boot a test entry with `watchdog.handle_boot_enabled=0` and
   with the systemd runtime watchdog disabled. If the Mac resets about 30 s
   after `apple_wdt` probes, the hardware watchdog was running at probe,
   i.e. U-Boot left it armed.
3. Gap fix: boot a test entry with `watchdog.open_timeout=60 init=/bin/sh`,
   so the kernel stays alive but systemd never opens the watchdog. Expect a
   reset roughly 60 + 30 s after probe. Without `open_timeout` it should sit
   at the shell indefinitely.
