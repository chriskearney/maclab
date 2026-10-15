# Two installs per Mac (A/B): a proposal

Status: proposal. Only part of what it relies on is verified on hardware, with a single install
(below); the rest needs a Mac with a second install, which takes a person at the Mac once.

## Why

A lab job today boots a test kernel next to the known-good one, in the same install. Three kinds of
change can't be tested that way:

- **Device trees.** m1n1 on the ESP hands the kernel its device tree, so a kernel that needs new
  bindings boots with the old ones (see [Kernel artifacts](../README.md#kernel-artifacts)).
- **The boot chain itself:** m1n1 stage 2, U-Boot, Limine, and the initramfs hooks.
- **Whole package sets and installs:** an Omarchy update, a fresh install, first-boot setup.

## The idea

Each lab Mac gets two Linux installs, each in its own APFS stub container with its own ESP, m1n1 and
Limine, as the Asahi installer creates them ("an EFI System Partition for each instance you install").

- **A, the control install,** is the default boot volume. It runs lab-agent and is never changed by a
  job.
- **B, the test install,** is rewritten by every job: packages, boot chain, or a whole image.

A job prepares B from A, selects B for one boot with `asahi-bless --next --set-boot`, and reboots. B boots,
reports to labd and runs the tests. Any reset (panic, watchdog, power) lands on A, because the
selection is spent.

## Verified

- `asahi-bless --next --set-boot` writes the NVRAM variable `system:alt-boot-volume`. On an M1 MacBook
  Air it was set before a reboot and gone while Linux ran after it: iBoot clears the one-shot before
  it boots the volume, so any reset of B returns to A. Selecting a boot volume from Linux needs root,
  but no macOS credentials and no change to the boot policy.
- m1n1 stage 1 hands the kernel its own ESP's PARTUUID in the device tree
  (`asahi,efi-system-partition`); on the Air it matched the mounted ESP. `update-m1n1` (asahi-scripts)
  mounts the ESP with that PARTUUID to write m1n1 stage 2 and the device trees, so on B it should write
  B's ESP. Not yet tried with two installs. Kernel, initramfs and Limine updates are different: they
  write whatever is mounted at `/boot` and `/boot/efi` (see "Fixed UUIDs").
- U-Boot leaves `apple_wdt` running into Linux, and `watchdog.open_timeout` limits how long the
  kernel feeds it: on the Air, a test boot stuck waiting for its root device was reset and came back
  on its known-good kernel.

## Open problems

- **Installing B needs a person.** The Asahi installer's second step runs in macOS recovery (hold the
  power button, choose the volume, enter the password for `bputil` and `kmutil`). It can't be
  scripted. The Omarchy Mac installer refuses to install alongside an existing Omarchy install, so B
  (or A) comes from the upstream Asahi installer.
- **Fixed UUIDs.** Every Omarchy image uses the same filesystem UUIDs (root `4f4d5801-524f-...0001`,
  `/boot` `4f4d5801-424f-...0001`, ESP `4F4D-5801`). fstab mounts `/`, `/boot` and `/boot/efi` by
  them, and the command line has `root=UUID=`. Two Omarchy installs on one disk can mount each other's
  partitions, so a kernel, initramfs or Limine update on B could land on A. Either A is a minimal
  non-Omarchy install with random UUIDs, or each image written to B gets new UUIDs (and a matching
  fstab and command line) as it is written.
- **Picking B.** `asahi-bless --set-boot NAME` takes the first volume with that name; with two
  installs called Omarchy, pass B's index from `asahi-bless --list-volumes` instead, or write the
  variable with `asahi-nvram`.
- **Re-imaging B from A.** The Omarchy image (an ESP tree, `boot.img`, `root.img`) can be written onto
  B's existing partitions, keeping B's ESP PARTUUID, which B's stage 1 is bound to, and the vendor
  firmware on its ESP. Not yet tried.
- **Watchdog coverage.** B boots with `watchdog.open_timeout=N`, and something has to open
  `/dev/watchdog` on a healthy B within N seconds, or B is reset too. With `lab-agent setup`'s `RuntimeWatchdogSec=30s`, systemd does
  once B's root is up and then keeps it fed while it runs, so a B that is alive but stuck isn't reset.
  To catch that, lab-agent on B would hold the watchdog itself (B booting with
  `systemd.watchdog_sec=0`) and feed it only while each step is within its budget. m1n1 disables the
  watchdog and U-Boot feeds it while it or Limine waits, so a B stuck in m1n1, U-Boot or Limine (one
  of the things B is for) needs an out-of-band reset or a person.
- **Tailscale.** A and B are separate tailnet nodes; copying `/var/lib/tailscale` between them
  duplicates the node key.

## Testing plan

1. Install B on a lab Mac with the Asahi installer (once, at the Mac), and make A the default boot
   volume.
2. From A, `asahi-bless --next --set-boot <B's index> -y` and reboot: B boots once, and a reboot from
   B lands on A.
3. Panic B, then hang B before anything opens the watchdog: both land on A by themselves.
4. Re-image B from A with an Omarchy image, with new UUIDs; boot it once.
5. Wire it into lab-agent as a third boot backend next to GRUB and Limine.
