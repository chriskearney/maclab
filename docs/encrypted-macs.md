# Encrypted Macs

## Why preflight refuses them

Every lab job reboots the Mac, often several times, with no one at it. If the
root volume is LUKS-encrypted, each of those boots stops at the disk passphrase
prompt and waits, and the job fails as a boot that never came back. So
`lab-agent setup` and `lab-agent preflight` refuse a Mac whose root (or
`/boot`) would wait for a passphrase. An encrypted root is accepted only when a
key file the initramfs can read before `/` is unlocked unlocks it (see
[Setup](../README.md#setup)).

## What you can do today

1. **Reinstall without disk encryption.** In the Omarchy Mac installer, turn
   off "Encrypt the Omarchy disk". Use this for any Mac that holds anything of
   its own.

2. **Lab-only auto-unlock** (`scripts/lab-only-autounlock`), opt-in, for
   **Lab-owned Macs and fresh lab-only installs with nothing personal on
   them**. Never for a Volunteer's own Mac.

   The trade-off, plainly: **while it is enabled, anyone holding the Mac can
   read its disk.** The disk key sits inside the boot images on the
   unencrypted EFI partition, so the encryption no longer protects the Mac if
   it is lost or taken. What the encryption still gives you is a disk that is
   unreadable again once you run `disable`. The lab's Maintainers already have
   root on a lab Mac, so this changes nothing about what they can reach.

## lab-only-autounlock

```sh
sudo scripts/lab-only-autounlock status    # what is set up now; changes nothing
sudo scripts/lab-only-autounlock enable    # asks you to type "yes" (--yes answers for you)
sudo scripts/lab-only-autounlock disable
```

`enable` refuses unless the root is LUKS2, unlocked by one `rd.luks.name=` or
`rd.luks.uuid=` on the kernel command line, by a systemd initramfs
(`systemd` and `sd-encrypt` hooks, not `encrypt`), and the Mac boots Limine
UKIs. It then:

1. backs up the LUKS header to `/root/lab-only-autounlock-backups/` (copy it
   off the Mac and keep it private);
2. writes a random 64-byte key to `/etc/cryptsetup-keys.d/<volume>.key`
   (root only, mode 600) and adds it as a new key slot with pbkdf2 at 1000
   iterations (the key is random, so a slow KDF buys nothing and would slow
   every boot). cryptsetup asks for your existing passphrase on the terminal;
3. adds `FILES+=(<key>)` in `/etc/mkinitcpio.conf.d/99-lab-only-autounlock.conf`;
4. adds `rd.luks.key=<uuid>=<key>` to the kernel command line, after backing
   up the file it edits. On an Omarchy Mac that is `GRUB_CMDLINE_LINUX` in
   `/etc/default/grub`: `omarchy-mac-limine-cmdline` derives Limine's command
   line from it at every rebuild, so an edit to `/etc/default/limine` would
   never reach `limine.conf`. Elsewhere it is the last
   `KERNEL_CMDLINE[default]` line of `/etc/default/limine`;
5. rebuilds the boot images (`omarchy-mac-boot-update`, or `limine-update`;
   and `mkinitcpio -P` first when `/boot` holds initramfs images);
6. checks that every UKI holds the key file and the `rd.luks.key=` argument,
   that every `/boot/initramfs-*.img` holds the key file, and that the key
   opens the volume.

Reboot: there should be no passphrase prompt, and preflight should accept the
Mac. On the first hardware run (chriskearney/maclab#38) preflight accepted
both encrypted Macs with no change to maclab, and their Lab boots unlocked
unattended.

`status` reports each piece: the key slots, the key file and which slot it
opens (or that it is **dead**, opening none), the drop-in, the command-line
argument in the file and in the running boot, and each boot image. On an
Omarchy Mac with `/boot/omarchy/encrypt.state`, the owner's and recovery key
slots are never touched, and any other slot is listed.

## Leaving the lab

Take the lab off the Mac first, then turn auto-unlock off:

```sh
sudo lab-agent uninstall    # or, on a Volunteer's Mac, sudo lab-agent leave
sudo scripts/lab-only-autounlock disable
```

`disable` asks for your passphrase and checks it opens another key slot. It
refuses if the key's slot is the only one left. Then it removes that key slot
using the key file **first**, which makes every copy of the key useless:
in the boot images, in snapshots, in backups. Only then does it delete the key
file, the drop-in and the `rd.luks.key=` argument, rebuild the boot images and
check that none still holds the key.

## Things to know

- Restoring a Snapper snapshot taken while auto-unlock was enabled brings the
  drop-in and the key file back. Run `disable` again after such a restore (a
  key whose slot is gone is reported as dead).
- Snapshot boot entries and any UKI the check reports as missing the key still
  ask for the passphrase.
- On an Omarchy Mac, `omarchy-apple-silicon-boot-check` (full mode) reports
  the extra key slot as a failure while auto-unlock is enabled.
- If a boot goes wrong, pick the Limine fallback or a snapshot entry, or type
  the passphrase: it still works.

## Longer term

Designs that keep an encrypted Volunteer's Mac encrypted are in
malik-na/maclab#17 (how a lab reboot gets past the passphrase),
malik-na/maclab#36 (Attended windows, where the Volunteer types it) and
malik-na/maclab#37 (kexec Lab boots on encrypted Macs).
