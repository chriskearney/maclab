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

2. **Lab-only auto-unlock** (`scripts/lab-only-autounlock`), opt-in, and
   only on an install with nothing personal on it: a **Lab-owned Mac**, a
   **fresh lab-only install**, or a **lab-only install a Volunteer lends the
   lab, with their explicit agreement** to what follows. Never on an install
   a Volunteer uses for anything of their own.

   The trade-off, plainly: **while it is enabled, anyone holding the Mac can
   read its disk.** The disk key sits inside the boot images on the
   unencrypted EFI partition, so the encryption no longer protects the Mac if
   it is lost or taken.

   `disable` protects the disk against whoever has the Mac after it: once it
   has run, the copies of the key left on the Mac open nothing. It can't
   protect against anyone who had the Mac while auto-unlock was enabled: they
   could have saved the volume key or copied the data, and removing a key
   slot doesn't change the volume key. If the Mac was out of your hands while
   it was enabled, reinstall, or re-encrypt the volume with
   `cryptsetup reencrypt`.

   Who can read the key on the Mac itself: root, and anyone who can read the
   EFI partition. On a Lab-owned Mac the Maintainers already have root (`lab
   exec` runs as root), so this adds nothing for them. On a Volunteer's Mac
   that holds only at Full Access: its Access level is Qualification unless
   its Volunteer raises it, and Qualification gives Maintainers no `lab exec`
   and no scripts. Lab jobs also run tools as the GUI user, so keep the EFI
   partition readable by root only (mount it with `fmask=0077,dmask=0077`):
   `enable` and `status` warn loudly when a boot image holding the key is
   readable by anyone else.

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
   that every `/boot/initramfs-*.img` holds the key file, that every
   `limine.conf` entry booting those UKIs (snapshot entries and the maclab
   block aside) has the argument on its own `cmdline:` line, and that the key
   opens the volume. On an Omarchy Mac each entry carries its own `cmdline:`,
   and that, not the UKI's embedded command line, is what boots.

All of `enable`'s refusals come before it asks you to confirm and before it
adds the key slot, so a refused `enable` leaves nothing behind. Besides the
layout above, it refuses an `/etc/crypttab.initramfs` entry for the volume,
another `rd.luks.key=` for it on the command line, a command line that isn't
one plain double-quoted value, and an Omarchy Mac (the `omarchy-mac-*` tools
are there) with no `/etc/default/grub`.

Reboot: there should be no passphrase prompt, and preflight should accept the
Mac. On the first hardware run (chriskearney/maclab#38) preflight accepted
both encrypted Macs with no change to maclab, and their Lab boots unlocked
unattended.

`status` reports each piece: the key slots, the key file and which slot it
opens (or that it is **dead**, opening none), the drop-in, the command-line
argument in the file and in the running boot, each boot image and boot entry,
and any boot image holding the key that users other than root can read. On
an Omarchy Mac with `/boot/omarchy/encrypt.state`, the owner's and recovery
key slots are never touched, and any other slot is listed. With or without
it, a slot made the way this script makes them (pbkdf2, 1000 iterations)
that the key file doesn't open is listed as unexplained.

## Leaving the lab

Take the lab off the Mac first, then turn auto-unlock off:

```sh
sudo lab-agent uninstall    # or, on a Volunteer's Mac, sudo lab-agent leave
sudo scripts/lab-only-autounlock disable
```

The order matters: the lab boot UKIs lab-agent stages under `<esp>/maclab/`
are built from this Mac's initramfs, so they hold the key too. `uninstall`
(or `leave`) removes them, and `disable` refuses while one holding the key
is still there.

`disable` asks for your passphrase and checks it opens another key slot. It
refuses if the key's slot is the only one left. Then it removes that key slot
using the key file **first**, so the copies of the key on this Mac (in the
boot images, in snapshots, in backups) open nothing. Only then does it delete
the key file, the drop-in and the `rd.luks.key=` argument, rebuild the boot
images and check that none still holds the key or the argument. As above,
that protects the disk from whoever has the Mac next; it doesn't change the
volume key.

If the key file is gone but a boot image still holds a key (a restored
snapshot, or a key file deleted by hand), `disable` copies that key out of
the image into a private temporary folder, removes the slot it opens with it,
and shreds the copy. If it can't copy the key out, it refuses and says how to
find the slot (`cryptsetup luksDump`: the auto-unlock slot uses pbkdf2 with
1000 iterations, passphrase slots argon2id) and remove it with
`cryptsetup luksKillSlot <device> <slot>`. It only reports the Mac as already
disabled when no key slot, key file, drop-in, argument, boot image or boot
entry is left.

To remove the key slot by hand, while the key file is still there:

```sh
sudo cryptsetup luksRemoveKey <device> /etc/cryptsetup-keys.d/root.key
```

(`<device>` is the LUKS partition; the key file is named after the volume,
`root` on an Omarchy Mac.) Then remove the key file, the drop-in and the
argument, and rebuild the boot images.

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
