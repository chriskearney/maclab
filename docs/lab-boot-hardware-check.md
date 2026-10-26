# Hardware check: Lab boots come back by themselves

The lab harness proves the deadline logic on a simulated Mac. This is the
check on a real one: that the early unit reboots a Lab boot on its deadlines
with no network, and that the Apple watchdog resets an early hang. Run it once
per Mac model, and again after an Omarchy, U-Boot or m1n1 update. Record the
results at the end.

You need: an enrolled Mac whose baseline passed, `lab` logged in to labd, a
way to see the Mac's screen (or its serial console, for step 4), and about
an hour. Start from the Mac's own boot (`lab status` shows its known-good
kernel).

## 1. The early unit is in place

On the Mac:

```sh
systemctl is-enabled maclab-lab-boot-deadlines.service   # enabled
systemctl show -p After,Wants,Requires maclab-lab-boot-deadlines.service
```

`After=` lists `local-fs.target` and nothing network-related.

## 2. No contact: a Lab boot without network reboots by itself

Boot a test entry with the network units masked, so lab-agent can never
reach labd:

```sh
lab run <mac> --boot-timeout 3m \
  --cmdline 'systemd.mask=iwd.service systemd.mask=systemd-networkd.service systemd.mask=NetworkManager.service'
```

Expect:

- The Mac boots the test entry to the login screen, then reboots by itself
  about 6 minutes (twice the boot timeout) after labd armed the one-shot, and
  comes back on its known-good kernel.
- On a Lab-owned Mac with OOB, no hard reset in the job's `recovery`.
- The job fails `lost_contact`, its events say which deadline rebooted the
  boot, and `prevboot/journal.txt` is that boot's journal. Its last lines
  include `maclab-lab-boot-deadlines`' "passed its no_contact deadline".
- `journalctl -b -1 -u maclab-lab-boot-deadlines` on the Mac shows the same.

## 3. Hard ceiling: a boot in contact still reboots at the job's end

Run a normal job (`lab run <mac>`) and, once it reports "booted", move the
ceiling close on the Mac:

```sh
sudo jq --arg t "$(date -u -d '+1 min' +%FT%TZ)" '.ceiling = $t' /var/lib/maclab/lab-boot/deadlines.json \
  | sudo tee /var/lib/maclab/lab-boot/deadlines.json.new && \
  sudo mv /var/lib/maclab/lab-boot/deadlines.json.new /var/lib/maclab/lab-boot/deadlines.json
sudo systemctl restart maclab-lab-boot-deadlines.service
```

Expect a reboot to the known-good kernel within about a minute, and
`journalctl -b -1 -u maclab-lab-boot-deadlines` saying "passed its ceiling
deadline". The job fails (`lost_contact` or `panicked`, depending on where in
the job it was).

## 4. The watchdog resets an early hang

From the research in #13, still to be seen on hardware:

1. **U-Boot arms it.** On the serial console or the framebuffer during
   U-Boot, look for `WDT:   Started watchdog@... with servicing (60s timeout)`.
2. **`apple_wdt` takes it over.** Boot a test entry with the systemd runtime
   watchdog off (`--cmdline 'systemd.watchdog_device= watchdog.handle_boot_enabled=0'`).
   The Mac should reset about 30 s after `apple_wdt` probes: the hardware
   watchdog was running when the driver took it.
3. **`watchdog.open_timeout` closes the gap.** Boot a test entry that never
   reaches systemd: `--cmdline 'init=/bin/sh'` (the entry already carries
   `watchdog.open_timeout=N`). Expect a reset about N + 30 s after probe,
   with the Mac back on its known-good kernel. With `watchdog.open_timeout=0`
   instead it would sit at the shell forever.
4. **Encrypted Mac.** If the Mac's disk is encrypted, check that N leaves
   time to type the disk password at the initramfs prompt before the reset;
   raise labd's `--watchdog-open-timeout` if it doesn't.
5. **A kernel without `apple_wdt`** (`CONFIG_APPLE_WATCHDOG` not set) should
   be flagged by the job ("built without apple_wdt") and reset about 60 s
   into its boot.

## 5. The lost boot's logs come back

`lab crashtest <mac>` panics the Lab boot on purpose. Expect the job's
`prevboot/` to hold the crashed boot's journal (its boot ID is in the job's
events) and, if the Mac has pstore/ramoops, `prevboot/pstore/` with the
`dmesg-ramoops-*` records of the panic.

## Results

| Mac model | Date | Omarchy / U-Boot | 1 | 2 | 3 | 4.1 | 4.2 | 4.3 | 4.4 | 4.5 | 5 | Notes |
|-----------|------|------------------|---|---|---|-----|-----|-----|-----|-----|---|-------|
|           |      |                  |   |   |   |     |     |     |     |     |   |       |
