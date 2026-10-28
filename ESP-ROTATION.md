# Explicit ESP retirement and restoration (source draft)

`lab-esp` is a standalone command. Building or reviewing it does not deploy an
agent, replace a controller, authorize target writes, install a kernel or reboot.
The existing agent/controller binaries stay unchanged. This tree is based on
`da13c820393507d5f69beaf0b5a6b98764633c9b`; a future controller deployment must
separately preserve the deployed 81abf6a metadata/durability fixes.

## Supported first scope

- One explicitly named, existing **top-level leaf ARM64 UKI** and its exact menu
  stanza, provided it is not current/default/known-good/previous-known-good,
  armed, shared with any other menu entry or owned by a managed lab entry.
- One explicitly named **unreferenced `m1n1/boot.bin.pre-<plain suffix>` backup**.
  Live `m1n1/boot.bin`, `m1n1/boot.bin.old`, root `boot.bin`, other paths and all
  menu-referenced files are refused. The menu stays byte-identical in this mode.
- Named defaults and reviewed Limine 12.9.0/12.9.3 BLI identifiers only.
  Ambiguous/numeric defaults, normalized-ID collisions and unsupported resource
  syntax refuse. A shared snapshot UKI is never silently retired.

There is no broad discovery/delete, installed-release promotion, reference update,
module removal, EFI-variable write, default change, enrollment change or service
operation. Inactive managed lab entries still use normal supported job cleanup;
this first helper deliberately does not remove their source `entry.limine` files.

A controller maintenance/no-staging fence and exclusive device lease are required
externally before any approved application. The helper additionally refuses a
lab-tagged boot, any local jobs workspace or armed one-shot and takes both
existing boot locks in their existing order. These checks do not replace the
controller fence or claim to stop an old agent before it begins unlocked work.

## Commands and review boundary

Cross-build without running on a Mac:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o lab-esp ./cmd/lab-esp
```

After separate target-write authorization, the owner uses the existing authenticated
**logged lab execution channel** to run the reviewed standalone binary. No new SSH
credentials, signing keys or services are introduced. Plan prints JSON to stdout;
redirecting stdout through the owner channel saves the reviewable artifact.
Every later operation requires SHA256 of the exact canonical plan bytes.

```sh
sudo ./lab-esp plan --esp /boot/efi --menu /boot/efi/limine.conf \
  --transaction example-uki --kind uki-leaf --entry '/Retired kernel' \
  --uki /boot/efi/EFI/Linux/retired.efi --kernel EXACT_UNAME \
  --uki-sha256 EXACT_SHA256 --uki-size EXACT_BYTES --retire-only
```

Download the exact proposed bytes through the authenticated chunk/readback path.
On the **controller**, not on the Mac, retain outside CAS/GC:

```sh
sudo ./lab-esp controller-retain --plan plan.json --plan-sha256 PLAN_SHA \
  --source /private/verified-download.efi \
  --archive-root /var/lib/maclab/esp-archives
```

This creates a private durable copy, fsyncs file and directories, reopens and hashes
it, and writes a plan-bound receipt with actual controller machine-id, copy path,
size, SHA and verification time. Reinvoking rechecks bytes. Archives on tmpfs/ramfs
or in an `artifacts` path are refused. Ordinary CAS upload alone is not retention:
current CAS GC can delete unrelated UKIs. No receipt copies a private key.

The owner reviews that actual receipt, obtains its exact hash, and supplies it over
the authenticated channel. This is an explicit root-controlled attestation, **not
cryptographic proof of arbitrary untrusted JSON or permission to retire**. The
helper requires the exact reviewed receipt hash, same plan/file, a different actual
machine identity and a fresh verification within five minutes. Refresh by rerunning
controller-retain and independently reviewing its new readback if this expires.

```sh
sudo ./lab-esp apply --plan plan.json --plan-sha256 PLAN_SHA \
  --retention controller-retention.json --retention-sha256 REVIEWED_RECEIPT_SHA \
  --archive-root /var/lib/maclab/esp-archives
```

Under the boot locks, apply rechecks boot identity/protected files/menu/UKI, creates
and reopens the **second independent retained copy on the Mac's non-ESP persistent
filesystem**, and fsyncs the original plan plus receipt before changing anything.
It then removes exactly the reviewed stanza, records that phase, unlinks only the
exact rehashed file, fsyncs the ESP directory, and records capacity. If interrupted,
inspect the durable phase files; do not blindly repeat apply under the same name.

```sh
sudo ./lab-esp restore --plan plan.json --plan-sha256 PLAN_SHA \
  --archive-root /var/lib/maclab/esp-archives
```

Restore refuses a foreign menu or existing different destination. It verifies the
local archive again, checks capacity for the full new allocation, copies/fsyncs/
reopens the UKI, publishes it, then restores the exact original stanza bytes.
A verified interrupted temp copy can resume. Repeated completed restore is safe.
If the local archive fails, preserve the failure and separately transfer/review the
verified controller copy; there is no automatic untrusted download or fallback.

Restore after an actual normal test return allows a new boot ID and changed raw
U-Boot variable-store bytes only. It does **not** roll back those variable bytes.
Machine, expected running kernel, BLI selected/default/one-shot, current defaults,
known-good records, current/other UKIs, live boot bundle, `.old` and ESP-root copy
must otherwise match. Observe/receipt records the new return identity. Any package
rollback owner must restore those original payloads first. Snapshot/menu churn or
an accepted new release requires a separately reviewed new plan; no fuzzy waiver.

## Capacity contract

Admission uses **available-to-root bytes on the actual ESP**, not rootfs free space:

```
120 MiB + 1 MiB bounded metadata + ceil(UKI_bytes/allocation_unit)*NEW_ESP_copies
    + ceil(additional_ESP_bytes/allocation_unit)
```

`--next-uki-bytes` is an exact privately built size or reviewed conservative ceiling,
never the compressed kernel or `Image` size. `--next-esp-temporary-copies` is 1 for
one new temp alongside the existing destination; use 2 if a separate staged new
copy and generator temp coexist. Existing destinations are never free credit.
`--additional-esp-bytes` accounts separately for differently sized live additions,
such as the exact old6 fallback. Each retirement credits only its observed allocated blocks; `retire-only` explicitly
makes **no** staging-admission claim. The final observation must still fit.

The separate agent source patch in `internal/agent/uki_reserve.go` fixes the known
stage peak: generate in root-private non-ESP scratch first, then lock and reserve
for the exact rounded output +120MiB+1MiB before one ESP temp copy. Fsync/readback
and a second reserve check precede rename. It preserves generator flags and does
not relax module/current/known-good admission. That agent change is source only;
standalone `lab-esp` deployment alone does not fix the existing daemon generator.

## First MBP composition (private packet remains authoritative)

Use two independently reviewed transactions, not an invented combined free-space
credit. First retire the named inactive SF UKI with `--retire-only`. Then make a
**fresh** backup-file plan from that post-p1 menu, with either `--retire-only` or
an exact next-operation budget including all additional allocations. For the
reviewed MBP packet, old6 bytes 60,215,808 plus candidate UKI ceiling 64,413,696,
one new temp and 1MiB metadata require 251,510,784 bytes after both retirements.
Observed available would be 251,666,432, leaving only 155,648 bytes beyond that
full conservative budget; remeasure immediately before application and before
each subsequent allocation. These are packet predictions, not actual mutations. Second mode:

```sh
sudo ./lab-esp plan --esp /boot/efi --menu /boot/efi/limine.conf \
  --transaction example-backup --kind unreferenced-m1n1-backup \
  --uki /boot/efi/m1n1/boot.bin.pre-EXACT_SUFFIX \
  --uki-sha256 EXACT_SHA256 --uki-size EXACT_BYTES --retire-only
```

The separately reviewed owner packet adds a distinct old6 fallback and repoints
its alias. That is **not** done by this helper. A plan budget must include that
additional UKI allocation; do not claim the post-retirement capacity receipt
reserves space indefinitely. No space is reserved against an unrelated writer.
The packet's gate must recheck immediately before generating the next UKI.

After testing/rollback, the owner first removes only its owned transient old6/test
copy and restores the exact post-p1 menu and original protected payloads (including
original `.old`, current UKI/default and alias resource bytes). Then restore p2
(the backup plan) first; p2's unchanged menu is the post-p1 menu. Restore p1 (SF)
second, bringing back the exact original menu. Restoring in the wrong order
refuses menu/protected-state CAS. If any step cannot fit, stop with both archives
preserved; never remove another recovery artifact speculatively.

Host tests cover actual retained MBP menu *shape* with machine/root IDs redacted,
rounded packet arithmetic, both artifact types, device/FIFO data-open refusal,
path swap, proof drift, protected/default/shared entries, capacity boundaries,
interrupted apply/restore, corruption, normal-return exceptions and idempotence.
They are not a device, package-acceptance or boot-recovery pass.
