# bt2 — one generic, deterministic boot-test workflow for every lab Mac (v2, Claude, 2026-10-26)

`bt2 run --device m1|m1air|m3pro --artifact pkg.tar.zst ... [--mode network-only|serial-assisted]`
installs candidate packages, runs the normal labd installed-mode test job, rolls back, restores, and proves the
Mac matches the state captured at the START of the run. One code path. Per-device facts = devices/<name>.json.
Research basis (read these): /dev/shm/claude-229/research/{labd-installed-mode.md, m1-safety-mechanisms.md,
device-differences.md}. Contract: CONTRACT.md. This file wins where they differ.

## Principles
1. Truth = fresh capture at run start (on the Mac, pulled to the controller, retained on the M5). No device
   state is pinned in source.
2. Every mutating step writes a journal intent BEFORE it runs; `bt2 restore --run ID` runs remaining inverses
   from any stopping point. No automatic retry of an ambiguous mutation: stop, record, report.
3. Exact, verified, reversible edits only: write temp + fsync + rename + readback; CAS against the expected
   current hash; never `--overwrite`; never delete what we did not create (move aside instead).
4. Take /run/lock/boot-partition.lock (flock) around every limine.conf / ESP mutation. These tmpfs locks vanish
   at reboot: create only if missing (root 0644, O_EXCL|O_NOFOLLOW) after each reboot.

## Target-side behaviour (stdlib Python, root, via labd exec; files under /var/lib/maclab/bt2/<run>/)

### capture (read + local copies only)
- state.json: pacman -Q (all), for every package named in candidates/originals: version (or null) + sha256 of
  gunzipped /var/lib/pacman/local/<pkg>-<ver>/mtree; /usr/lib/modules tree map {krel: owned_by, keep_marker,
  tree_sha256 (type/mode/uid/gid/size/sha256 per entry, no symlink follow)} for the running kernel and every
  krel the candidates install or remove; ESP manifest (every file: rel path, size, sha256, mtime_ns) EXCLUDING
  ubootefi.var* and maclab/ (lab-agent owned; recorded separately as info); limine.conf bytes; boot.bin sha;
  default entry {name, uki path, sha, blake2b, cmdline, owned_by_package_uki: bool}; /etc capture set
  (config.etc_capture + every backup= file of the named packages + their .pacnew/.pacsave siblings):
  type, mode, uid, gid, size, sha256, mtime_ns, symlink target; systemd unit states (systemctl show
  LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths) for writer units, linux-modules-cleanup.service,
  and units shipped by the named packages; /etc/systemd/system full listing incl. symlink targets + inode;
  efivars presence of LoaderEntryOneShot/LoaderEntryDefault; /.snapshots ids; limine_history listing.
- copies: capture/esp/ = byte copy of every ESP manifest file (needed for exact restore); capture/etc/ = copies
  of /etc capture set; capture/modules/<krel>.tar for the running kernel tree when owned by a package that the
  candidates replace (restore source if kernel-modules-hook does not restore it exactly).
- original-archive proof: every originals/ archive must reproduce the installed files of its package
  (sha256 of each regular payload file vs live file; backup= files may differ and are covered by /etc capture).
  Missing original archive for a package that will change => refuse (exit 3).
- unowned-conflict scan: every regular file path in a candidate archive that exists on disk and is NOT owned by
  any package (pacman -Qqo fails) => list `conflicts` (M3 has 5). Reported in capture; held by install.
- refuse if: root free < copies + 2 GiB; capture dir already exists.

### hold-writers / release-writers
- Units (config.writer_units, only if loaded): limine-snapper-sync.service (+alias limine-snapper-watcher.service),
  snapper-timeline.timer, snapper-cleanup.timer. Refuse if snapper-cleanup.service or snapper-timeline.service
  is active (never cancel a running cleanup/snapshot); stop timers first, then the sync service.
- Persistent mask: if /etc/systemd/system/<unit> is an alias symlink, hard-link it to hold/alias.<unit>
  (keeps inode) then unlink; then create mask symlink /etc/systemd/system/<unit> -> /dev/null; daemon-reload;
  verify inactive + masked. Receipt lists every mask we created (only those are removed on release).
- release: remove only our masks, re-link held alias (same inode), daemon-reload, start only units that were
  active at capture. Verify states == capture.

### esp-prep
- Space need = 120 MiB reserve + PEAK (64 MiB = 67,108,864, also the pacman RLIMIT_FSIZE) + fallback copy size
  (if a copy is needed) + 1 MiB. If ESP free < need: park files from devices/<dev>.json `parkable` (in order)
  until enough: move file to hold/esp/ (after copying to capture already), remove its top-level menu stanza if
  one references it; record. If still short: refuse (exit 3, nothing changed or everything undone).
- Fallback: if the default entry's UKI is written by a candidate package (default UKI path ==
  EFI/Linux/<CUSTOM_UKI_NAME>_<pkgname>.efi for a candidate kernel pkgname, or simply: the default entry is the
  limine-entry-tool auto entry) => copy UKI to EFI/Linux/bt2-<run8>-original.efi (sha+b2 verified), insert
  top-level stanza "/bt2 original <run8>" (protocol efi, path copy#b2, cmdline = default entry cmdline) just
  before the maclab block, set default_entry to "bt2 original <run8>". Else (custom default, M3): no copy,
  keep default; record default must stay byte-identical through install.

### install (phases; each phase = one bounded pacman transaction)
- Phase order: every candidate except the boot package (omarchy-mac-boot) first, then the boot package alone.
- Before phase N: ESP free >= reserve + PEAK; db.lck absent; writers still masked.
- Local-only config: exact preamble + leading [options] block of /etc/pacman.conf, no repo sections/Includes,
  SigLevel unchanged. `pacman --config C -U --print --print-format 'BT2\t%n\t%v\t%l' -- FILES` must list exactly
  the phase's packages at the given versions/local paths, only allowed diagnostics.
- Unowned conflicts belonging to this phase's packages: move each to hold/conflicts/<sha>/<basename> with a
  receipt (path, mode, uid, gid, mtime, sha) before pacman.
- Running kernel module tree, if owned by a package in this phase: copy-verified in capture already.
- pacman -U --noconfirm in its own session/pgid, RLIMIT_FSIZE=PEAK, timeout 900 s then TERM, 30 s, KILL;
  record outcome durably BEFORE any follow-up; if the group cannot be drained => exit 4 "UNKNOWN", no restore.
  Scan output for 'error:' / hook failure lines even on exit 0 => fail.
- After all phases: versions == candidates; running-kernel tree exact (else restore from capture copy and
  verify); create owned .keep-local-kernel marker only if absent at capture (O_EXCL, receipt dev/ino);
  boot.bin sha must equal config.expected_bootbin_sha256 (the manifest's macs.<dev>.boot_bin_sha256); if not
  and allow_bootbin_change is false => restore captured boot.bin bytes immediately, exit 4;
  re-assert default_entry (fallback stanza or unchanged custom default) by CAS; default UKI bytes unchanged;
  report: candidate krel(s), installer entry (name, path, sha), extra new ESP files and menu entries created by
  the transaction (e.g. M3 Eryk UKI), services the transaction enabled/started (diff vs capture).

### rollback (only on the known-good kernel, untagged boot, writers masked)
- Stop units the transaction started that were not active at capture (e.g. omarchy-mac-efi-vars.service).
- Remove our .keep-local-kernel marker (receipt match). If the running kernel tree is now unowned and an
  original archive will own it again: rename it to /usr/lib/modules/.bt2-hold-<run8>-<krel> (no copy).
- Phase order reversed: boot package first (`pacman -R` if absent at capture, else -U original), then the rest
  (-U originals; -R for packages absent at capture). Same local-only config, print check, bounded pacman.
- Reinstate held conflict files exactly (bytes, mode, owner, mtime) after their owning package is removed.
- Verify: pacman -Q == capture for all named packages; mtree sha == capture; running tree == capture
  (if the reinstalled tree differs from the held one => fail, keep both); then delete the hold tree.

### esp-restore + etc-restore (writers still masked)
- ESP: for every capture manifest file whose live bytes differ -> rewrite from capture/esp (temp+rename);
  remove files not in capture manifest (fallback copy, transaction extras such as the Eryk UKI), except
  ubootefi.var* and maclab/ (lab-agent owned); restore limine.conf bytes last (CAS); restore parked files.
  Verify full ESP manifest == capture.
- /etc: for each capture-set path: bytes differ -> restore bytes+mode+owner+mtime from capture/etc; only mtime
  differs -> utime; file absent at capture but present now (.pacnew/.pacsave, new files under captured dirs)
  -> move to hold/etc-extra/ (never delete). Verify.

### audit (read-only; exact)
Compare every captured item with the live system. Allowed differences: boot_id/uptime; ubootefi.var*
(informational, reported); /var/lib/maclab/bt2/<run>/; labd agent work dirs; /usr/lib/modules/.old content
added by linux-modules-cleanup for candidate trees (reported). Must also hold: no LoaderEntryOneShot/Default
efivars; no bt2 markers/stanzas/copies; ESP free == capture free (+-1 MiB); known-good refs unchanged
(/var/lib/maclab/known-good.json*). Two modes: `--held` (writers masked) and final (after release-writers:
menu may differ from capture ONLY by snapshot-subtree additions, checked with the snapshot grammar).

### cleanup
After final audit ok: remove pkgs/, originals/, hold/ trees we own; keep capture/ + receipts/.

## Controller sequence (bt2/controller.py)
lease (holder bt2) -> recovery-mode select + readback (generic select(); serial-assisted only if /api/devices/
<dev>/oob says connected) -> push target package + config -> upload artifacts -> fetch -> preflight -> capture
-> pull capture (state.json + receipts) to controller run dir -> M5 retain capture tarball (gate) ->
write preinstall (copy from devices/<dev>.json baseline_release) + freeze manifest (reuse from
devices/<dev>.json manifest_source_release; release = bt2-<dev>-<run8>) -> hold-writers -> esp-prep -> install
-> freeze entry -> native script + inputs -> submit job -> wait -> verify back on known-good (new boot id,
untagged) -> recreate locks -> rollback -> esp-restore -> etc-restore -> ordinary reboot (systemctl --no-block
reboot via exec) -> wait new boot id (<= 6 min), kernel == known-good, untagged -> audit --held ->
release-writers -> audit (final) -> cleanup -> M5 retain result -> release lease.
Failure anywhere: journal 'failed', stop, keep lease, print `bt2 restore --run <id>`.
`bt2 restore`: from the journal, run (in reverse) the inverse of each started step that is not yet undone,
including a reboot to the known-good default if the Mac is on a candidate or tagged boot; end with audit.

## Native GL/VK test
Generic wrapper around the existing checker (components/native/normal-session-smoke-launchfix.py, sha b33eb239)
and supervisor: manifest from config (device, board, kernel=candidate krel, gui_user/uid, wifi iface/mac from
preflight, providers = candidate Mesa package files libgallium*.so, libEGL_mesa.so.0.0.0, libvulkan_asahi.so,
libdril_dri.so, libGLX_mesa.so.0.0.0, libgbm.so.1.0.0 with sha/bytes from the artifact, tools = probes-r2).
Script reads <run>/native-input.json at job time; script bytes depend only on the run dir path.

## Boot.bin-changing runs (`--allow-bootbin-change`, 2026-10-27, pA, boot-combo-26f8)
Default path unchanged: a candidate set that changes m1n1/boot.bin is refused. With the flag (generate manifests only):
- manifest: boot.bin must become exactly the manifest-computed bytes (candidate m1n1.bin + candidate DTBs + current
  U-Boot gz + current trailer). A candidate m1n1.bin is allowed only with the flag; its stage 2 version is the text
  after its one `##m1n1_ver##` marker, and the same rule must first reproduce the live version from the installed
  m1n1 archive. The flag with an unchanged boot.bin is refused.
- install (target pkg.py check_bootbin): exact candidate boot.bin, update-m1n1's `m1n1/boot.bin.old` == the captured
  original (the Recovery copy), and the ESP must still pass reserve + peak after the install; else the captured
  boot.bin and boot.bin.old are restored and install fails before anything reboots.
- bootbin-guard-install (right after install, inverse bootbin-guard-remove): unit bt2-<run8>-bootbin-guard.service,
  enabled for the next boot only. ExecStop (orderly shutdown) and ExecStart (any boot not on the candidate kernel)
  replace the exact candidate with the captured original (CAS under the boot-partition lock); other bytes are left
  alone. NOT a hard one-boot limit: a panic, hang, power loss or reset of the candidate boot skips the stop hook and
  the next boot runs the candidate stage 2 again; a stage 2 that never reaches Linux needs a person at macOS
  Recovery (RECOVERY.txt in the run dir: ESP partition UUID, boot.bin.old hash, commands).
- bootbin-guard-check (back on known-good): one start receipt from the candidate kernel boot, labd booted/after
  identity MATCH (boot.bin + stage 2 = candidate), exactly one clean restore, boot.bin == original, Recovery copy
  intact. A restore by a later boot's start hook makes the run GUARD_LATE_RESTORE (never a pass).
- bootbin-guard-remove before rollback (also first in `restore`): stop hook, one more CAS restore, unit files out.
- stage2-final after the ordinary reboot (and restore-stage2-final in `restore`, before audit): live stage 2 and
  boot.bin are the captured originals.

## Off-target capture carrier

The complete `capture/` and `receipts/` trees travel as `bt2-capture.tar.gz`.
The controller verifies its SHA256 and size, and the M5 fsync/reopen verification
retains it as `capture.tar.gz`. Compression changes the transport representation;
the original files, metadata and on-Mac capture tree remain intact. Standard
`tar -xzf capture.tar.gz` opens the independently retained recovery copy.
