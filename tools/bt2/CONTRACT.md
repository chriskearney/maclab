# bt2 controller <-> target contract (v1)

## Target package (uploaded to the Mac as files, run as root)
/var/lib/maclab/bt2/<run>/t/  : __main__.py common.py capture.py pkg.py writers.py espops.py audit.py limine.py
Invocation (by controller via labd exec):
  cd /var/lib/maclab/bt2/<run> && /usr/bin/python3 -I -B t <cmd> --run-dir /var/lib/maclab/bt2/<run>
Exit codes: 0 ok; 3 refused BEFORE any change (safe); 4 failed AFTER a change (restore required);
            5 internal error (treat as 4). Stdout: exactly one JSON object (last line), <= 256 KiB.
Every command writes receipts/<cmd>.<seq>.json (O_EXCL, fsync) with the same JSON before exiting.
No command reboots. No command retries a failed mutation.

Common result fields: {schema:"bt2.target-result/1", cmd, ok, run_id, device, boot_id, kernel, changed:bool,
                       refused_reason?, error?, ...cmd-specific}

## Run dir on the Mac (root 0700)
config.json  (written by controller; target verifies sha256 given by controller via --config-sha256)
pkgs/<file>          candidate archives      originals/<file>   original archives (for rollback)
capture/state.json, capture/esp.tar, capture/etc.tar, capture/boot.bin, capture/menu.conf
hold/                 moved aside items (writer aliases, unowned module trees, parked ESP files)
receipts/             one JSON per command execution
markers created by bt2 are always named exactly: /usr/lib/modules/<krel>/.keep-local-kernel (only if absent
at capture), ESP file EFI/Linux/bt2-<run8>-original.efi, menu entry "/bt2 original <run8>".

## config.json (schema bt2.target-config/1)
{
 "schema": "bt2.target-config/1", "run_id": "...", "device": "m1", "board": "apple,j293",
 "known_good_kernel": "7.2.11-6-1-ARCH", "gui_user": "chrisk", "gui_uid": 1000,
 "esp": "/boot/efi", "esp_reserve_bytes": 125829120, "root_reserve_bytes": 2147483648,
 "candidates": [ {"name","version","file","sha256","bytes"} ... ],
 "originals":  [ {"name","version","file","sha256","bytes"} | {"name","version": null} ... ],
       # version null = package absent at baseline => rollback removes it
 "artifact_shas": {"<file>": "<sha256>"},           # everything fetch must download
 "writer_units": ["limine-snapper-sync.service","limine-snapper-watcher.service","snapper-timeline.timer",
                  "snapper-cleanup.timer"],        # handled only if present on the Mac
 "etc_capture": ["/etc/pacman.conf", "/etc/default/limine", "/etc/limine-entry-tool.conf",
                 "/etc/limine-entry-tool.d", "/etc/default/update-m1n1", "/etc/m1n1.conf",
                 "/etc/mkinitcpio.conf", "/etc/mkinitcpio.conf.d", "/etc/mkinitcpio.d",
                 "/etc/systemd/system"],
 "allow_bootbin_change": false,
 "expected_bootbin_sha256": "<from manifest macs.<dev>.boot_bin_sha256>"
}

## Commands
preflight  read-only. ok=false+exit 3 on any gate failure. Reports: board, kernel, boot_id, cmdline_job_tag,
           db_lock, root_free, esp_free, packages{name: version|null}, default_entry{name,path,uki_sha256,b2},
           bootbin_sha256, menu_sha256, writer_units{unit:{load,active,enabled,etc_link}}, module_trees{krel:
           {owned_by_pkg:bool, keep_marker:bool}}, cleanup_dropin_keep_marker:bool.
fetch      downloads artifact_shas from labd (agent creds in /etc/maclab/agent.json) into pkgs/ or originals/
           (by whether the file is a candidate or original); verifies sha+size; idempotent per verified file.
capture    builds capture/ (see SPEC). Verifies each originals/ archive reproduces installed payload of its
           package (sha per regular file in /var/lib/pacman/local/<pkg>/files list, excluding backup= files
           whose live sha differs -> recorded as config). Refuses (3) if any mismatch. Result has
           capture_sha256 (sha of state.json) and file pins for esp.tar/etc.tar.
hold-writers / release-writers   as SPEC. Idempotent: a second hold on a held unit is a no-op with proof.
esp-prep   fallback copy + menu entry + default_entry repoint; ESP free check; never touches maclab block.
install    as SPEC; on success reports candidate{krel, uki_path, uki_sha256, entry_name}, bootbin_unchanged.
           On boot.bin change with allow false: restores captured boot.bin bytes, exit 4.
rollback   as SPEC (must run on known_good kernel, no job tag).
esp-restore  exact ESP restore vs capture (including limine.conf, ubootefi.var, removal of bt2 files).
audit      exact compare vs capture -> {"differences": [...]} ok iff empty (allowed volatile list below).
           Volatile (never compared): /etc/systemd/system/*.wants changes made by systemd itself? NO - compared.
           Only boot_id, uptime, journal, /var/lib/maclab/bt2/<run>/ itself, and labd agent work dir are excluded.
cleanup    removes pkgs/ originals/ hold/ (only after audit ok); keeps receipts/ and capture/.

## capture/state.json (schema bt2.capture/1) — written by capture.py, read by pkg.py / espops.py / audit.py
{
 "schema": "bt2.capture/1", "run_id": str, "device": str, "boot_id": str, "kernel": str, "board": str,
 "captured_at": float,
 "packages_all": {name: version},                                   # pacman -Q
 "packages": {name: {"version": str|null, "mtree_sha256": str|null, "files": [abs paths]}},  # named pkgs only
 "backup_files": [abs path],                                         # backup= files of named packages
 "modules": {krel: {"owned_by": [pkg], "keep_marker": bool, "tree_sha256": str, "entries": int}},
 "running_kernel": {"krel": str, "owned_by": [pkg], "copy": "capture/modules/<krel>.tar" | null},
 "esp": {"root": "/boot/efi", "free": int, "excluded": ["ubootefi.var*", "maclab/"],
         "files": {rel: {"size": int, "sha256": str, "mtime_ns": int}}, "dirs": [rel],
         "info": {"ubootefi.var": sha|null}},
 "menu": {"sha256": str, "bytes": int, "default": {"name": str, "path": rel, "uki_sha256": str, "uki_b2": str,
          "cmdline": str|null, "auto_entry": bool}},
 "bootbin_sha256": str,
 "etc": {abs path: {"type": "f"|"d"|"l"|"absent", "mode": int, "uid": int, "gid": int, "size": int,
         "sha256": str|null, "mtime_ns": int, "target": str|null}},          # capture set incl. dir members
 "units": {unit: {"LoadState","ActiveState","UnitFileState","FragmentPath","DropInPaths"}},
 "systemd_etc": {rel under /etc/systemd/system: {"type": "f"|"d"|"l", "target": str|null, "ino": int}},
 "efivars": {"LoaderEntryOneShot": bool, "LoaderEntryDefault": bool},
 "snapshots": [int], "limine_history": {rel: sha256},
 "conflicts": [{"path": abs, "package": name, "sha256": str, "mode": int, "uid": int, "gid": int,
                "mtime_ns": int}],
 "known_good_refs": {abs path: sha256},
 "originals_verified": {pkg: {"archive": file, "files_checked": int}},
 "copies": {"esp": "capture/esp", "etc": "capture/etc"}
}
Paths in tests go through common.P(); tools through common.BIN().
