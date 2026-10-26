# First-class Mesa jobs (design and increments)

A Mesa job tests exact, pinned Mesa split packages (for example `mesa-aurora` and `vulkan-aurora`) on a lab Mac, with a stated meaning and a standard result. It is not an ad hoc shell framework: packages are artifacts like kernels, results land in the job record, and the existing fault, OMT and installed-acceptance machinery stays in charge of what it already judges.

## Two meanings, never mixed
- **Staged (diagnostic).** The packages are unpacked into a private per-job prefix on the Mac. Only the job's own probe processes are pointed at that prefix. The desktop, the compositor and every other process keep the installed Mesa. A staged result is evidence about the packages on this Mac and kernel, **not about the installed desktop**. Every result restates this (`MesaResult.Semantics`), and staged runs are never published.
- **Installed (desktop).** A real package transaction makes the packages the system's Mesa. That needs a recovery contract: the previous package files pinned for rollback, identity before and after through the installed manifest/acceptance collector, and an explicit session-restart step. It is **not supported yet**, and the server refuses it. No labd ever runs `pacman` on a Mac without that contract.

## Increment 1a (this change): the request, its validation, and safety rails
- **API:** `JobSpec.Mesa` (`MesaSpec`: mode, pinned packages by artifact sha256, optional producing build) and `JobResult.Mesa` (`MesaResult`: mode, semantics, packages, per-API provider verdicts, overall verdict).
- **CLI:** `lab run <mac> --mesa-package mesa-aurora=FILE|SHA256 [--mesa-package …] [--mesa-mode staged] [--mesa-build <id>]`. Files are uploaded as artifacts.
- **Validation at submission** (`internal/server/mesa.go`):
  - installed mode is refused;
  - unknown modes, combination with `--installed`, baseline, crash or publish are refused;
  - 1 to 8 packages, Mesa-family names only (`mesa`, `mesa-*`, `vulkan-*`, `opencl-*`), no duplicates, and each sha uploaded;
  - the Mac needs a GUI user and lab-agent `0.8.0` or later.

  **No agent implements the staged mode yet, so every Mesa job is refused today** (409). A defensive runner check refuses any stored Mesa job too.
- **GC:** a Mesa job's package artifacts are pinned while the job is unfinished, so an over-budget store cannot delete them mid-job. That is what happened to unpinned kernel artifacts on 2026-10-25.
- **Tests** (`internal/server/mesa_test.go`):
  - a validation table with 16 refusals and 2 accepts;
  - the refusal on the current agent through `Submit`;
  - GC pinning while unfinished and release once done, plus a mutant check that reverting the GC change fails the test.

## Increment 1b (next): agent 0.8.0 runs a staged job
- **Agent command `mesa_stage`:**
  - fetch each package with the existing authenticated artifact fetch and verify its sha256;
  - unpack it into `/var/lib/maclab/mesa/<job>/root` with a bounded, path-checked extraction: no absolute paths, no `..`, regular files and in-prefix links only, and no `.INSTALL` scripts run;
  - record a per-file sha256 manifest;
  - write an environment file pointing the loaders at the prefix (Vulkan ICD JSON rewritten to the prefix library, EGL vendor file, `LD_LIBRARY_PATH`, DRI and GBM paths).

  It makes no system file changes and needs no pacman.
- **Builtin GUI test `mesa-provider`:** runs the frozen GL and Vulkan render-check probes under that environment and records:
  - the renderer and device strings;
  - the probe processes' mapped provider files. These are hashed with regular-file-only, bounded reads; device nodes are never read.

  A per-API verdict follows:
  - **`NATIVE_STAGED`** only if the mapped `libgallium`/`libEGL_mesa` (GL) or `libvulkan_asahi` (Vulkan) are the staged files (under the prefix, with sha256 in the staged manifest) **and** the renderer is the native Apple GPU;
  - **`SYSTEM_PROVIDER`** if the installed system libraries were used instead;
  - **`SOFTWARE`** for llvmpipe, lavapipe or softpipe;
  - **`MISSING`** otherwise.
- **Cleanup:** the job's cleanup removes the prefix, and the agent also removes leftovers at startup. The installed packages and the working kernel are never touched.
- **Gates:** standard kernel-event and new-error-line gates, OMT as usual (judging the installed desktop, unchanged meaning), job files under `test-mesa-provider/`, and `JobResult.Mesa` filled in.

## Increment 1c: the official GPU suite as an option
Optionally run the reviewed official GPU CLI (source `e81d8093`) under the staged environment. Its provider pins are the staged files, its supervisor is unchanged, and its counts and signed-report validation are the official ones. This is the measured workload; the 1b probe stays the cheap provider check.

## Increment 2: the installed desktop mode
Extend the installed manifest with Mesa package artifacts **and the previous package artifacts** (both GC-pinned). Then:
- the transaction is `pacman -U` of the exact pinned files under the boot-partition locks;
- identity is checked before and after with the installed collector (packages and mtree);
- the session restart is explicit;
- rollback is `pacman -U` of the pinned previous files, verified equal to the pre-transaction identity.

It is promoted only through installed acceptance, and is never automatic without a reviewed recovery contract.
