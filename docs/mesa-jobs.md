# First-class Mesa jobs

A staged Mesa job runs exact uploaded split packages in its own private prefix on the selected Mac and test kernel. The compositor and other desktop processes continue using installed Mesa. Results are private diagnostics about the staged providers on that boot; they do not qualify the installed desktop or promote an OMT reference.

## Admission and operator inputs

The controller exposes schema-1 capabilities at `GET /api/mesa`. Mesa submissions use the dedicated `POST /api/mesa/jobs` route. The client never falls back to the older ordinary-job route: an old controller cannot silently discard the Mesa request and boot a kernel-only job. The selected agent must advertise `mesa_staged` capability and version 0.8.0 or newer, and have an existing nonroot GUI account. Stored jobs repeat admission before any device command and after waiting for a build/device.

Upload the two approved render-check helpers with `lab upload` before the first job. Their hashes are fixed in `internal/mesa/types.go`, and their retained source/provenance is described in `tools/mesa-probes/README.md`. The small helpers remain GC-pinned. The controller must also retain each exact package artifact; unfinished jobs pin every package regardless of job age. Reference-query failures stop artifact GC.

Use the existing kernel selection and recovery options with:

```
lab run <mac> --mesa-package mesa-aurora=FILE_OR_SHA256 \
  --mesa-package vulkan-aurora=FILE_OR_SHA256 --mesa-mode staged
```

An optional `--mesa-build` must name a completed package build containing every requested artifact by exact package name and SHA. Archive contents are checked independently on the agent. Installed mode, `--installed`, baseline, crash, publication, OMT allowlists and replacement of the mandatory provider test are refused. Normal recovery readiness and kernel/ESP admission still apply.

## Agent staging and provider proof

`mesa_stage` binds the actual job tag, boot ID, running kernel and command-line digest. It downloads through the authenticated artifact channel and rehashes every archive and helper. It never runs package install scripts or pacman.

The bounded extractor admits regular files, directories and deferred in-prefix relative symlinks. Traversal, absolute paths, path collisions, hardlinks, devices, FIFOs, privilege bits and escaping/cyclic aliases are refused. A package must contain exactly one zstd frame with no skippable frame; decompression has a 60-second deadline inside a three-minute staging deadline. After the tar end marker, at most 1 MiB of block-aligned zero padding is drained before waiting for the decoder, so trailing payloads and full-pipe hangs fail. Every package's actual `.PKGINFO` must name the requested package, use a coherent Mesa-family pkgbase/full pkgver/aarch64 cohort, and have a distinct archive hash. Original EGL/Vulkan JSON descriptors must name the extracted native providers. Generated private descriptors preserve their fields and point only at canonical staged files.

The root-owned prefix is private to root and the existing GUI group (0750); its library tree is read-only to the child. The GUI-owned HOME/cache/tmp/state subtree is separate. Runtime inputs and staged per-file manifests stay root-owned 0600. The prefix must be on a non-FAT filesystem and cannot consume the ESP.

The mandatory `mesa-provider` test runs the fixed GL and Vulkan correctness probes for three seconds each in owned transient systemd cgroups, with an explicit clean environment and staged loader paths. Each API needs a native Apple renderer, a zero-wrong-pixels oracle, the actual expected staged implementations and an observed native render descriptor. Loader-only, mixed system providers, software renderers, unknown/deleted graphics mappings and incomplete witnesses cannot pass.

Provider identity uses retained O_PATH descriptors for the actual `/proc/<pid>/map_files/<range>` reference and canonical live file, equal complete inode metadata, SHA pins and repeated exact mapping/PID-birth checks. It does not equate Btrfs textual maps-device numbers with filesystem fstat device numbers. Cached byte hashes retain their descriptors and repeat all identity checks. A complete witness also binds the actual held helper image and SHA, exact arguments, trusted environment, unique unit leader and flushed checked-work banner. Previously proved ranges may retire while that same process is alive: a fixed five-second completion window repeatedly admits and binds every current graphics map, verifies retained/live file identity and rejects address reuse by another provider. Owned process-read ENOENT/ESRCH may use this route only after that same-birth complete witness. Missing first proof, PID/image/argument/environment drift, new unverified ranges and a hang still stop. Genuine same-invocation exit zero, the correctness oracle and verified empty owned-cgroup cleanup remain mandatory. Pre-first-witness range races conservatively stop rather than granting a completion waiver.

Before and after each phase the root supervisor checks actual boot identity, GUI displays, connected Wi-Fi, CPU/memory/thermal admission, installed package identity and trusted system graphics bytes. Fresh same-boot journal cursors reject new GPU/DART/reset/timeout/kernel faults without baseline normalization or fault waivers. Cancellation, partial output and cleanup failure never produce a staged PASS.

## Results, cleanup and current limits

`JobResult.Mesa` records exact package hashes, boot/kernel/manifest identity, `NATIVE_STAGED` for both APIs, cleanup, verdict and explicit staged semantics. Ordinary uploaded test artifacts retain the staged manifest, runtime/source pins, actual provider witnesses, probe output, journal and genuine terminal/cleanup receipts. Boot-health always precedes the managed GPU phase, preserving explicit caller settings and additional requested checks; a failed boot-health stops all remaining Mesa tests. Existing OMT tests remain required; OMT describes the installed desktop and is neither promoted nor published by this job.

After normal return, existing agent cleanup removes only a matching schema/job/kind-owned prefix. The currently running job prefix and any unit with unreadable or live recursive cgroup membership are preserved. A preserved or unreadable Mesa prefix cannot skip the independent kernel, one-shot and boot-entry cleanup: both cleanup paths are attempted and both errors remain reported. This is not a disk-wide cleanup or package rollback mechanism.

`--mesa-official-gpu` and its signing-public pin are reserved for the separately reviewed official 65-invocation adapter. This source increment refuses official execution explicitly and advertises `official_gpu=false`; its stub cannot run a partial suite. Installed desktop mode also remains refused until a package rollback, session restart and installed acceptance contract exists.

Host extraction/admission, lifetime, cancellation and simulator controls validate source behavior. They are not a physical Mac or staged-driver qualification. Deployment must retain the actual controller's version-metadata and artifact-durability fixes; this source branch alone does not authorize replacing that deployed provenance.
