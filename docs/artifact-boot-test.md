# Test reviewed kernel, Mesa and boot artifacts

`lab boot-test` is a local artifact-to-workflow frontend. It inspects exact input files, compiles a reviewed device adapter, and invokes the actual `lab-workflow` runner with a plan-bound authorization. It does not install or restart a controller service. The controller must already advertise explicit job and transaction recovery-mode isolation.

## Build an isolated command prefix

```sh
make boot-test-dist BOOT_TEST_OUT=/owned/new-prefix
/owned/new-prefix/bin/lab boot-test --help
```

The prefix contains `bin/lab`, `bin/lab-workflow`, `bin/lab-boot-test`, and the Python resource bundle under `share/maclab/boot-test`. The Go dispatcher resolves resources relative to its actual executable. Linux Python 3.14 or newer with `compression.zstd` is required. Building this prefix does not contact a Mac or install packages/services. No runtime resource is located through a developer's temporary source path.

Device compiler/owner closures, catalogs, recipes and per-run artifacts remain explicit source-reviewed inputs. Install a separately reviewed source package into a new private durable prefix:

```sh
lab boot-test profile-bundle install --archive reviewed-source-package.tar.gz \
  --sha256 EXACT_SHA256 --bytes EXACT_LENGTH --prefix /owned/durable/profile-prefix
```

The installer validates a finite regular-only archive and each exact member, writes at most 1 MiB between checked fsync calls, reopens and hashes every output, and syncs directories. It refuses overwrites, partial-prefix adoption, links, path traversal, unknown members and volatile installation. A failed write leaves its partial prefix as evidence; it does not retry. `--validation-only` permits CPU tests on volatile storage and records that no durable installation occurred.

Only explicit source-descriptor JSON paths relocate; source text, target paths, historical freezes and baseline claims are preserved. The installed `COMPONENTS.json` pins the actual current source set. Its compiler resolves fixed logical component roles relative to that descriptor, without reading the original developer session. A profile package can generate `profile.CLOSED.json` and `catalog.CLOSED.json` containing the new exact paths, but their review stays closed and execution remains disabled. Installation neither approves source nor creates a Plan authorization. Review the installed pins and actual restoration contract before selecting them for an execution request. Existing durable baseline files are explicit, independently checked prerequisites; relocating a source closure does not fabricate a new baseline.

The initial M1 package is limited to its fixed reviewed artifact tuple. Historical Air/M3 prototypes are not executable profiles and arbitrary artifact tuples remain unsupported. A package containing an older owner algorithm retains that algorithm's known limitations; packaging it does not qualify or fix its behavior.

## Prepare an immutable Plan

```sh
lab boot-test --catalog-descriptor catalog.pin.json --profile PROFILE_ID \
  --request request.json --review-descriptor source-review.pin.json \
  --packet /var/lib/maclab/rc7-DEVICE-UNIQUE --out NEW_PRIVATE_DIRECTORY --compile
```

A request contains an explicit device, `recovery_mode` (`network-only` or `serial-assisted`), and an exact `artifacts` map from profile slot names to local files. The equivalent named flags are `--kernel`, `--kernel-headers`, repeated `--mesa-package name=path`, `--bootloader`, and `--artifact name=path`; their roles come from the selected profile. A boot-setup package and a raw Stage2 artifact are different slot kinds. Supplying one never proves execution of the other.

Preparation makes no API or target calls. It hashes the actual files and safely scans bounded archive metadata without extracting or executing package scripts. It checks exact package name/version/architecture and optional selected kernel Image, config and native-provider payload hashes. Malformed paths, duplicates, wrong versions, unexpected special entries, changed files or incomplete reviewed payloads are refused. Source metadata does not prove a running kernel, firmware or GPU driver. Actual child stdout/stderr and failure records stay private and bounded.

Every descriptor is `{path, sha256, bytes}` with an absolute canonical path. Catalog/profile/source files must be owned regular files without group/world write permission. The catalog selects an exact profile descriptor; the review selects the catalog, profile, compiler, helper/interpreter closure, metadata tool, runner and recipe. `ROOT_SOURCE_REVIEWED` is an assertion in a root-selected exact input, not automatic source review or a cryptographic signature. Closed review data is refused.

## Execute the reviewed Plan

```sh
lab boot-test --prepared NEW_PRIVATE_DIRECTORY --execute \
  --authorization plan-authorization.json --state PRIVATE_DURABLE_STATE
```

The existing authorization must bind the exact final Plan and allowed scopes. A single command may also prepare then execute if it already has an authorization matching the resulting Plan. There is no interactive permission prompt or blind retry.

Before any target helper the frontend verifies advertised mode isolation and the actual ordinary idle device/model/original kernel, acquires or renews only its reviewed holder's lease, explicitly selects the requested recovery transaction, and reads it back. Network-only makes no OOB readiness claim. Serial-assisted additionally requires an actual connected route. Physical/manual recovery facts are never fabricated. An ambiguous state-changing response is retained and observed, not automatically repeated.

The runner retains finite phase outcomes, source/artifact identity and genuine failure/cancellation evidence. Its owned process group, logs, waits and total runtime are bounded. State defaults to `~/.local/share/maclab/workflows/TRANSACTION`; volatile filesystems are refused and actual fsync/readback is checked. An I/O failure stops the operation; the command does not repair a filesystem or assert prior errors are fixed.

Lease release requires the actual completed restoration verdict, full original audit, current ordinary original boot, and owned lease. A sole final test assertion may fail after all restoration phases completed: this releases the lease but returns a nonzero `TESTS_FAILED_RESTORED_LEASE_RELEASED`. Earlier or incomplete restoration retains the lease for explicit recovery. `FAILURE.json` supplements rather than overwrites the first result and reports the private attempt directory.

## Device adapter boundary

A `maclab.device-test-profile/1` supplies exact device/board/model and original installed or custom kernel, all expected package versions and originally absent packages, candidate artifact slots, capture/owner/rollback/final-restore source pins, and a finite compiler entry. Its restore contract fixes required phase order and actual audit/verdict/final-assertion selectors with packet/Plan/boot identity. Originally absent packages need explicit actual absence checks.

The compiler receives the reviewed profile and actual artifact metadata. It must emit the same restoration contract and reviewed device/mode/transaction; every helper, interpreter and closure must match reviewed pins. Legacy `compile_oneshot` remains limited to its existing fixed tuple. A data-bound `compile_device` adapter may admit another reviewed tuple only if its actual owner logic supports it. Pending profiles are unsupported and never silently substituted with M1.

Raw Stage2 support additionally requires its exact four-member bundle, eight native identity pins, reviewed risk/retention policy and actual live Stage1/Stage2 evidence before and after the job. Disk bytes alone do not prove loader execution. No firmware, ANE, SEP, TouchID or Stage1 scope is waived.

The frontend does not define one universal test battery, promote references, publish results, or make an RC qualification claim. The selected reviewed adapter defines actual test and restore coverage. Source-shaped CPU fixtures are not hardware passes; a newly converted profile needs its own genuine execution proof.
