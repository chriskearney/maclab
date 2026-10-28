# Volunteer and local-tool integration

This branch combines Malik's volunteer PR stack with the locally developed Mesa,
ESP-retention, workflow and installed-cohort tools. It is source integration for
review, not a controller deployment or a claim that every new combination has
been tested on a Mac.

## Included source and provenance

- Malik's rebased upstream PRs #20–#34, through
  `cadd3b03c111dba02bafa4388dc1e8491d0990cc`, retain their authors and history.
  They include named maintainers, remote enrollment, windows/pause, lock-screen
  handling, audit/access levels, leaving, named installs and reboot warnings.
- Malik's separate GRUB environment fix (#19), agent/domain configuration, and
  three research documents are included. The engineering issue-tracker reference
  is adjusted to this upstream repository. His older `p01`–`p16` and `volunteer`
  branches are historical predecessors of already merged work and this stack;
  their old versions are not replayed over newer fixes.
- The local Mesa job branch at `009a51b` is included with its pinned provider
  archive, render-check sources, GC protection and independent review controls.
  Official-GPU execution remains disabled pending its runtime qualification.
- The resumable workflow line through `75208c2`, bounded-cache successor
  `325c632`, artifact frontend `e5e18ca`, and family admission `4acef67` are
  included. Historical per-Mac recipes remain private inputs, not shipped data.
- ESP retention at `56849c6`, with the separately developed Limine 12.9.1
  compatibility follow-up `0ba5f2e`, is included. Retention still requires a
  durable, independently verified copy, protected-entry checks and reserves.
- Uncommitted local artifact sync/readback and version-metadata fixes, the
  pinned Limine recovery-default utility, package-identity publication guard,
  and independent tests are carried without changing their original worktrees.
  Earlier review-only patches already incorporated by successor branches are
  not applied a second time. The full-checkpoint replay remains an explicitly
  supplied-fixture test, not a fabricated hardware run.
- `tools/bt2` carries the generic controller/target source from local release
  `5ab0385adcec39e6` and its pinned native checker sources. Operational device
  profiles, credentials, frozen releases, binaries, run receipts, package
  archives and firmware are excluded. Test profiles and menus are fixtures.
  Scratch-only predecessors of this installed-cohort controller are superseded
  source experiments, not additional live execution paths.

## Composition fixes

Conflicts preserve named maintainer authentication and attribution, volunteer
windows/access/audit rules, the simulator's cancellable delay, lock-screen
readiness, lost-boot collection, and explicit network-only OOB isolation. New
Mesa staging/probes require Full access on a Volunteer Mac, including when its
access is lowered after submission. Recovery-policy overrides require Full too.
A failed recovery-policy persistence write restores the in-memory prior policy.

Artifact writes sync in bounded chunks and verify on-file size/hash before
commit. OMT publication requires a unique positive running-package identity.
Build metadata does not lower an agent's required release version. Newer named
install operations retain their 0.8.0 minimum.

Host portability fixes keep schedule tests away from an accidental DST boundary,
relocate pinned source references to the checkout under test, include synthetic
menu fixtures, and make the bt2 tests use the included native sources and fake
profiles. No operational profile is loaded by the fake-environment tests.

## Validation boundaries

Run the repository's normal `go vet ./...`, `go test -race ./...`, and `make all`.
Additional host suites:

```sh
python3 -B -m unittest discover -s internal/agent -p 'test_mesa*.py'
python3 -B -m unittest discover -s scripts/boot-test
python3 -B -m unittest discover -s scripts/workflow/m1
python3 -B -m unittest discover -s tools/bt2/tests
```

The workflow directory retains explicitly optional private historical-fixture
checks. A skip when those inputs are absent is not hardware qualification.
The bt2 package/state/controller tests use fake roots and mocked transports.
ESP retention tests need a durable test-temp filesystem: production code refuses
recovery archives on tmpfs. On Go versions whose `testing.T.TempDir` uses
`GOTMPDIR`, that variable must point to a durable filesystem for those tests.

The combined controller/agent tree has not been deployed, and no new target
boots or state changes are part of this PR. Keep review and normal integration
checks before deciding on a deployment. Existing qualification, restore and
recovery requirements remain meaningful after source conflicts are resolved.
