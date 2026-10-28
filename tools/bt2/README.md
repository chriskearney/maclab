# Journaled installed-cohort boot tests

`bt2-cli` runs a pinned kernel/Mesa/Stage2 package cohort through an explicit
capture, independent retention, baseline, candidate and exact rollback journal.
It can resume restoration after interruption. See SPEC.md and CONTRACT.md.

This source snapshot comes from the locally qualified 5ab0385adcec39e6 release.
It is included for review; this combined Maclab branch has not been deployed or
boot-qualified. No live profiles, credentials, package archives, run receipts,
firmware or saved system state are shipped. Supply reviewed operational profiles
with `--devices-dir`; tests/devices contains fake-environment fixtures only.

Native checker sources are included and retain their content pins. Tool binaries
and device package archives must be supplied through the normal reviewed path.
Run fake-root tests from this directory with `python3 -B -m unittest discover -s tests`.
These tests use mocked transports and fake package/system tools, never a Mac.
Do not interpret a host-test pass as authorization for a target run.
