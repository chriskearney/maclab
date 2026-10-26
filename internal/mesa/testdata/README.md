# Official suite archive fixture

`official-archive.tar.gz` is the unchanged 372,821-byte qualified native tester
archive, SHA256 `f209493b34e13e2985b1752c147a33a9a45e3e2eac99eb9606ae5a664c252f99`,
source commit `e81d80938876c906b64c4e3f31f76c6c33ba95b1`. It contains Python
schema/validation source and the ARM64 helper
`059ccbce35f2154bc4c62984bddcbb1c4dabd6ad8e4d580482233412f52a8af0`.

Host tests inspect the archive and exercise source-backed schema, oracle, ordering,
statistics and cryptographic validation. They never execute the native ELF or
submit GPU work. Actual GPU/systemd actors are explicitly substituted. The
production agent fetches this hash through authenticated CAS and independently
checks it; this fixture path is not a production fallback. Workload source,
helper bytes and archive remain unchanged. This fixture is not new device
qualification or permission to deploy/enable the optional capability.
