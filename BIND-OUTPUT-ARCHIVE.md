This standalone runner successor preserves the existing Plan and authorization
contract. It requires an explicit root-reviewed runner replacement receipt; it
is not the original b1819e04 binary and does not change a daemon or agent.

Only completed bind records with a declared downstream consumer may hold an
optional `output_pin`. The full original canonical JSON is retained privately
under `STATE/bind-outputs/<original_output_sha256>.json`. The pin contains the
absolute path, same SHA256, and exact byte count. Attempt, timing, authorization,
request hash, original output hash and completed status are retained verbatim.
Helper/wait outputs and terminal leaf assertions remain inline, including the
frontend's final audit, verdict and final assertion inputs.

Archive files use held regular-inode checks, exact owner/private mode and link
count, a bounded canonical JSON read, original hash equality, exclusive link
publication, fsync and full reopen verification. Existing foreign files refuse
rather than being overwritten. Open and Status hydrate and validate pins before
the existing output checks and binding resolution. Saving serializes a cold copy;
it does not replace the in-memory evidence with a synthetic descriptor output.
A failure leaves the previous durable state intact. Full per-file/per-phase and
checkpoint bounds remain 4 MiB; the phase limit remains 256.

This retains local evidence; it does not claim independent hardware durability
or repair controller Btrfs corruption. Root owns independent proof retention.
Old binaries that do not understand output_pin must not be used to resume an
archived checkpoint. Existing inline checkpoints remain supported. Expired
observations remain expired: the runner neither refreshes their timestamps nor
reinterprets failed target work as passed.

The R2 successor additionally accepts the explicit reconciliation decision
`refresh-observation` for one completed, non-mutating helper. It requires the
exact old attempt/request, reviewed receipt/evidence and new bounded actual
output. It refuses any transitive completed consumer or already-attempted
mutating consumer. Full previous Record and exact new receipt are published
exclusively and synchronized before the checkpoint update, using names bound to
old attempt and full receipt SHA. A distinct receipt-derived attempt identifies
the reconciled observation. Original request/auth hashes stay unchanged. A
pending failure in a different phase stays pending; refresh does not reset it,
replay it or waive downstream freshness checks. This operation is not available
for mutating helpers, binding computations, jobs or already consumed evidence.
