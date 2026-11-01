---
status: accepted
---

# labd is an ordinary HTTPS service; Macs join by a one-time invite

Maclab grew up on a LAN and then a tailnet: labd spoke plain HTTP, and Tailscale gave both the encryption and, with `--tailscale`, the identity of anyone looking. To run labd as a normal internet service (a Kubernetes workload on its own host, `https://maclab.chonkbase.net`) with Macs anywhere joining it, we decided that labd serves HTTPS itself or behind a trusted reverse proxy, under one public URL (whose path, if it has one, is labd's prefix on a shared host), and that the transport stays REST: long-poll check-ins for the Macs and server-sent events for browsers, with no WebSockets, since both already carry everything outbound through any proxy. Identity stays token-based and independent of the network: a Maintainer's named token, a Mac's device secret, the builder's token, and one-time enrollment tokens. Forwarded headers and source addresses are never identity. A Mac joins by an owner-made one-liner that keeps the token out of URLs, logs and command lines, shows the lab's participation terms, and enrolls once; the token is bound to that Mac's activation key. Because Macs may now be on the internet, a Mac's device secret reaches only its own enrollment's running job: its artifacts (job grants, adapted from Naeem Malik's maclab PR #53) and its files, plus what a Maintainer grants it explicitly for a while.

## Considered options

- **Keep Tailscale for everyone.** Rejected as the requirement: Volunteers and Macs should need nothing but HTTPS.
- **WebSockets for control.** Rejected: long polls and SSE already work through ordinary proxies; a second protocol would add a dependency and a separate origin and revocation story with no use case it fixes.
- **Accounts for Volunteers now.** Deferred: Volunteers manage their Mac through lab-agent on it; a web portal for them needs the per-caller scope work (maclab #51) and its prior-owner and stale-owner fixes first.
- **An ingress that strips the prefix.** Rejected: labd builds browser and enrollment URLs from its public URL; one prefix contract, handled once by labd, leaves nothing to drift.

## Consequences

- Plain HTTP is served only on loopback unless `--allow-plain-http`; clients refuse plain HTTP beyond loopback unless allowed, except an agent.json written before this change, which keeps working with a warning.
- A path prefix is not an origin: the browser token is readable by any app on the same host. labd gets a host of its own; a prefix on a shared host is supported only for equally trusted neighbours.
- Artifact grants live in memory; a labd restart ends running jobs and their grants. An interrupted activation can resume only while labd keeps running.
- labd in the cloud can't reach oobd on the lab's network: those Macs run without out-of-band reset unless a private route is added.
