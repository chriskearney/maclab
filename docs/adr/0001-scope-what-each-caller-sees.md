---
status: accepted
---

# labd scopes every request to the Macs its caller may see

A Volunteer's Mac must not reach any other Mac, a Volunteer's or Lab-owned. Today any tailnet peer, a Volunteer's Mac included, is a viewer of the whole fleet: device records with other Volunteers' contacts and notice topics, every job file, saved screens, the event stream, and the live journal of Lab-owned Macs. We decided that labd resolves exactly one caller per request (Maintainer by token, a person by an untagged tailnet login, a Mac by its device secret, the builder) and that one module answers, for every route, whether that caller may see or act on a given Mac, job, job file, screen, artifact or event. Only Maintainers see the whole fleet; a Volunteer sees only their own Macs while they stay enrolled; a Mac sees only itself and the artifacts its own job was sent; a tagged tailnet peer without a token sees nothing.

## Considered Options

- **Fence it at the network only** (tag Volunteer Macs and fence them with tailnet ACLs, or take them off the tailnet behind an agent-only TLS listener). Rejected as the primary fix: it leaves the Volunteer's other devices as fleet-wide viewers, and labd would still hand out everything to whatever reaches it. Either may follow as a second layer.
- **Patch each route.** Rejected: the checks that exist (watching gate, Access level, upload device check) are already scattered across handlers, each re-joining caller and target by hand, and a new route that forgets one leaks silently.
- **Let a Volunteer see Lab-owned Macs too.** Rejected: Lab-owned Macs' journals can carry sudo lines, and nothing a Volunteer does needs them; a tokenless browser already shows an empty dashboard.

## Consequences

- Every route declares the kind of resource it touches and its action, or it cannot be registered; a short allow-list covers routes that touch none.
- Out-of-scope resources answer 404, so Mac names and job IDs aren't revealed.
- The ntfy topic, contact and OOB URL of a Mac are shown only to Maintainers and that Mac's own Volunteer.
- Builds, builders, Installed run status and capability endpoints are Maintainer-only.
- `/api/auth` still reports `viewer` for a person, so `./volunteer` keeps working; README's description of what tailnet viewers see changes.
- The existing action checks (Access level, window and held gating, upload) move inside the same module; their rules don't change.
