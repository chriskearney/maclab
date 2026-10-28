# Which Tailscale mechanism joins a Volunteer's Mac to labd

Research for issue #2 (part of #1; blocks #6). Researched 2026-10-25.
This note gathers facts and states a leaning; the decision belongs to the Maintainers.

Vocabulary follows `CONTEXT.md`: **Volunteer**, **Maintainer**, **Availability window**, and so on.

Housekeeping: `docs/agents/issue-tracker.md` does not exist in this worktree, so no tracker conventions were applied. This file lives in `docs/research/` as the ticket asked.

## 1. Connection direction today (repo facts)

- The agent only dials out. `lab-agent` enrolls with `POST /api/agent/enroll`, then long-polls `POST /api/agent/checkin?wait_ms=10000`. It also calls `/api/agent/report`, `/api/agent/artifacts/{sha}`, `/api/agent/upload` and `/api/agent/screen` (`internal/agent/agent.go`; routes in `internal/server/server.go` lines 333-357).
- The agent has no listener: a search for `Listen`/`Serve` over `internal/agent` and `cmd/lab-agent` finds nothing. labd never dials a Mac. Commands such as `lab_exec` ride back inside the held check-in response (`agent.go` "The heartbeat is a long poll: labd holds it"; `internal/server/exec.go`). Only labd listens (`cmd/labd/main.go`, `--listen :7770`).
- So the network policy needed today is one-directional: **Mac -> labd:7770 (TCP)**. labd -> Mac needs nothing.
- Caveat: labd listens on `:7770` on all interfaces by default, and `--trust` judges `r.RemoteAddr` only (README, "Phones and the LAN"). For "reachable only over Tailscale", labd should bind its tailscale address or sit behind a host firewall, whichever mechanism is chosen.

## 2. Comparison

| | (a) Invite Volunteer as user of Maintainers' tailnet | (b) Share labd node into Volunteer's own tailnet | (c) Tagged pre-auth key into Maintainers' tailnet |
|---|---|---|---|
| Volunteer steps | Install tailscale, accept invite, sign in with own IdP; the Mac is a user-owned node | Run tailscale in their own tailnet, accept share link as an Owner/Admin/IT admin of it | Install tailscale, `tailscale up --auth-key=...`; no Tailscale account needed |
| Identity on the wire | The Volunteer's user | The Volunteer's user (shared-in user) | A tag, e.g. `tag:volunteer-mac`; no user |
| Mac reaches only labd:7770 | Yes, ACL keyed on user/group; scoped to the person, not the Mac | Yes, ACL with `src` = Volunteer's email or `autogroup:shared`; scoped to the person on any of their devices | Yes, `src: tag:volunteer-mac`, `dst: tag:labd:7770`; scoped to the device |
| labd -> Mac | Only if an ACL allows; not needed | Not possible by default (quarantine); needs mutual sharing; not needed | Only if an ACL allows; not needed |
| Revocation | Suspend/remove user | Revoke share, immediate | Delete the node (revoking the key alone does not) |
| Free plan pressure | Counts against 6 users | None on Maintainers' side | Counts as a tagged resource (50 included) |

### 2a. Invite the Volunteer as a user

- Steps: an Owner/Admin/IT admin sends invites from the Users page; tailnets on shared domains such as gmail.com use an invite link instead. Invitees install the client and sign in with an identity provider or passkey. Unused invites expire after 90 days; with user approval on, a Maintainer approves first. <https://tailscale.com/kb/1064/invite-team-members>
- Limits: Personal plan is "Up to 6 users" with "Unlimited user devices", and "only suitable for non-commercial use". <https://tailscale.com/pricing> Billing "includes invited users who join and transfer data in your tailnet"; whether pending invites count is not stated. <https://tailscale.com/kb/1064/invite-team-members> The 6 users include the Maintainers, so this does not scale to a fleet of Volunteers.
- Restriction: ACLs are deny-by-default once a policy exists, directional (a rule A->B does not allow B->A), and `dst` takes `host:port`, including a single port. <https://tailscale.com/kb/1018/acls> Grants are the newer syntax, with "Prefer grants for access control policies" <https://tailscale.com/kb/1337/grants>; the page does not state free-plan availability.
- Revocation: remove or suspend the user; "removing the user removes their devices". <https://tailscale.com/docs/concepts/tailscale-identity> The invite page covers only deleting pending invites.
- Initiating back: members are ordinary nodes; ACLs decide.
- Downside: the whole Volunteer account joins the Maintainers' tailnet, and any other device they sign in with does too.

### 2b. Share labd into the Volunteer's tailnet

- Steps: a Maintainer (Owner/Admin/IT admin) shares the labd machine via single-use email invite or a link reusable up to 1,000 times; unused links expire after 30 days. The recipient must also be Owner/Admin/IT admin of their tailnet, accepts, and reaches labd by its full MagicDNS name `<host>.<tailnet>.ts.net` (short names do not work for shared-in nodes). With Tailnet Lock, their nodes must be signed first. <https://tailscale.com/kb/1084/sharing>, <https://tailscale.com/kb/1081/magicdns>
- Limits: the sharing page says it is available on all plans and lists no free-plan cap besides the 1,000-use link limit. It does not consume Maintainer user slots. (Pricing page is silent on sharing.)
- Restriction: "A shared-in user's requests are subject to the access control policies of the tailnet that owns the shared machine." Rules name the recipient's email or `autogroup:shared`; tags, groups and subnet info are stripped, and tags are not exposed to the other tailnet. `src: ["*"]` also covers shared users, which the page warns against. <https://tailscale.com/kb/1084/sharing> Sharing is to a user, not a device, so it cannot pin the Mac at the network layer.
- Revocation: Machines page, Share > Revoke invite; access ends immediately and needs a new invite to restore. <https://tailscale.com/kb/1084/sharing>
- Initiating back: "Shared machines are quarantined: they can receive incoming connections but can't start them." Here labd is the shared machine, so labd cannot initiate to the Volunteer's tailnet; the Volunteer's side initiates. Mutual sharing is the only route for labd -> Mac. This matches today's one-way flow. <https://tailscale.com/kb/1084/sharing>
- Side effects: Maintainers see the Volunteer's email and avatar. The Volunteer needs their own tailnet, which is extra setup for a casual Volunteer, and the agent URL must be the full `*.ts.net` name.

### 2c. Tagged pre-auth key into the Maintainers' tailnet

- Steps: a Maintainer mints a key (one-off or reusable; ephemeral, pre-approved and tags options; 1-90 days, default 90). A device using a tagged key "assumes the identity of the auth key's tags". Keys can be created through the API using an OAuth client. <https://tailscale.com/kb/1085/auth-keys>
- Tags: a node has a user or tags, never both; tagged nodes are not tied to a user (removing a user does not remove them); key expiry is disabled by default for tagged nodes; only tag owners, or Owner/Admin/Network admin, can apply a tag; tags are defined in `tagOwners`. <https://tailscale.com/kb/1068/tags>
- Limits: Personal plan "Up to 50 tagged resources to start. Additional tagged resources cost $1/month each", "Up to 3 ACL groups", ephemeral resources 1,000 minutes a month. <https://tailscale.com/pricing> Uses no user slots. That a Volunteer's Mac counts as a "tagged resource" is inferred from the pricing wording; confirm in the admin console.
- Restriction: finest grained, `src: tag:volunteer-mac`, `dst: tag:labd:7770`, one-way unless a reverse rule is added. <https://tailscale.com/kb/1018/acls>
- Revocation: "Already-registered devices remain authorized. Revoking only stops new use of the key"; deauthorize by deleting the device from the Machines page. One-off keys are auto-revoked after use. <https://tailscale.com/kb/1085/auth-keys>
- Risks: the Mac holds a node key into the Maintainers' tailnet on a machine they do not control, and a stolen reusable key lets anyone join as that tag (the docs call reusable keys dangerous if stolen). Use one-off keys, one per enrolled Mac. That pairs naturally with the existing per-Mac `enr_...` token, but minting both together is new Maintainer-side work.
- Initiating back: governed by ACLs alone, no quarantine.

## 3. Packaging and running on Asahi / Omarchy

- Arch Linux ARM carries `tailscale` for aarch64: 1.104.2-1, repo `extra`, depends on glibc. <https://archlinuxarm.org/packages/aarch64/tailscale>. The package file-list page returned HTTP 500, so the shipped `tailscaled.service` was not confirmed.
- Tailscale's Linux install page lists Arch under "Other distributions" and links to the Arch wiki; static binaries exist per CPU architecture and the tarball includes systemd units in `systemd/`. <https://tailscale.com/kb/1031/install-linux> The Arch wiki fetch was blocked by an anti-bot page, so wiki details were not read.
- Not verified by this research: that `tailscaled` runs under systemd on an actual Asahi (16K page kernel) machine with the `tun` device. Nothing Apple-specific is expected, since it is a Go userspace daemon, but a one-Mac test is cheap: `pacman -S tailscale && systemctl enable --now tailscaled && tailscale up`.

## 4. What LocalAPI `whois` returns

Interface: `GET /localapi/v0/whois?addr=<ip:port>` on tailscaled; Go client `tailscale.WhoIs`. The response type is `apitype.WhoIsResponse` with `Node *tailcfg.Node`, `UserProfile *tailcfg.UserProfile` and `CapMap`; "In successful whois responses, Node and UserProfile are never nil." <https://github.com/tailscale/tailscale/blob/main/client/tailscale/apitype/apitype.go>

`LocalBackend.WhoIs` finds the node by address in the netmap and then resolves `UserByID(n.User())`; it fails if there is no netmap, node or user profile. <https://github.com/tailscale/tailscale/blob/main/ipn/ipnlocal/local.go>

Relevant `tailcfg.Node` / `UserProfile` fields (<https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go>):

- `User`: "the user who created the node. If ACL tags are in use for the node then it doesn't reflect the ACL identity that the node is running as."
- `Sharer`: "if non-zero, is the user who shared this node, if different than User."
- `Tags`: ACL tags of the form `tag:<value>`; `IsTagged()` reports whether any.
- `Name` is the FQDN / MagicDNS name. `ComputedName` is the base name for normal nodes and the FQDN for shared-in nodes.
- `UserProfile.LoginName` (for example `alice@smith.com`, display only, no provider) and `DisplayName`.

What labd would see when the Mac connects:

| | Login | Tags | Node name |
|---|---|---|---|
| (a) invited user | the Volunteer's login | none | MagicDNS name in the Maintainers' tailnet |
| (b) shared | the Volunteer's email is what ACLs match and what the Share dialog shows; the exact whois fields for a sharee connecting to the sharer's node (`User` vs `Sharer`, name form) are not documented in the sources read | none (tags are not exposed across tailnets) | the Volunteer's tailnet-side name; unconfirmed |
| (c) tagged | no user: "The identity used for any Tailscale connection by a tagged device is the set of tags assigned to the device", and Serve identity headers are "populated only for users, not tagged devices". <https://tailscale.com/docs/concepts/tailscale-identity> The sources do not say what `UserProfile` holds for a tagged node | e.g. `["tag:volunteer-mac"]` | MagicDNS name in the Maintainers' tailnet |

Implication for the identity-model ticket (#6): under (c) whois can identify only the tag and the node (name, node key), so a per-Volunteer or per-Mac identity must come from the node name or from lab's own enrollment secret, which `s.agent` already checks. Under (a) and (b) whois gives the Volunteer's login, but one login can own several Macs, so the node name or the secret is still needed to name the Mac. Whois is a good second factor but not a substitute for the agent secret.

## 5. Recommendation (the human decides)

Lean toward **(c): a one-off tagged pre-auth key per Volunteer Mac**, with ACL `tag:volunteer-mac -> tag:labd:7770` only, and labd bound to its tailscale address.

Reasons: it is the only option that does not spend the free plan's 6 user slots, it scopes access to the device rather than the person, it is revoked per Mac by deleting a node, and the Volunteer needs no Tailscale account or tailnet.

**(b)** is the best alternative if Maintainers do not want a Volunteer's machine holding a key into their tailnet. Its quarantine property matches the one-way traffic, but the Volunteer must run their own tailnet as an admin, access is by person, and the agent must use the full `*.ts.net` name. **(a)** is least attractive: it hits the 6-user cap fast and brings the Volunteer's whole account into the Maintainers' tailnet.

## 6. Open trade-offs and unverified items

- Trust: with (c) the node key sits on a Volunteer's machine. The bound is the ACL, and the default policy is allow-all, so the ACL must be written, and builder/oobd must be tagged and fenced too.
- Cost: (c) is capped at 50 included tagged resources, then $1 per resource per month; the Personal plan is non-commercial only. Confirm how tagged resources are counted.
- Grants vs ACLs: grants are recommended by the docs, but free-plan availability was not stated; `tagOwners` and ACLs are listed as available on all plans.
- Not verified: `tailscaled` on real Asahi hardware, the ALARM unit file, and the exact whois output for tagged and shared peers. Suggest a short empirical test of each mechanism with `curl --unix-socket /var/run/tailscale/tailscaled.sock 'http://local-tailscaled.sock/localapi/v0/whois?addr=<ip:port>'` before #6 commits.
- Key minting: automating (c) via OAuth client + API and bundling it into `lab enroll` is follow-up work.
- If labd ever needs to reach into a Mac (not so today), plain (b) is ruled out and mutual sharing would be needed.
