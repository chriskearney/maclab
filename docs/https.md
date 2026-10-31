# labd over HTTPS, without Tailscale

labd can run as a plain HTTPS service. Maintainers use the web UI, `lab` and its MCP server over HTTPS. Macs reach labd with
outbound requests only: check-in long polls, reports, uploads, and artifact downloads with resume. There are no WebSockets,
and nothing connects *to* a Mac. Tailscale still works as before, but nothing here needs it.

The main deployment is a Kubernetes workload at **https://maclab.chonkbase.net**, labd's own origin on the cluster that serves
chonkbase.net. `https://chonkbase.net/maclab` remains a supported compatibility layout. A reverse proxy or labd's own TLS work
too (see [Other ways to serve HTTPS](#other-ways-to-serve-https)).

## labd's flags for HTTPS

| flag | what it does |
|---|---|
| `--public-url https://host[:port][/path]` | The one external URL. labd serves everything under its path, removing the path exactly once, and builds browser and enrollment URLs from it. Without it, labd serves at `/` |
| `--trusted-proxy CIDR[,CIDR]` | The only peers whose `X-Forwarded-Proto`/`X-Forwarded-Host` labd reads. Those headers must match `--public-url`, or labd answers 421. They are never identity. Refused together with `--tailscale` |
| `--tls-cert FILE --tls-key FILE` | labd serves TLS itself (1.2+, HTTP/2) and re-reads the files when they change |
| `--allow-plain-http` | Allows plain HTTP on a non-loopback `--listen`. Use it behind a proxy inside a private network. Without it, a non-loopback `--listen` without TLS is refused |
| `--terms-file FILE` | The terms a Mac's owner accepts before setup. Without it, labd uses its built-in terms |

`X-Forwarded-Prefix` is never read. A request outside the `--public-url` path gets 404, and so does `/maclabx` for `/maclab`.
A non-canonical path under the prefix (`//`, `/./`, `/../`) is 404 too, and any redirect labd makes keeps the prefix.

`GET <prefix>/healthz` answers 200 `ok` with no credentials, for health checks. A request from a `--trusted-proxy` address must
still name the public origin in `X-Forwarded-Proto`/`X-Forwarded-Host`, or it gets 421; the manifests' probes always send both.

## Kubernetes at maclab.chonkbase.net

The manifests are in `deploy/k8s/`:
- `base/` is the deployment at **https://maclab.chonkbase.net**, served at `/`.
- `path-prefix/` is the compatibility layout at `https://chonkbase.net/maclab` (see [Origin and trust](#origin-and-trust)).
- `terms/` supplies your own terms text.

They follow the cluster's existing conventions (the chonkbase and slopblender namespaces on the same LKE cluster):
- ingress-nginx;
- cert-manager's `letsencrypt-production` ClusterIssuer (DNS-01 through the Linode webhook);
- `linode-block-storage-retain`;
- images in `ghcr.io/iconidentify` with the `ghcr-secret` pull secret.

### DNS: straight to the ingress, no CDN proxy
- `maclab.chonkbase.net` needs an A (and AAAA, if the ingress has one) record in the chonkbase.net zone, pointing at the
  ingress-nginx LoadBalancer address. That is the same address `api.chonkbase.net` and `app.chonkbase.net` use; the zone is
  on Linode DNS, as the DNS-01 issuer needs.
- Keep it a plain DNS record. **Don't put a proxying CDN in front of it.** A synchronous `lab exec` can be silent for up to
  about an hour (3630 s), and the event stream, console and long polls stay open. Common CDN proxies cut an idle request far
  sooner (often after 100 s).
- If a proxy must sit in front, its read timeout must exceed 3700 s and it must not buffer streams. Otherwise `lab exec` fails at
  the proxy while the command keeps running on the Mac.
- The Ingress's own timeouts (3700 s) already cover this.

### Origin and trust
- On `maclab.chonkbase.net`, the UI's token storage (`localStorage`) belongs to labd's origin alone. Pages on chonkbase.net and
  its other subdomains can't read it. That is why it is the default.
- The `path-prefix/` layout serves labd at `https://chonkbase.net/maclab`. A path is not an origin: the token then lives in the
  storage of the whole origin `https://chonkbase.net`, and any script served from any path there can read it, call labd's API
  with it, or frame `/maclab`.
- So use that layout only when every app on chonkbase.net is trusted as much as labd. Today that means:
  - the chonkbase frontend at `/`;
  - slopblender at `/slopblender` until it is removed. It serves other people's uploads on that origin, under its own
    allow-list, `nosniff` and `sandbox` CSP (its README, "Security notes").

### What the manifests set
- **One writer.** SQLite (WAL mode) on a ReadWriteOnce volume means `replicas: 1` and `strategy: Recreate`. A rollout stops the
  old pod before the new one starts, so two labds never open the same data. Never scale it above 1.
- **State:** one PVC at `/data` (60 Gi). It holds:
  - `labd.db` with its `-wal` and `-shm`;
  - the `artifacts/` store (capped by `--artifact-budget-gb`, 20 GiB by default);
  - `jobs/ builds/ frozen/ baselines/ screens/ serial/ audit/`;
  - `admin.token` and `builder.token`.
- **Pod:**
  - uid/gid 10001, `fsGroup` 10001 (the volume is the pod user's, not root's);
  - a read-only root filesystem, all capabilities dropped, the RuntimeDefault seccomp profile;
  - no service-account token;
  - no hostPath, and nothing from i9beef.
- **labd's args:** `--listen=0.0.0.0:7770 --allow-plain-http --data=/data --public-url=https://maclab.chonkbase.net --trusted-proxy=<CIDR> --maintainer=chris`
  (`path-prefix/` changes `--public-url` to `https://chonkbase.net/maclab`).
  Plain HTTP stays inside the cluster, from the ingress controller only; TLS ends at the Ingress.
- **Ingress:**
  - host `maclab.chonkbase.net`, path `/` (`path-prefix/`: host `chonkbase.net`, path `/maclab`), passed through **unchanged**: no
    rewrite-target, no snippet;
  - `proxy-read-timeout`/`proxy-send-timeout` 3700 s (`lab exec` is synchronous for up to 3630 s);
  - `proxy-buffering off` (the event stream, serial console and build log are streamed);
  - `proxy-request-buffering off`, `proxy-body-size 4g`.
- **NetworkPolicy:**
  - in: only from the `ingress-nginx` namespace;
  - out: DNS, and public port 443 (git for GitHub refs, ntfy, omarchy-m-testing.org);
  - nothing private.
- **No Secret in the manifests.** The tokens are made in `/data` on the first start, or come with migrated data. labd logs only the
  token file's *path* (`log in with lab login <url> "$(cat /data/admin.token)"`), never a token.

### Before the first apply: two values to set
1. **The image, by digest.**
   - Publish a commit on main with `gh workflow run publish.yml -f commit=<full sha>` (Actions > publish > Run workflow). It:
     - builds that commit for linux/amd64 and runs the image smoke at both URLs;
     - pushes `ghcr.io/chriskearney/maclab:<full sha>` (there's no moving tag, and it refuses to re-push a tag that exists);
     - reads it back and prints `ghcr.io/chriskearney/maclab@sha256:<digest>` in the job summary.
   - Pin that digest, not a tag:
     `cd deploy/k8s/base && kustomize edit set image maclab=ghcr.io/chriskearney/maclab@sha256:<digest>`, or put `digest:` in place
     of `newTag` in its `images:` entry.
   - **Pull secret:** a public package needs none, so remove the Deployment's `imagePullSecrets`. A private one needs a pull secret named
     `ghcr-secret` in the `maclab` namespace whose token can read `ghcr.io/chriskearney/maclab`. Check that access before you rely on it.
2. **The trusted proxy.** `--trusted-proxy` must name the addresses the ingress-nginx controller's pods connect *from*: the
   cluster's pod network.
   - Find it with `kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'` and `kubectl -n ingress-nginx get pods -o wide`.
   - The shipped value, `SET-INGRESS-NGINX-POD-CIDR`, is deliberately not a CIDR, so labd refuses to start until it is set.
   - The NetworkPolicy keeps every other pod in that range away from labd, so trusting the range trusts only the controller.

- **Probes:** readiness and liveness on `/healthz` (`/maclab/healthz` for `path-prefix/`). Each names the public origin in
  `X-Forwarded-Proto`/`X-Forwarded-Host`, which labd needs if the probe's source address falls inside `--trusted-proxy`.

Render with `kubectl kustomize deploy/k8s/base` (or `deploy/k8s/path-prefix`) and check it. `deploy/k8s/test_manifests.py` runs the same checks offline.
Apply in this order:
1. the DNS record (above), then namespace, PVC, Certificate;
2. wait for `certificate/maclab-tls` to be Ready;
3. Service, NetworkPolicy, Ingress, Deployment.

### Terms, and inviting a Mac
- A Mac's owner accepts labd's terms before anything is installed. Their version is the sha256 of the exact text, and labd records
  the accepted version and the time with the Mac.
  - To use your own text, put it in `deploy/k8s/terms/terms.txt` and deploy `deploy/k8s/terms`. That mounts it from a ConfigMap
    and adds `--terms-file`.
  - A changed text gets a new sha256. labd refuses an enrollment that accepted any other version.
- A Maintainer runs `lab enroll <name> --volunteer "<name>" --contact <c>`, or uses the web UI. labd answers with a **one-line join command**.
  - It holds a one-time activation token, `enr_…`, valid for 24 h. The token travels only in an `Authorization` header, never in a URL,
    and is in no process's arguments: curl reads that header on stdin (`-H @-`), and setup reads the token on stdin too.
  - The command starts with a space, so shells that skip such lines (bash with `HISTCONTROL=ignorespace`) leave it out of history.
  - It downloads lab-agent over https, checks its sha256, and runs `sudo lab-agent setup --server https://maclab.chonkbase.net --token-stdin`.
  - Where the UI or `lab enroll` can't make the one-liner, they show the fallback: `printf '%s\n' '<token>' | sudo ./lab-agent setup --token-stdin …`.
- `lab-agent setup` shows the terms and needs a typed `yes` on the terminal **before it changes anything**.
  - Without a terminal it stops, unless `--accept-terms <sha256>` names the exact current terms (unattended runs by a Maintainer).
  - With `--tailscale-authkey` and a token, setup needs `--accept-terms <sha256>` up front, and stops before any change without it.
    After joining the tailnet it checks that labd's terms are the ones named.
- The token is used up by the first enrollment and bound to that Mac's activation key; another Mac with the token gets 403.
  - If setup is interrupted, re-running it on the same Mac works until its first check-in, and only while labd keeps running: the
    activation state is in labd's memory.
  - After a labd restart, `lab forget <name>` and send a new invite.
  - The Mac keeps its activation key in `/var/lib/maclab`, renamed into place. The rename is atomic, but the file isn't flushed to
    disk first, so a power cut right after setup may lose it; then the same remedy applies.
- `lab enroll <name> --revoke` withdraws an unused invite.

### The container
The image (`Dockerfile` at the repo root) holds `labd`, plus `lab-agent-linux-arm64` next to it, which labd hands to invited Macs.

What labd itself runs or reads at run time:

| need | why | in the image |
|---|---|---|
| `git` | resolving a build's source ref (`git ls-remote`, `internal/server/sources.go`) | yes, plus outbound 443 to GitHub |
| IANA time zones | Availability windows (`internal/window`) | built into labd (`-tags timetzdata`), and `tzdata` |
| CA certificates | ntfy, publishing omarchy-m-test reports, GitHub | yes |
| `sh` | only for `--notify-cmd` | debian's `/bin/sh`; the pod sets no `--notify-cmd` |
| `tailscale` | only for `--tailscale` | not installed; the pod never uses it |
| Omarchy themes | the UI's palette, read from the controller user's home | not present; the UI uses its default palette |

There is no hostPath and no service account. labd never runs the Mac-side tools (systemctl, pacman, mkinitcpio and so on); those
belong to lab-agent on the Macs.

### What stays local
- **oobd** (on the M5: USB reset and serial console for the Macs) is called *by* labd at `http://<M5 LAN address>:7780`.
  - A pod in the cloud has no route to it, so those Macs run without hard reset or serial (tier 1).
  - Keep oobd private, and don't expose it or its token to make the cloud reach it. Only a private route (a VPN to the M5's
    network) brings it back.
- **lab-builder** polls labd outbound. It only needs `--server https://maclab.chonkbase.net`, plus `--ca-file` for a private CA.
- **The Macs** need outbound https to chonkbase.net, and **NTP** (see [The clock](#the-clock-comes-before-the-certificate)).
- Nothing else of i9beef is needed. The desktop `--notify-cmd` hook isn't set in the pod; use `--ntfy`.

## Moving labd from i9beef (and back)

Move only from a stopped, consistent state. Never run the old and new labd at the same time.

1. **Drain.** No running or queued jobs, and no leases: `lab status`.
2. **Point the agents first.**
   - Each Mac needs the new lab-agent binary (it understands https, `--ca-file` and the plain-http policy).
   - Re-point it with **`lab-agent move`**, which changes the labd URL and nothing else. Run it **in a terminal on the Mac or over
     SSH**, never through `lab exec`:
     `sudo lab-agent move --server https://maclab.chonkbase.net [--ca-file <pem>] [--allow-plain-http] [--no-check]`.
   - Run from inside lab-agent's own service (that is what `lab exec` does), `move` refuses before it changes anything. Restarting
     lab-agent there would cut off the answer.
   - Unless `--no-check` is given, `move` first asks the new labd, with the Mac's own device secret, whether it knows this Mac as
     the same kind of Mac (`GET /api/agent/enrollment`). Otherwise it stops with "Nothing was changed".
   - It then replaces only `server`, `server_ca` and `allow_plain_http` in agent.json:
     - `server_ca` is removed without `--ca-file`;
     - every other field stays;
     - the write is one fsynced rename;
     - it restarts only `lab-agent.service`.

     The Mac keeps its enrollment (ID and secret), its GUI settings and its recovery state.
   - What `move` answers:
     - **Refused, ending "Nothing was changed":** run inside lab-agent's service, the new labd doesn't know this Mac, or the URL or
       CA is refused. agent.json is as it was.
     - **"agent.json was not changed: …":** writing the new file failed before it replaced the old one. agent.json is as it was.
     - **"…/agent.json was replaced, but syncing its directory failed, so a power cut could undo it: … lab-agent was not
       restarted":** agent.json already names the new labd, but lab-agent still runs with the old one. Fix the cause, then
       `systemctl restart lab-agent.service`, or run `move` again.
     - **"lab-agent restarted; the move is done when this Mac checks in to …":** done on the Mac. The move counts once the check-in
       happens.
   - **Before the cutover** the new labd isn't answering yet, so use `--no-check`. The URL policy and the CA are still checked, and
     the agent keeps retrying until the new labd answers.
   - **After the cutover**, use the checked form, without `--no-check`.
   - This needs a shell on every Mac: SSH from a Maintainer's machine, or someone at the Mac. Check that you have one before step 3.
   - Don't use `lab-agent setup` for this. `setup` with a different `--server` and no token refuses and points to `move`, because
     a setup run also redoes the bootloader, known-good, watchdog, journal and getty setup, which a move of labd must not touch.
   - The agents then keep retrying until the new labd answers.
   - Check each Mac's `/etc/maclab/agent.json` afterwards: same `device_id`, new `server`, and an `allow_plain_http` key.
   - A Mac has moved only when it **checks in to the new labd** (`lab status` there, step 6). Before that, a staged move is just
     agent.json on the Mac.
   - If you are unsure whether `move` ran, read agent.json on the Mac. Don't simply run it again.
3. **Stop labd on i9beef.** Run `systemctl --user disable --now labd`, then check that no labd process is left and port 7770 is closed.
4. **Snapshot.**
   - Stopped, the database is closed. Run `sqlite3 ~/.local/share/maclab/labd.db 'PRAGMA wal_checkpoint(TRUNCATE)'` anyway.
   - Copy the **whole** data dir (`labd.db`, any `-wal`/`-shm`, every directory, both tokens) to a dated archive.
   - Keep that archive untouched: it is the rollback.
5. **Seed the PVC.**
   - Scale the Deployment to 0 and confirm no maclab pod exists.
   - Start a one-off pod as uid 10001 with the PVC mounted, and refuse to continue if `/data/labd.db` already exists.
   - Untar the archive into `/data`, then delete the one-off pod.
6. **Start** (scale to 1).
   - Artifact grants are memory-only and start empty. That is expected: bt2 asks for a new grant each run.
   - Check every Mac's check-in in `lab status`, then run `lab login https://maclab.chonkbase.net "<token>"` on each Maintainer machine.

**Rollback**:
1. Scale the Deployment to 0 and confirm the pod is gone.
2. Restore data on i9beef: either copy `/data` back (to keep what happened since), or use the untouched archive from step 4.
3. Re-point the agents to the old URL with `lab-agent move`, in a terminal on each Mac or over SSH, as in step 2 (never `setup`, and
   never through `lab exec`). That URL is plain HTTP to a non-loopback address, so it takes the explicit opt-in:
   `sudo lab-agent move --server http://<i9beef tailnet address>:7770 --allow-plain-http`. Add `--no-check` if labd on i9beef isn't
   answering yet. A Mac is back when it checks in there. Likewise run `lab login http://… "<token>" --allow-plain-http`.
4. Start labd on i9beef with `--allow-plain-http` on its tailnet `--listen`.

Nothing falls back to plain HTTP by itself: every client or agent set up for https refuses it until told explicitly.

## Clients: certificates and plain HTTP

Every client verifies TLS against the system roots, plus a private CA if you give one. None can turn verification off.

None follows a redirect: a 3xx answer is an error, so a token never goes anywhere it wasn't sent.

Plain `http://` is allowed only to a literal loopback address (127.0.0.0/8, ::1) or `localhost`, unless explicitly enabled.
There is no hostname or private-range guessing: `.local`, `.ts.net`, single-label names and RFC 1918 addresses all need the opt-in.

| client | private CA | plain http to a non-loopback host |
|---|---|---|
| `lab`, MCP | `lab login <url> <token> --ca-file F`, or `MACLAB_CA_FILE` | `lab login … --allow-plain-http` (saved), or `MACLAB_ALLOW_PLAIN_HTTP=1` |
| lab-agent | `setup … --ca-file F` (the PEM is kept in agent.json as `server_ca`) | `setup … --allow-plain-http`. An agent.json without the key, from an older lab-agent, keeps plain http, with a warning, only when its own server URL is plain http to a non-loopback host |
| lab-builder | `--ca-file F` | `--allow-plain-http` |
| bt2, `scripts/` tools | `MACLAB_CA_FILE`, or `"ca_file"` in client.json | `MACLAB_ALLOW_PLAIN_HTTP=1`, or `"allow_plain_http": true` in client.json |
| bt2 on the Mac (`target/preflight.py fetch`) | agent.json `server_ca` | agent.json `allow_plain_http`, by the same rule as lab-agent |

Every client also ignores `http_proxy`/`https_proxy` and connects to labd directly, and refuses a labd URL with credentials in it
(`https://user:pass@…`).

Their policy is one block of code, `tools/bt2/bt2/labhttp.py`. Each of these carries a byte-for-byte copy, and a test fails if any
copy drifts:
- `scripts/boot-test/runtime.py`;
- `scripts/workflow/m1/controller.py`;
- `tools/bt2/target/preflight.py`.

A labd URL with a path (`https://chonkbase.net/maclab`, the `path-prefix/` layout) works everywhere too: every API path is appended to it.

**Pinned sources.** Four Python files are pinned by sha256 elsewhere and are unchanged:
- `scripts/boot-test/frozen-controller-ea3.py` and its identical copy in `scripts/workflow/m1/`;
- `scripts/workflow/m1/retention-core/mirror_reuse.py`;
- `retain-controller.py`.

They are covered as follows:
- `scripts/boot-test/runtime.py`, the live `lab boot-test` runner, installs the policy as urllib's default opener before it loads
  the frozen SDK. The SDK's own calls then use it; `scripts/boot-test/test_https_runtime.py` drives them.
- Its earlier qualification was over plain HTTP and doesn't cover this transport.
- The M1 cohort helpers and the M5 retention scripts that load those files themselves keep their old behaviour: system roots
  (or `SSL_CERT_FILE`), redirects followed, plain http allowed.
  - Use them only against a loopback or tailnet labd.
  - Moving them needs a new, recorded revision of their pins.

**bt2 and artifact grants.** A Mac fetches from labd only what it is allowed to. Before the target's `fetch` step, bt2 makes one
explicit, journaled `grant-artifacts` step:
- `POST /api/devices/<name>/artifact-grants` for exactly that run's artifact shas, with a TTL of 2700 s (the fetch step's 1800 s, with margin);
- after `fetch` it revokes them (an empty list);
- a failed fetch leaves the grant to run out;
- a new run grants again in its own step; nothing extends a grant quietly.

## Other ways to serve HTTPS

**Caddy** (the simplest proxy): its defaults already pass the Host header through, have no read timeout, and flush streams and
unknown-length responses immediately.
```
maclab.example.org {
	reverse_proxy 127.0.0.1:7770
}
```
labd then runs with `--listen 127.0.0.1:7770 --public-url https://maclab.example.org --trusted-proxy 127.0.0.1/32`.

For a path on a shared host, match exactly the prefix and use `handle`, not `handle_path`, so the path reaches labd unchanged:
`@maclab path /maclab /maclab/*` and `handle @maclab { reverse_proxy 127.0.0.1:7770 }`, with `--public-url https://example.org/maclab`.

**nginx.** Its defaults break labd, so all of this is needed:
```
location / {                               # or location /maclab for a path on a shared host
	proxy_pass http://127.0.0.1:7770;          # no URI part: the path passes through unchanged
	proxy_http_version 1.1;
	proxy_set_header Host $host;               # the default, $proxy_host, makes every browser change a 403
	proxy_set_header X-Forwarded-Host $host;
	proxy_set_header X-Forwarded-Proto $scheme;
	proxy_read_timeout 3700s;                  # lab exec: up to 3630 s with no bytes
	proxy_send_timeout 3700s;
	proxy_buffering off;                       # event stream, serial console, build log
	proxy_request_buffering off;
	client_max_body_size 4g;                   # the default 1m refuses every artifact
}
```
Don't put `X-Forwarded-Prefix` or a rewrite here.

**labd's own TLS**, with no proxy: `labd --listen 0.0.0.0:443 --tls-cert /etc/maclab/tls.crt --tls-key /etc/maclab/tls.key --public-url https://labd.example.org`.
labd re-reads the files when your ACME client renews them. No `--trusted-proxy` is needed.

## Operational limits

### The clock comes before the certificate
- After a reboot a Mac's clock can start in 1976 until NTP corrects it, about 25 s later. Until then every TLS certificate looks
  not yet valid, so the agent's check-ins fail.
- The agent logs that it is a clock problem, retries every 5 s, and gets through once the clock is right.
- A Lab boot has twice its boot timeout to reach labd (12 min by default). Those deadlines are absolute times, so a clock in the
  past doesn't fire them early.
- What this needs is NTP reachable from the Macs. A Mac whose clock never comes right can't reach an https labd at all.

### Long requests
- `lab exec` is synchronous, up to its `timeout_sec` (at most 3600 s, plus 30). Any proxy in front needs a read timeout above that.
- Job waits are asked in calls of at most 50 s.
